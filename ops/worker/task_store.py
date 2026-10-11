"""Redis v2 QA cursor and observation storage foundation."""

from __future__ import annotations
import hashlib
import json
import re
from typing import Any, Literal, TypeAlias, TypedDict, cast
from task_contracts import (
    Cursor, CursorValidation, EventValidation, FailureOccurrence, IncidentIdentity,
    MAX_SAFE_COUNTER, QueuedTask, StoredEvent, TaskState, TaskValidation,
    is_safe_counter, is_safe_timestamp_ms, is_valid_owner, queued_task, stable_json,
    validate_cursor, validate_stored_event, validate_task,
)

PREFIX = "ops:v2:"
CURSOR_KEY = PREFIX + "cursor:qa-history"
QUEUE_KEY = PREFIX + "queue"
QUEUE_REGISTRY_KEY = PREFIX + "queue:registrations"
DEFAULT_LEASE_SECONDS = 300
MAX_LEASE_SECONDS = 86400


def occurrence_key(occurrence_id: str) -> str:
    """Name one immutable evidence record in the v2 namespace."""
    if not isinstance(occurrence_id, str) or not re.fullmatch(r"occ_[0-9a-f]{64}", occurrence_id):
        raise TaskStoreError("invalid_occurrence_id")
    return PREFIX + "occurrence:" + occurrence_id


def task_key(task_id: str) -> str:
    """Name one durable incident lifecycle document in the v2 namespace."""
    if not isinstance(task_id, str) or not re.fullmatch(r"inc_[0-9a-f]{64}", task_id):
        raise TaskStoreError("invalid_task_id")
    return PREFIX + "task:" + task_id


def observations_key(task_id: str) -> str:
    """Name the occurrence index retained for one incident task."""
    task_key(task_id)
    return PREFIX + "observations:" + task_id


def execution_key(task_id: str) -> str:
    """Name the bounded durable execution budget for one incident."""
    if not isinstance(task_id, str) or not re.fullmatch(r"inc_[0-9a-f]{64}", task_id):
        raise TaskStoreError("invalid_task_id")
    return PREFIX + "execution:" + task_id


class Claimed(TypedDict):
    status: Literal["claimed"]
    task: TaskState


class ClaimStatus(TypedDict):
    status: Literal[
        "busy", "stale_state", "not_found", "not_claimable", "wrong_type",
        "invalid_state", "counter_exhausted", "timestamp_out_of_range",
    ]


ClaimResult: TypeAlias = Claimed | ClaimStatus


class LeaseUpdated(TypedDict):
    status: Literal["renewed"]
    task: TaskState


class LeaseStatus(TypedDict):
    status: Literal[
        "stale_state", "stale_owner", "expired", "not_investigating", "not_found",
        "wrong_type", "invalid_state", "counter_exhausted", "timestamp_out_of_range",
    ]


LeaseResult: TypeAlias = LeaseUpdated | LeaseStatus


class TaskStoreError(RuntimeError):
    """Stable storage failure without echoing Redis payloads or error values."""

    domain = "ops.v2.store"

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{self.domain}:{code}")


class MissingCursor(TypedDict):
    status: Literal["missing"]


class StoredCursor(TypedDict):
    status: Literal["stored"]
    raw: str
    value: Cursor


class CursorInitialized(TypedDict):
    status: Literal["stored"]


class CursorInitializationStatus(TypedDict):
    status: Literal["stale_cursor", "wrong_type"]


class IngestStored(TypedDict):
    status: Literal["stored"]


class IngestDuplicate(TypedDict):
    status: Literal["duplicate"]


class IngestStale(TypedDict):
    status: Literal["stale_cursor"]


class IngestWrongType(TypedDict):
    status: Literal["wrong_type"]
    key_role: str


class IngestInvalidState(TypedDict):
    status: Literal["invalid_state"]


class IngestTimestampOutOfRange(TypedDict):
    status: Literal["timestamp_out_of_range"]


CursorInitializationResult: TypeAlias = CursorInitialized | CursorInitializationStatus
CursorSnapshot: TypeAlias = MissingCursor | StoredCursor
AnyCursorSnapshot: TypeAlias = CursorSnapshot
IngestResult: TypeAlias = (
    IngestStored | IngestDuplicate | IngestStale | IngestWrongType
    | IngestInvalidState | IngestTimestampOutOfRange
)

_INITIALIZE_CURSOR = r"""
local cursor_type = redis.call('TYPE', KEYS[1]).ok
if cursor_type ~= 'none' and cursor_type ~= 'string' then return {'wrong_type'} end
if redis.call('SETNX', KEYS[1], ARGV[1]) == 0 then return {'stale_cursor'} end
return {'stored'}
"""
_INGEST_OBSERVATION = r"""
local function keytype(key)
  return redis.call('TYPE', key).ok
end
local cursor_type = keytype(KEYS[1])
if cursor_type ~= 'none' and cursor_type ~= 'string' then return {'wrong_type', 'cursor'} end
local event_type = keytype(KEYS[2])
if event_type ~= 'none' and event_type ~= 'string' then return {'wrong_type', 'occurrence'} end
if ARGV[4] ~= '0' and ARGV[4] ~= '1' then return {'invalid_state'} end
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '' then
  if current then return {'stale_cursor'} end
elseif current ~= ARGV[1] then
  return {'stale_cursor'}
end
local existed = event_type == 'string'
if existed and redis.call('GET', KEYS[2]) ~= ARGV[3] then return {'invalid_state'} end
if not existed then redis.call('SET', KEYS[2], ARGV[3]) end
if ARGV[4] == '1' then redis.call('SET', KEYS[1], ARGV[2]) end
if existed then return {'duplicate'} end
return {'stored'}
"""

_INGEST_FAILURE = r"""
local function keytype(key)
  return redis.call('TYPE', key).ok
end
local roles = {'cursor', 'occurrence', 'task', 'queue', 'queue_registry', 'observations'}
local expected = {'string', 'string', 'string', 'stream', 'hash', 'zset'}
if ARGV[12] ~= '0' and ARGV[12] ~= '1' then return {'invalid_state'} end
for i = 1, #KEYS do
  local actual = keytype(KEYS[i])
  if actual ~= 'none' and actual ~= expected[i] then return {'wrong_type', roles[i]} end
end
local function exact_keys(value, expected_keys)
  local count = 0
  for key, _ in pairs(value) do
    if not expected_keys[key] then return false end
    count = count + 1
  end
  local expected_count = 0
  for key, _ in pairs(expected_keys) do
    if value[key] == nil then return false end
    expected_count = expected_count + 1
  end
  return count == expected_count
end
local MAX_SAFE_COUNTER = 2147483647
local MAX_SAFE_TIMESTAMP_MS = 99999999999999
local function nonnegative_integer(value)
  return type(value) == 'number' and value >= 0 and value == math.floor(value)
end
local function safe_timestamp_ms(value)
  return nonnegative_integer(value) and value <= MAX_SAFE_TIMESTAMP_MS
end
local function current_time_ms()
  local time = redis.call('TIME')
  local seconds = tonumber(time[1])
  local microseconds = tonumber(time[2])
  if not nonnegative_integer(seconds) or not nonnegative_integer(microseconds)
      or microseconds >= 1000000 then return nil end
  local now_ms = seconds * 1000 + math.floor(microseconds / 1000)
  if not safe_timestamp_ms(now_ms) then return nil end
  return now_ms
end
local function safe_counter(value)
  return nonnegative_integer(value) and value <= MAX_SAFE_COUNTER
end
local function valid_task(value, task_id, source_repo, category, component, mode, error_family)
  if type(value) ~= 'table' or value.schema_version ~= 2 or value.id ~= task_id
      or value.source_repo ~= source_repo or value.category ~= category
      or value.component ~= component or value.mode ~= mode
      or value.error_family ~= error_family then return false end
  local extras = {
    queued = {}, investigating = {owner=true, lease_until_ms=true},
    blocked = {reason_code=true, blocked_at_ms=true}
  }
  local extra = extras[value.status]
  if not extra then return false end
  local fields = {
    schema_version=true, id=true, source_repo=true, category=true, component=true,
    mode=true, error_family=true, attempts=true, epoch=true, revision=true,
    created_at_ms=true, updated_at_ms=true, error=true, status=true
  }
  local count = 0
  for key, _ in pairs(extra) do fields[key] = true end
  for key, _ in pairs(value) do
    if not fields[key] then return false end
    count = count + 1
  end
  local expected_count = 14
  for _, _ in pairs(extra) do expected_count = expected_count + 1 end
  if count ~= expected_count then return false end
  if value.source_repo ~= 'ManddarinShop/Hikoutei' and value.source_repo ~= 'ManddarinShop/Hikoutei-Website' then return false end
  if type(value.category) ~= 'string' or value.category == '' or #value.category > 128
      or type(value.component) ~= 'string' or value.component == '' or #value.component > 128
      or type(value.error_family) ~= 'string' or value.error_family == '' or #value.error_family > 128
      or (value.mode ~= 'local' and value.mode ~= 'sync' and value.mode ~= 'unknown') then return false end
  for _, field in ipairs({'attempts', 'epoch', 'revision'}) do
    if not safe_counter(value[field]) then return false end
  end
  for _, field in ipairs({'created_at_ms', 'updated_at_ms'}) do
    if not safe_timestamp_ms(value[field]) then return false end
  end
  if type(value.error) ~= 'table' then return false end
  if value.error.status == 'none' then
    if not exact_keys(value.error, {status=true}) then return false end
  elseif value.error.status == 'recorded' then
    if not exact_keys(value.error, {status=true, code=true, at_ms=true})
        or type(value.error.code) ~= 'string' or #value.error.code > 64
        or not string.match(value.error.code, '^[a-z][a-z0-9_]*$')
        or not safe_timestamp_ms(value.error.at_ms) then return false end
  else
    return false
  end
  if value.status == 'investigating' then
    if type(value.owner) ~= 'string' or value.owner == '' or #value.owner > 128
        or not safe_timestamp_ms(value.lease_until_ms) then return false end
  elseif value.status == 'blocked' then
    if type(value.reason_code) ~= 'string' or #value.reason_code > 64
        or not string.match(value.reason_code, '^[a-z][a-z0-9_]*$')
        or not safe_timestamp_ms(value.blocked_at_ms) then return false end
  end
  return true
end
-- A previous runtime error may have followed XADD but preceded the registry update.
local function find_stream_registration(task_id)
  local entries = redis.call('XRANGE', KEYS[4], '-', '+')
  local found
  for _, entry in ipairs(entries) do
    local fields = entry[2]
    if #fields ~= 2 or fields[1] ~= 'task_id' then return nil, false end
    if fields[2] == task_id then
      if found then return nil, false end
      found = entry[1]
    end
  end
  return found, true
end
local current_cursor = redis.call('GET', KEYS[1])
if ARGV[1] == '' then
  if current_cursor then return {'stale_cursor'} end
elseif current_cursor ~= ARGV[1] then
  return {'stale_cursor'}
end
local event_exists = keytype(KEYS[2]) == 'string'
local task_exists = keytype(KEYS[3]) == 'string'
local task
if task_exists then
  local raw_task = redis.call('GET', KEYS[3])
  local ok
  ok, task = pcall(cjson.decode, raw_task)
  if not ok or not valid_task(task, ARGV[6], ARGV[7], ARGV[8], ARGV[9], ARGV[10], ARGV[11]) then
    return {'invalid_state'}
  end
else
  local ok, prototype = pcall(cjson.decode, ARGV[4])
  if not ok or not valid_task(prototype, ARGV[6], ARGV[7], ARGV[8], ARGV[9], ARGV[10], ARGV[11])
      or prototype.status ~= 'queued' then
    return {'invalid_state'}
  end
  task = prototype
end
if event_exists and redis.call('GET', KEYS[2]) ~= ARGV[3] then return {'invalid_state'} end
local registration = redis.call('HGET', KEYS[5], ARGV[6])
local stream_id
if registration and registration ~= '__pending__' then
  if not string.match(registration, '^%d+%-%d+$') then return {'invalid_state'} end
  local entries = redis.call('XRANGE', KEYS[4], registration, registration)
  if #entries ~= 1 then return {'invalid_state'} end
  local fields = entries[1][2]
  if #fields ~= 2 or fields[1] ~= 'task_id' or fields[2] ~= ARGV[6] then
    return {'invalid_state'}
  end
  stream_id = registration
elseif registration == '__pending__' then
  local valid
  stream_id, valid = find_stream_registration(ARGV[6])
  if not valid then return {'invalid_state'} end
end
local now_ms = current_time_ms()
if now_ms == nil then return {'timestamp_out_of_range'} end
local encoded_task
if not task_exists then
  task.created_at_ms = now_ms
  task.updated_at_ms = now_ms
  encoded_task = cjson.encode(task)
end
if not event_exists then redis.call('SET', KEYS[2], ARGV[3]) end
-- Lua runtime errors do not roll back; the marker makes a partial XADD retry idempotent.
if not registration then
  redis.call('HSET', KEYS[5], ARGV[6], '__pending__')
end
if not stream_id then
  stream_id = redis.call('XADD', KEYS[4], '*', 'task_id', ARGV[6])
end
if registration ~= stream_id then redis.call('HSET', KEYS[5], ARGV[6], stream_id) end
redis.call('ZADD', KEYS[6], now_ms, ARGV[5])
if not task_exists then redis.call('SET', KEYS[3], encoded_task) end
if ARGV[12] == '1' then redis.call('SET', KEYS[1], ARGV[2]) end
if event_exists then return {'duplicate'} end
return {'stored'}
"""

_CLAIM = r"""
local MAX_SAFE_COUNTER = 2147483647
local MAX_SAFE_TIMESTAMP_MS = 99999999999999
local function safe_counter(value)
  return type(value) == 'number' and value >= 0 and value <= MAX_SAFE_COUNTER
      and value == math.floor(value)
end
local function safe_timestamp_ms(value)
  return type(value) == 'number' and value >= 0 and value <= MAX_SAFE_TIMESTAMP_MS
      and value == math.floor(value)
end
local function task_timestamps_valid(task)
  if not safe_timestamp_ms(task.created_at_ms) or not safe_timestamp_ms(task.updated_at_ms)
      or type(task.error) ~= 'table' then return false end
  if task.error.status == 'recorded' then
    if not safe_timestamp_ms(task.error.at_ms) then return false end
  elseif task.error.status ~= 'none' then return false end
  if task.status == 'investigating' then return safe_timestamp_ms(task.lease_until_ms) end
  if task.status == 'blocked' then return safe_timestamp_ms(task.blocked_at_ms) end
  return task.status == 'queued'
end
local function current_time_ms()
  local time = redis.call('TIME')
  local seconds = tonumber(time[1])
  local microseconds = tonumber(time[2])
  if type(seconds) ~= 'number' or seconds < 0 or seconds ~= math.floor(seconds)
      or type(microseconds) ~= 'number' or microseconds < 0
      or microseconds >= 1000000 or microseconds ~= math.floor(microseconds) then return nil end
  local now_ms = seconds * 1000 + math.floor(microseconds / 1000)
  if not safe_timestamp_ms(now_ms) then return nil end
  return now_ms
end
local task_type = redis.call('TYPE', KEYS[1]).ok
if task_type ~= 'none' and task_type ~= 'string' then return {'wrong_type'} end
if task_type == 'none' then return {'not_found'} end
local raw = redis.call('GET', KEYS[1])
if raw ~= ARGV[3] then return {'stale_state'} end
local ok, task = pcall(cjson.decode, raw)
if not ok or type(task) ~= 'table' or task.schema_version ~= 2
    or type(task.status) ~= 'string' or not safe_counter(task.attempts)
    or not safe_counter(task.epoch) or not safe_counter(task.revision)
    or not task_timestamps_valid(task) then
  return {'invalid_state'}
end
local now_ms = current_time_ms()
if now_ms == nil then return {'timestamp_out_of_range'} end
if task.status == 'investigating' then
  if type(task.lease_until_ms) ~= 'number' then return {'invalid_state'} end
  if task.lease_until_ms > now_ms then return {'busy'} end
elseif task.status ~= 'queued' then
  return {'not_claimable'}
end
if task.attempts == MAX_SAFE_COUNTER or task.epoch == MAX_SAFE_COUNTER
    or task.revision == MAX_SAFE_COUNTER then return {'counter_exhausted'} end
local lease_until_ms = now_ms + tonumber(ARGV[2])
if not safe_timestamp_ms(lease_until_ms) then return {'timestamp_out_of_range'} end
task.status = 'investigating'
task.owner = ARGV[1]
task.lease_until_ms = lease_until_ms
task.attempts = task.attempts + 1
task.epoch = task.epoch + 1
task.revision = task.revision + 1
task.updated_at_ms = now_ms
local encoded = cjson.encode(task)
redis.call('SET', KEYS[1], encoded)
return {'claimed', encoded}
"""

_RENEW = r"""
local MAX_SAFE_COUNTER = 2147483647
local MAX_SAFE_TIMESTAMP_MS = 99999999999999
local function safe_counter(value)
  return type(value) == 'number' and value >= 0 and value <= MAX_SAFE_COUNTER
      and value == math.floor(value)
end
local function safe_timestamp_ms(value)
  return type(value) == 'number' and value >= 0 and value <= MAX_SAFE_TIMESTAMP_MS
      and value == math.floor(value)
end
local function task_timestamps_valid(task)
  if not safe_timestamp_ms(task.created_at_ms) or not safe_timestamp_ms(task.updated_at_ms)
      or type(task.error) ~= 'table' then return false end
  if task.error.status == 'recorded' then
    if not safe_timestamp_ms(task.error.at_ms) then return false end
  elseif task.error.status ~= 'none' then return false end
  if task.status == 'investigating' then return safe_timestamp_ms(task.lease_until_ms) end
  if task.status == 'blocked' then return safe_timestamp_ms(task.blocked_at_ms) end
  return task.status == 'queued'
end
local function current_time_ms()
  local time = redis.call('TIME')
  local seconds = tonumber(time[1])
  local microseconds = tonumber(time[2])
  if type(seconds) ~= 'number' or seconds < 0 or seconds ~= math.floor(seconds)
      or type(microseconds) ~= 'number' or microseconds < 0
      or microseconds >= 1000000 or microseconds ~= math.floor(microseconds) then return nil end
  local now_ms = seconds * 1000 + math.floor(microseconds / 1000)
  if not safe_timestamp_ms(now_ms) then return nil end
  return now_ms
end
local t = redis.call('TYPE', KEYS[1]).ok
if t ~= 'none' and t ~= 'string' then return {'wrong_type'} end
if t == 'none' then return {'not_found'} end
local raw = redis.call('GET', KEYS[1])
if raw ~= ARGV[4] then return {'stale_state'} end
local ok, task = pcall(cjson.decode, raw)
if not ok or type(task) ~= 'table' or task.schema_version ~= 2
    or type(task.status) ~= 'string' or type(task.epoch) ~= 'number'
    or not safe_counter(task.revision) or not task_timestamps_valid(task) then
  return {'invalid_state'}
end
if task.status ~= 'investigating' then return {'not_investigating'} end
if task.owner ~= ARGV[1] or task.epoch ~= tonumber(ARGV[2]) then return {'stale_owner'} end
local now_ms = current_time_ms()
if now_ms == nil then return {'timestamp_out_of_range'} end
if type(task.lease_until_ms) ~= 'number' then return {'invalid_state'} end
if task.lease_until_ms <= now_ms then return {'expired'} end
if task.revision == MAX_SAFE_COUNTER then return {'counter_exhausted'} end
local lease_until_ms = now_ms + tonumber(ARGV[3])
if not safe_timestamp_ms(lease_until_ms) then return {'timestamp_out_of_range'} end
task.lease_until_ms = lease_until_ms
task.revision = task.revision + 1
task.updated_at_ms = now_ms
local encoded = cjson.encode(task)
redis.call('SET', KEYS[1], encoded)
return {'renewed', encoded}
"""

_READ_QUEUE_SNAPSHOT = r"""
local registry_type = redis.call('TYPE', KEYS[1]).ok
local queue_type = redis.call('TYPE', KEYS[2]).ok
if registry_type ~= 'none' and registry_type ~= 'hash' then return {'queue_registry_wrong_type'} end
if queue_type ~= 'none' and queue_type ~= 'stream' then return {'queue_wrong_type'} end
if queue_type == 'none' and registry_type == 'hash' and redis.call('HLEN', KEYS[1]) > 0 then
  return {'queue_registry_without_queue'}
end
local registrations = {}
if registry_type == 'hash' then registrations = redis.call('HGETALL', KEYS[1]) end
local entries = {}
if queue_type == 'stream' then entries = redis.call('XRANGE', KEYS[2], '-', '+') end
return {'snapshot', registrations, entries, redis.call('TIME')}
"""


class TaskStore:
    """Own only `ops:v2:*`; cursor-CAS scripts repair partial writes on retry."""

    def __init__(self, client: Any):
        self._client = client

    def claim(
        self,
        task_id: str,
        owner: str,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> ClaimResult:
        """Claim queued work or fence-reclaim an expired lease using Redis server time."""
        self._validate_owner_lease(owner, lease_seconds)
        snapshot = self._read_task_snapshot(task_id)
        if snapshot is None:
            return {"status": "not_found"}
        expected_raw, _ = snapshot
        reply = self._client.eval(
            _CLAIM, 1, task_key(task_id), owner, lease_seconds * 1000, expected_raw,
        )
        status = self._reply_status(reply)
        if status != "claimed":
            return {"status": cast(Any, status)}
        return {"status": "claimed", "task": self._decode_task(reply[1])}

    def renew(
        self,
        task_id: str,
        owner: str,
        epoch: int,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> LeaseResult:
        """Extend only the current, unexpired owner/epoch lease."""
        self._validate_owner_lease(owner, lease_seconds)
        if not self._nonnegative_int(epoch):
            raise TaskStoreError("invalid_epoch")
        snapshot = self._read_task_snapshot(task_id)
        if snapshot is None:
            return {"status": "not_found"}
        expected_raw, _ = snapshot
        reply = self._client.eval(
            _RENEW, 1, task_key(task_id), owner, epoch, lease_seconds * 1000, expected_raw,
        )
        status = self._reply_status(reply)
        if status != "renewed":
            return {"status": cast(Any, status)}
        return {"status": "renewed", "task": self._decode_task(reply[1])}

    def load_task(self, task_id: str) -> TaskState | None:
        """Load one durable task only after strict lifecycle validation."""
        snapshot = self._read_task_snapshot(task_id)
        return None if snapshot is None else snapshot[1]

    def observation_ids(self, task_id: str) -> list[str]:
        """Return retained occurrence IDs for an incident task."""
        key = observations_key(task_id)
        key_type = self._text(self._client.type(key))
        if key_type == "none":
            return []
        if key_type != "zset":
            raise TaskStoreError("observations_wrong_type")
        return list(self._client.zrange(key, 0, -1))

    def read_cursor(self) -> CursorSnapshot:
        """Read and validate the v2 cursor without touching legacy `q:*` state."""
        key_type = self._text(self._client.type(CURSOR_KEY))
        if key_type == "none":
            return {"status": "missing"}
        if key_type != "string":
            raise TaskStoreError("cursor_wrong_type")
        raw = self._client.get(CURSOR_KEY)
        if not isinstance(raw, str):
            raise TaskStoreError("cursor_unreadable")
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            raise TaskStoreError("cursor_invalid_json") from None
        result = validate_cursor(value)
        if result["status"] != "valid":
            raise TaskStoreError("cursor_invalid_state")
        return {"status": "stored", "raw": raw, "value": result["value"]}

    def initialize_cursor(self, cursor: Cursor) -> CursorInitializationResult:
        """Bind the first active file once; a racing initializer must reload the winner."""
        initial = self._require_initial_cursor(cursor)
        return self._initialize_cursor(CURSOR_KEY, stable_json(initial))

    def ingest_observation(
        self,
        expected: CursorSnapshot,
        next_cursor: Cursor,
        occurrence: StoredEvent,
    ) -> IngestResult:
        """Persist a QA observation and its file cursor with the original CAS behavior."""
        event = self._require_event(occurrence)
        cursor = self._require_cursor(next_cursor)
        if event["kind"] == "failure":
            raise TaskStoreError("failure_requires_task")
        return self._ingest_observation(
            CURSOR_KEY, self._expected(expected), cursor, event, advance=True,
        )

    def ingest_failure(
        self,
        expected: CursorSnapshot,
        next_cursor: Cursor,
        occurrence: FailureOccurrence,
        identity: IncidentIdentity,
    ) -> IngestResult:
        """Fence one QA failure and its cursor while preserving the established public contract."""
        event = self._require_event(occurrence)
        cursor = self._require_cursor(next_cursor)
        if event["kind"] != "failure" or event["incident_id"] != identity["id"]:
            raise TaskStoreError("incident_mismatch")
        if any(identity[key] != event[key] for key in ("source_repo", "mode")):
            raise TaskStoreError("incident_mismatch")
        return self._ingest_registered_failure(
            CURSOR_KEY, self._expected(expected), cursor, event, identity, advance=True,
        )

    def queued_ids(self) -> list[str]:
        """Discover queued and expired leases from one consistent registry/stream snapshot."""
        reply = self._client.eval(_READ_QUEUE_SNAPSHOT, 2, QUEUE_REGISTRY_KEY, QUEUE_KEY)
        status = self._reply_status(reply)
        if status in ("queue_registry_wrong_type", "queue_wrong_type", "queue_registry_without_queue"):
            raise TaskStoreError(status)
        if status != "snapshot" or not isinstance(reply, (list, tuple)) or len(reply) != 4:
            raise TaskStoreError("queue_snapshot_invalid")
        raw_registry, raw_entries, raw_time = reply[1:]
        if (
            not isinstance(raw_registry, (list, tuple)) or len(raw_registry) % 2 != 0
            or not isinstance(raw_entries, (list, tuple))
            or not isinstance(raw_time, (list, tuple)) or len(raw_time) != 2
        ):
            raise TaskStoreError("queue_snapshot_invalid")
        try:
            seconds, microseconds = (int(self._snapshot_text(value)) for value in raw_time)
        except (TaskStoreError, ValueError):
            raise TaskStoreError("queue_snapshot_invalid") from None
        if seconds < 0 or not 0 <= microseconds < 1_000_000:
            raise TaskStoreError("queue_snapshot_invalid")
        now_ms = seconds * 1000 + microseconds // 1000

        registrations: dict[str, str] = {}
        for index in range(0, len(raw_registry), 2):
            task_id = self._snapshot_text(raw_registry[index])
            registration = self._snapshot_text(raw_registry[index + 1])
            try:
                task_key(task_id)
            except TaskStoreError:
                raise TaskStoreError("queue_invalid_registration") from None
            if task_id in registrations or (
                registration != "__pending__" and re.fullmatch(r"[0-9]+-[0-9]+", registration) is None
            ):
                raise TaskStoreError("queue_invalid_registration")
            registrations[task_id] = registration

        entries_by_task: dict[str, str] = {}
        # ponytail: full stream reads are O(n); paginate only if registrations grow materially.
        for entry in raw_entries:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise TaskStoreError("queue_invalid_registration")
            stream_id = self._snapshot_text(entry[0])
            raw_fields = entry[1]
            if (
                re.fullmatch(r"[0-9]+-[0-9]+", stream_id) is None
                or not isinstance(raw_fields, (list, tuple)) or len(raw_fields) != 2
            ):
                raise TaskStoreError("queue_invalid_registration")
            field_name = self._snapshot_text(raw_fields[0])
            task_id = self._snapshot_text(raw_fields[1])
            try:
                task_key(task_id)
            except TaskStoreError:
                raise TaskStoreError("queue_invalid_registration") from None
            if task_id in entries_by_task:
                raise TaskStoreError("queue_duplicate_registration")
            registration = registrations.get(task_id)
            if registration is None or registration not in ("__pending__", stream_id):
                raise TaskStoreError("queue_invalid_registration")
            if field_name != "task_id":
                raise TaskStoreError("queue_invalid_registration")
            entries_by_task[task_id] = stream_id

        if len(entries_by_task) != len(registrations):
            raise TaskStoreError("queue_invalid_registration")
        if any(
            task_id not in entries_by_task
            or (registration != "__pending__" and registration != entries_by_task[task_id])
            for task_id, registration in registrations.items()
        ):
            raise TaskStoreError("queue_invalid_registration")

        candidates: list[str] = []
        for task_id in entries_by_task:
            snapshot = self._read_task_snapshot(task_id)
            if snapshot is None:
                # Surface matching partial registrations so cursor replay can repair ingress.
                candidates.append(task_id)
                continue
            task = snapshot[1]
            if task["status"] == "queued" or (
                task["status"] == "investigating" and task["lease_until_ms"] <= now_ms
            ):
                candidates.append(task_id)
        return candidates

    def _initialize_cursor(self, key: str, serialized: str) -> CursorInitializationResult:
        """Share SETNX initialization while keeping the QA and CI cursor keys separate."""
        reply = self._client.eval(_INITIALIZE_CURSOR, 1, key, serialized)
        status = self._reply_status(reply)
        if status in ("stored", "stale_cursor", "wrong_type"):
            return {"status": cast(Any, status)}
        raise TaskStoreError("unexpected_cursor_initialization_result")

    def _ingest_observation(
        self,
        cursor_key: str,
        expected: str,
        next_cursor: Cursor,
        event: dict[str, object],
        *,
        advance: bool,
    ) -> IngestResult:
        """Reuse the observation Lua path for immutable evidence and optional page CAS."""
        reply = self._client.eval(
            _INGEST_OBSERVATION, 2, cursor_key, occurrence_key(str(event["occurrence_id"])),
            expected, stable_json(next_cursor), stable_json(event), "1" if advance else "0",
        )
        return self._ingest_result(reply)

    def _ingest_registered_failure(
        self,
        cursor_key: str,
        expected: str,
        next_cursor: Cursor,
        event: dict[str, object],
        identity: IncidentIdentity,
        *,
        advance: bool,
    ) -> IngestResult:
        """Reuse the single queue/registry ingress, optionally leaving a CI page pending."""
        if event.get("incident_id") != identity["id"] or event.get("source_repo") != identity["source_repo"]:
            raise TaskStoreError("incident_mismatch")
        if event.get("mode", "unknown") != identity["mode"]:
            raise TaskStoreError("incident_mismatch")
        prototype: QueuedTask = queued_task(identity)
        if self._require_task(prototype)["id"] != identity["id"]:
            raise TaskStoreError("incident_invalid")
        reply = self._client.eval(
            _INGEST_FAILURE, 6, cursor_key, occurrence_key(str(event["occurrence_id"])),
            task_key(identity["id"]), QUEUE_KEY, QUEUE_REGISTRY_KEY, observations_key(identity["id"]),
            expected, stable_json(next_cursor), stable_json(event), stable_json(prototype),
            event["occurrence_id"], identity["id"], identity["source_repo"], identity["category"],
            identity["component"], identity["mode"], identity["error_family"],
            "1" if advance else "0",
        )
        return self._ingest_result(reply)

    def _read_task_snapshot(self, task_id: str) -> tuple[str, TaskState] | None:
        """Read raw CAS bytes and validate their discriminated state together."""
        key = task_key(task_id)
        key_type = self._text(self._client.type(key))
        if key_type == "none":
            return None
        if key_type != "string":
            raise TaskStoreError("task_wrong_type")
        raw = self._client.get(key)
        if not isinstance(raw, str):
            raise TaskStoreError("task_unreadable")
        try:
            result = validate_task(json.loads(raw))
        except (TypeError, ValueError):
            raise TaskStoreError("task_invalid_json") from None
        if result["status"] != "valid":
            raise TaskStoreError("task_invalid_state")
        return raw, result["value"]

    @staticmethod
    def _text(value: object) -> str:
        return value.decode("utf-8") if isinstance(value, bytes) else str(value)

    @staticmethod
    def _snapshot_text(value: object) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                raise TaskStoreError("queue_invalid_registration") from None
        raise TaskStoreError("queue_invalid_registration")

    @staticmethod
    def _expected(snapshot: AnyCursorSnapshot) -> str:
        return "" if snapshot["status"] == "missing" else snapshot["raw"]

    @staticmethod
    def _require_cursor(value: Cursor) -> Cursor:
        result: CursorValidation = validate_cursor(value)
        if result["status"] != "valid":
            raise TaskStoreError("invalid_cursor")
        return result["value"]

    @staticmethod
    def _require_initial_cursor(value: Cursor) -> Cursor:
        result: CursorValidation = validate_cursor(value)
        if result["status"] != "valid":
            raise TaskStoreError("invalid_initial_cursor")
        cursor = result["value"]
        if (
            cursor["file"]["status"] != "bound"
            or cursor["generation"] != 0
            or cursor["offset"] != 0
            or cursor["boundary_sha256"] != hashlib.sha256(b"").hexdigest()
            or cursor["boot_context"] != {"status": "unknown"}
        ):
            raise TaskStoreError("invalid_initial_cursor")
        return cursor

    @staticmethod
    def _require_event(value: StoredEvent) -> StoredEvent:
        result: EventValidation = validate_stored_event(value)
        if result["status"] != "valid":
            raise TaskStoreError("invalid_occurrence")
        return result["value"]

    @staticmethod
    def _require_task(value: QueuedTask) -> TaskState:
        result: TaskValidation = validate_task(value)
        if result["status"] != "valid":
            raise TaskStoreError("invalid_task")
        return result["value"]

    @staticmethod
    def _ingest_result(reply: list[object]) -> IngestResult:
        status = TaskStore._reply_status(reply)
        if status in ("stored", "duplicate", "stale_cursor"):
            return {"status": cast(Any, status)}
        if status == "wrong_type":
            return {"status": "wrong_type", "key_role": TaskStore._text(reply[1])}
        if status == "invalid_state":
            return {"status": "invalid_state"}
        if status == "timestamp_out_of_range":
            return {"status": "timestamp_out_of_range"}
        raise TaskStoreError("unexpected_ingest_result")

    @staticmethod
    def _decode_task(raw: object) -> TaskState:
        try:
            value = json.loads(TaskStore._text(raw))
        except (TypeError, ValueError):
            raise TaskStoreError("task_invalid_json") from None
        result = validate_task(value)
        if result["status"] != "valid":
            raise TaskStoreError("task_invalid_state")
        return result["value"]

    @staticmethod
    def _nonnegative_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    @staticmethod
    def _validate_owner_lease(owner: str, lease_seconds: int) -> None:
        if not is_valid_owner(owner):
            raise TaskStoreError("invalid_owner")
        if not TaskStore._nonnegative_int(lease_seconds) or not 0 < lease_seconds <= MAX_LEASE_SECONDS:
            raise TaskStoreError("invalid_lease_duration")

    @staticmethod
    def _reply_status(reply: object) -> str:
        if not isinstance(reply, (list, tuple)) or not reply:
            raise TaskStoreError("unexpected_redis_result")
        return TaskStore._text(reply[0])
