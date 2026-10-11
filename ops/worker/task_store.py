"""Redis v2 QA cursor and observation storage foundation."""

from __future__ import annotations
import hashlib
import json
import re
from typing import Any, Literal, TypeAlias, TypedDict, cast
from task_contracts import (
    Cursor, CursorValidation, EventValidation, StoredEvent,
    stable_json, validate_cursor, validate_stored_event,
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


class TaskStore:
    """Own only QA cursor and observation state in the v2 namespace."""

    def __init__(self, client: Any):
        self._client = client

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

    @staticmethod
    def _text(value: object) -> str:
        return value.decode("utf-8") if isinstance(value, bytes) else str(value)

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
    def _reply_status(reply: object) -> str:
        if not isinstance(reply, (list, tuple)) or not reply:
            raise TaskStoreError("unexpected_redis_result")
        return TaskStore._text(reply[0])
