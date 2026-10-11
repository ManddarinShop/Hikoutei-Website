"""Validated v2 QA-record and cursor contracts."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Literal, TypeAlias, TypedDict, cast

SOURCE_REPOSITORIES = (
    "ManddarinShop/Hikoutei",
    "ManddarinShop/Hikoutei-Website",
)
BASE_BRANCH_BY_REPOSITORY = {
    "ManddarinShop/Hikoutei": "develop",
    "ManddarinShop/Hikoutei-Website": "main",
}
DEFAULT_SOURCE_REPOSITORY = "ManddarinShop/Hikoutei-Website"
QA_OPERATIONS = (
    "create", "update", "delete", "duplicateInsert", "noOpUpdate",
    "deleteRecreate", "flushCycle", "step",
)
ERROR_MODES = ("local", "sync", "unknown")
COUNT_DRIFT = re.compile(r"^count drift at step [0-9]+: runtime=[0-9]+ model=[0-9]+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_QA_SEED = 0xFFFFFFFF
# 10 decimal digits stay exact with Redis Lua cjson's default 14-digit precision.
MAX_SAFE_COUNTER = (1 << 31) - 1
# Lua cjson round-trips at most 14 significant digits for task timestamps.
MAX_SAFE_TIMESTAMP_MS = 99_999_999_999_999
MAX_OWNER_BYTES = 128


class ContractError(ValueError):
    """Stable machine-readable failure at a JSON or stored-state boundary."""

    domain = "ops.v2.contract"

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{self.domain}:{code}")


class FileUnbound(TypedDict):
    status: Literal["unbound"]


class FileBound(TypedDict):
    status: Literal["bound"]
    device: int
    inode: int


FileIdentity: TypeAlias = FileUnbound | FileBound


class UnknownBoot(TypedDict):
    status: Literal["unknown"]


class KnownBoot(TypedDict):
    status: Literal["known"]
    seed: int
    mode: Literal["local", "sync"]


BootContext: TypeAlias = UnknownBoot | KnownBoot


class Cursor(TypedDict):
    schema_version: Literal[2]
    file: FileIdentity
    generation: int
    offset: int
    boundary_sha256: str
    boot_context: BootContext


class ValidCursor(TypedDict):
    status: Literal["valid"]
    value: Cursor


class InvalidCursor(TypedDict):
    status: Literal["invalid"]
    code: str


CursorValidation: TypeAlias = ValidCursor | InvalidCursor


class BootRecord(TypedDict):
    type: Literal["boot"]
    ts: str
    seed: int
    sync_mode: Literal["local", "sync", "unknown"]


class SummaryRecord(TypedDict):
    type: Literal["summary"]
    ts: str
    seed: int
    iterations: int
    failures: int
    uptimeS: int
    opCounters: dict[str, dict[str, int]]


class FailureRecord(TypedDict):
    type: Literal["failure"]
    ts: str
    seed: int
    step: int
    op: str
    detail: str


QARecord: TypeAlias = BootRecord | SummaryRecord | FailureRecord


class RecordOccurrenceBase(TypedDict):
    schema_version: Literal[2]
    occurrence_id: str
    source_repo: str
    generation: int
    offset: int
    file: FileBound
    raw_sha256: str


class BootOccurrence(RecordOccurrenceBase):
    kind: Literal["boot"]
    record: BootRecord


class SummaryOccurrence(RecordOccurrenceBase):
    kind: Literal["summary"]
    record: SummaryRecord


class FailureOccurrence(RecordOccurrenceBase):
    kind: Literal["failure"]
    record: FailureRecord
    mode: Literal["local", "sync", "unknown"]
    incident_id: str


class QuarantineOccurrence(TypedDict):
    schema_version: Literal[2]
    occurrence_id: str
    source_repo: str
    status: Literal["blocked"]
    generation: int
    offset: int
    file: FileBound
    raw_sha256: str
    kind: Literal["quarantined"]
    reason_code: Literal["invalid_json", "invalid_utf8", "invalid_record", "oversized_line"]


RecordOccurrence: TypeAlias = BootOccurrence | SummaryOccurrence | FailureOccurrence
StoredEvent: TypeAlias = RecordOccurrence | QuarantineOccurrence


class ValidEvent(TypedDict):
    status: Literal["valid"]
    value: StoredEvent


class InvalidEvent(TypedDict):
    status: Literal["invalid"]
    code: str


EventValidation: TypeAlias = ValidEvent | InvalidEvent


class ValidRecord(TypedDict):
    status: Literal["valid"]
    value: QARecord


class InvalidRecord(TypedDict):
    status: Literal["invalid"]
    code: str


RecordValidation: TypeAlias = ValidRecord | InvalidRecord


class IncidentIdentity(TypedDict):
    id: str
    source_repo: str
    category: str
    component: str
    mode: Literal["local", "sync", "unknown"]
    error_family: str


def stable_json(value: object) -> str:
    """Serialize validated state deterministically for Redis CAS comparisons."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def is_int(value: object, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def is_qa_seed(value: object) -> bool:
    return is_int(value) and value <= MAX_QA_SEED


def is_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _exact_keys(value: dict[str, object], required: set[str]) -> bool:
    return set(value) == required


def validate_qa_record(value: object) -> RecordValidation:
    """Validate and normalize one complete JSONL record before use."""
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        return {"status": "invalid", "code": "record_not_object"}
    record_type = value.get("type")
    if record_type == "boot":
        if not _exact_keys(value, {"type", "ts", "seed", "syncMode"}):
            return {"status": "invalid", "code": "boot_shape"}
        if not is_timestamp(value["ts"]) or not is_int(value["seed"]):
            return {"status": "invalid", "code": "boot_fields"}
        if not is_qa_seed(value["seed"]):
            return {"status": "invalid", "code": "boot_seed"}
        if not isinstance(value["syncMode"], str):
            return {"status": "invalid", "code": "boot_mode"}
        mode = {"local": "local", "local-only": "local", "sync": "sync"}.get(value["syncMode"], "unknown")
        return {"status": "valid", "value": {
            "type": "boot", "ts": value["ts"], "seed": value["seed"], "sync_mode": mode,
        }}
    if record_type == "summary":
        required = {"type", "ts", "seed", "iterations", "failures", "uptimeS", "opCounters"}
        if not _exact_keys(value, required):
            return {"status": "invalid", "code": "summary_shape"}
        if not is_timestamp(value["ts"]):
            return {"status": "invalid", "code": "summary_timestamp"}
        if not is_qa_seed(value["seed"]):
            return {"status": "invalid", "code": "summary_seed"}
        if any(not is_int(value[key]) for key in ("iterations", "failures", "uptimeS")):
            return {"status": "invalid", "code": "summary_counters"}
        counters = value["opCounters"]
        if not isinstance(counters, dict) or set(counters) != set(QA_OPERATIONS[:-1]):
            return {"status": "invalid", "code": "summary_operations"}
        normalized_counters: dict[str, dict[str, int]] = {}
        for name, counts in counters.items():
            if not isinstance(counts, dict) or set(counts) != {"total", "ok", "fail"}:
                return {"status": "invalid", "code": "summary_operation_shape"}
            if any(not is_int(counts[key]) for key in ("total", "ok", "fail")):
                return {"status": "invalid", "code": "summary_operation_counters"}
            normalized_counters[name] = dict(counts)
        return {"status": "valid", "value": {
            "type": "summary", "ts": value["ts"], "seed": value["seed"],
            "iterations": value["iterations"], "failures": value["failures"],
            "uptimeS": value["uptimeS"], "opCounters": normalized_counters,
        }}
    if record_type == "failure":
        if not _exact_keys(value, {"type", "ts", "seed", "step", "op", "detail"}):
            return {"status": "invalid", "code": "failure_shape"}
        if not is_timestamp(value["ts"]):
            return {"status": "invalid", "code": "failure_timestamp"}
        if not is_qa_seed(value["seed"]):
            return {"status": "invalid", "code": "failure_seed"}
        if not is_int(value["step"]):
            return {"status": "invalid", "code": "failure_step"}
        if not isinstance(value["op"], str) or value["op"] not in QA_OPERATIONS:
            return {"status": "invalid", "code": "failure_operation"}
        if not isinstance(value["detail"], str) or len(value["detail"]) > 32768:
            return {"status": "invalid", "code": "failure_detail"}
        try:
            value["detail"].encode("utf-8")
        except UnicodeEncodeError:
            return {"status": "invalid", "code": "failure_detail"}
        return {"status": "valid", "value": {
            "type": "failure", "ts": value["ts"], "seed": value["seed"],
            "step": value["step"], "op": value["op"], "detail": value["detail"],
        }}
    return {"status": "invalid", "code": "record_type"}


def require_source_repository(source_repo: str) -> str:
    """Reject sources outside the fixed repository registry."""
    if source_repo not in SOURCE_REPOSITORIES:
        raise ContractError("unknown_source_repository")
    return source_repo


def classify_incident(
    source_repo: str,
    record: FailureRecord,
    mode: Literal["local", "sync", "unknown"],
) -> IncidentIdentity:
    """Group only the known count-drift shape; keep other numeric details distinct."""
    require_source_repository(source_repo)
    if mode not in ERROR_MODES:
        raise ContractError("invalid_mode")
    detail = record["detail"]
    if COUNT_DRIFT.fullmatch(detail):
        category, component, family = "state_invariant", "entity_count", "count_drift"
    else:
        category, component = "qa_failure", record["op"]
        family = f"unclassified:{hashlib.sha256(detail.encode('utf-8')).hexdigest()}"
    identity = {
        "source_repo": source_repo,
        "category": category,
        "component": component,
        "mode": mode,
        "error_family": family,
    }
    digest = hashlib.sha256(stable_json(identity).encode("utf-8")).hexdigest()
    return {"id": f"inc_{digest}", **identity}


def make_occurrence_id(
    source_repo: str,
    device: int,
    inode: int,
    generation: int,
    offset: int,
    raw_sha256: str,
) -> str:
    """Identify one actual complete file record, independent of incident grouping."""
    require_source_repository(source_repo)
    if any(not is_int(part) for part in (device, inode, generation, offset)):
        raise ContractError("invalid_occurrence_location")
    if not isinstance(raw_sha256, str) or not _SHA256.fullmatch(raw_sha256):
        raise ContractError("invalid_occurrence_digest")
    value = [source_repo, device, inode, generation, offset, raw_sha256]
    return "occ_" + hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def validate_cursor(value: object) -> CursorValidation:
    """Validate persisted cursor JSON before using its offset or boot context."""
    if not isinstance(value, dict):
        return {"status": "invalid", "code": "cursor_not_object"}
    if set(value) != {"schema_version", "file", "generation", "offset", "boundary_sha256", "boot_context"}:
        return {"status": "invalid", "code": "cursor_shape"}
    if value["schema_version"] != 2 or not is_int(value["generation"]) or not is_int(value["offset"]):
        return {"status": "invalid", "code": "cursor_version_or_position"}
    if not isinstance(value["boundary_sha256"], str) or not _SHA256.fullmatch(value["boundary_sha256"]):
        return {"status": "invalid", "code": "cursor_boundary"}
    file_value = value["file"]
    if not isinstance(file_value, dict):
        return {"status": "invalid", "code": "cursor_file"}
    if file_value == {"status": "unbound"}:
        pass
    elif (
        set(file_value) == {"status", "device", "inode"}
        and file_value.get("status") == "bound"
        and is_int(file_value.get("device"))
        and is_int(file_value.get("inode"))
    ):
        pass
    else:
        return {"status": "invalid", "code": "cursor_file"}
    boot = value["boot_context"]
    if not isinstance(boot, dict):
        return {"status": "invalid", "code": "cursor_boot_context"}
    if boot == {"status": "unknown"}:
        pass
    elif (
        set(boot) == {"status", "seed", "mode"}
        and boot.get("status") == "known"
        and is_qa_seed(boot.get("seed"))
        and boot.get("mode") in ("local", "sync")
    ):
        pass
    else:
        return {"status": "invalid", "code": "cursor_boot_context"}
    return {"status": "valid", "value": cast(Cursor, value)}
