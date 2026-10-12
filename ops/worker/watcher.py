"""Import-safe, shadow-only JSONL intake for the Website QA harness."""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, cast

from task_contracts import (
    DEFAULT_SOURCE_REPOSITORY,
    BootContext,
    Cursor,
    FailureRecord,
    FailureOccurrence,
    IncidentIdentity,
    QARecord,
    QuarantineOccurrence,
    StoredEvent,
    classify_incident,
    make_occurrence_id,
    stable_json,
    validate_qa_record,
)
from task_store import CursorSnapshot, IngestResult, TaskStore, TaskStoreError

MAX_RECORD_BYTES = 1024 * 1024
_BOUNDARY_BYTES = 128


def _boundary_hash(stream: Any, offset: int) -> str:
    """Fingerprint bytes immediately before a cursor to detect copytruncate rewrites."""
    start = max(0, offset - _BOUNDARY_BYTES)
    stream.seek(start)
    value = stream.read(offset - start)
    stream.seek(offset)
    return hashlib.sha256(value).hexdigest()


class WatcherRecoveryBlocked(RuntimeError):
    """Identify file-history damage that cannot be recovered without losing evidence."""

    domain = "ops.v2.watcher"

    def __init__(self, code: str):
        self.code = code
        super().__init__(f"{self.domain}:{code}")


def _effective_cursor(snapshot: CursorSnapshot, stream: Any) -> tuple[Cursor, dict[str, int]]:
    """Resolve the file identity without changing a bound cursor on rotation."""
    stat = os.fstat(stream.fileno())
    current_file = {"device": int(stat.st_dev), "inode": int(stat.st_ino)}
    empty_boundary = hashlib.sha256(b"").hexdigest()
    if snapshot["status"] == "missing":
        return {
            "schema_version": 2,
            "file": {"status": "bound", **current_file},
            "generation": 0,
            "offset": 0,
            "boundary_sha256": empty_boundary,
            "boot_context": {"status": "unknown"},
        }, current_file

    previous = snapshot["value"]
    previous_file = previous["file"]
    if previous_file["status"] == "unbound":
        raise WatcherRecoveryBlocked("cursor_file_unbound")
    old_file = {"device": previous_file["device"], "inode": previous_file["inode"]}
    if old_file != current_file:
        return previous, old_file
    # ponytail: 128-byte hashes miss distant rewrites; use a producer generation marker if that risk matters.
    if stat.st_size < previous["offset"]:
        raise WatcherRecoveryBlocked("active_file_overwritten")
    if _boundary_hash(stream, previous["offset"]) != previous["boundary_sha256"]:
        raise WatcherRecoveryBlocked("active_file_overwritten")
    return previous, current_file


def _find_archived_file(qa_file: str, device: int, inode: int) -> str | None:
    """Find only a regular archived inode in the active log's immediate directory."""
    directory = os.path.dirname(os.path.abspath(qa_file))
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                try:
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    stat = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if int(stat.st_dev) == device and int(stat.st_ino) == inode:
                    return entry.path
    except OSError:
        return None
    return None


def _read_complete_line(stream: Any, start: int) -> tuple[bytes | None, str | None]:
    """Return one bounded complete line or its digest when it exceeds the cap."""
    first = stream.readline(MAX_RECORD_BYTES + 1)
    if not first:
        return None, None
    digest = hashlib.sha256(first)
    if first.endswith(b"\n"):
        if len(first) <= MAX_RECORD_BYTES:
            return first, None
        return None, digest.hexdigest()
    if len(first) <= MAX_RECORD_BYTES:
        stream.seek(start)
        return None, None

    while True:
        chunk = stream.readline(64 * 1024)
        if not chunk:
            stream.seek(start)
            return None, None
        digest.update(chunk)
        if chunk.endswith(b"\n"):
            return None, digest.hexdigest()


def _boot_after_record(previous: BootContext, record: QARecord) -> BootContext:
    """Keep mode only while later records remain bound to the validated boot seed."""
    if record["type"] == "boot":
        if record["sync_mode"] == "unknown":
            return {"status": "unknown"}
        return {"status": "known", "seed": record["seed"], "mode": record["sync_mode"]}
    if record["type"] == "summary":
        if previous["status"] == "known" and previous["seed"] != record["seed"]:
            return {"status": "unknown"}
        return previous
    if previous["status"] == "known" and previous["seed"] == record["seed"]:
        return previous
    return {"status": "unknown"}


def _make_event(
    record: QARecord,
    source_repo: str,
    file: dict[str, object],
    generation: int,
    offset: int,
    raw_sha256: str,
    boot_context: BootContext,
) -> tuple[StoredEvent, IncidentIdentity | None, BootContext]:
    """Promote one validated record into durable evidence and optional incident identity."""
    file_value = cast(Any, {"status": "bound", **file})
    occurrence_id = make_occurrence_id(
        source_repo,
        int(file["device"]),
        int(file["inode"]),
        generation,
        offset,
        raw_sha256,
    )
    base = {
        "schema_version": 2,
        "occurrence_id": occurrence_id,
        "source_repo": source_repo,
        "generation": generation,
        "offset": offset,
        "file": file_value,
        "raw_sha256": raw_sha256,
    }
    next_boot = _boot_after_record(boot_context, record)
    if record["type"] == "failure":
        mode = (
            boot_context["mode"]
            if boot_context["status"] == "known" and boot_context["seed"] == record["seed"]
            else "unknown"
        )
        identity = classify_incident(source_repo, cast(FailureRecord, record), mode)
        event: FailureOccurrence = {
            **base,
            "kind": "failure",
            "record": record,
            "mode": mode,
            "incident_id": identity["id"],
        }
        return event, identity, next_boot
    if record["type"] == "boot":
        return {**base, "kind": "boot", "record": record}, None, next_boot
    return {**base, "kind": "summary", "record": record}, None, next_boot


def _quarantine_event(
    source_repo: str,
    file: dict[str, object],
    generation: int,
    offset: int,
    reason_code: str,
    raw_sha256: str,
) -> QuarantineOccurrence:
    """Record only the malformed line's digest and location, never its raw bytes."""
    occurrence_id = make_occurrence_id(
        source_repo,
        int(file["device"]),
        int(file["inode"]),
        generation,
        offset,
        raw_sha256,
    )
    return {
        "schema_version": 2,
        "occurrence_id": occurrence_id,
        "source_repo": source_repo,
        "generation": generation,
        "offset": offset,
        "file": {"status": "bound", **file},
        "raw_sha256": raw_sha256,
        "kind": "quarantined",
        "status": "blocked",
        "reason_code": reason_code,
    }


def _decode_line(raw_line: bytes) -> tuple[QARecord | None, str | None]:
    """Decode and validate one complete JSONL line, returning a safe quarantine code."""
    body = raw_line[:-1]
    if body.endswith(b"\r"):
        body = body[:-1]
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "invalid_utf8"
    try:
        value = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return None, "invalid_json"
    result = validate_qa_record(value)
    if result["status"] != "valid":
        return None, "invalid_record"
    return result["value"], None


def _advance(
    store: TaskStore,
    snapshot: CursorSnapshot,
    cursor: Cursor,
    event: StoredEvent,
    identity: IncidentIdentity | None,
) -> IngestResult:
    """Route failures through the task-registration script and other evidence to observations."""
    if event["kind"] == "failure":
        if identity is None:
            raise TaskStoreError("incident_missing")
        return store.ingest_failure(snapshot, cursor, cast(FailureOccurrence, event), identity)
    return store.ingest_observation(snapshot, cursor, event)


def _drain(
    store: TaskStore,
    snapshot: CursorSnapshot,
    cursor: Cursor,
    file: dict[str, int],
    stream: Any,
    source_repo: str,
    *,
    archived: bool,
) -> tuple[int, CursorSnapshot, Cursor, bool]:
    """Commit complete records in order and block rather than rescan overwritten history."""
    processed = 0
    stream.seek(cursor["offset"])
    while True:
        current_size = os.fstat(stream.fileno()).st_size
        if current_size < cursor["offset"] or _boundary_hash(stream, cursor["offset"]) != cursor["boundary_sha256"]:
            code = "rotation_archive_overwritten" if archived else "active_file_overwritten"
            raise WatcherRecoveryBlocked(code)
        start = cursor["offset"]
        raw_line, oversized_hash = _read_complete_line(stream, start)
        if raw_line is None and oversized_hash is None:
            if archived and current_size > start:
                raise WatcherRecoveryBlocked("rotation_archive_incomplete")
            return processed, snapshot, cursor, False
        identity: IncidentIdentity | None = None
        quarantined = oversized_hash is not None
        if oversized_hash is not None:
            next_offset = stream.tell()
            event: StoredEvent = _quarantine_event(
                source_repo, file, cursor["generation"], start, "oversized_line", oversized_hash,
            )
            next_boot: BootContext = {"status": "unknown"}
        else:
            if raw_line is None:
                raise TaskStoreError("line_reader_state")
            next_offset = stream.tell()
            raw_sha256 = hashlib.sha256(raw_line).hexdigest()
            record, invalid_reason = _decode_line(raw_line)
            if invalid_reason is not None:
                event = _quarantine_event(
                    source_repo, file, cursor["generation"], start, invalid_reason, raw_sha256,
                )
                next_boot = {"status": "unknown"}
                quarantined = True
            elif record is not None:
                event, identity, next_boot = _make_event(
                    record, source_repo, file, cursor["generation"], start,
                    raw_sha256, cursor["boot_context"],
                )
            else:
                raise TaskStoreError("record_validation_state")
        next_cursor: Cursor = {
            "schema_version": 2,
            "file": {"status": "bound", **file},
            "generation": cursor["generation"],
            "offset": next_offset,
            "boundary_sha256": _boundary_hash(stream, next_offset),
            "boot_context": next_boot,
        }
        if quarantined:
            result = store.ingest_observation(snapshot, next_cursor, event)
        else:
            result = _advance(store, snapshot, next_cursor, event, identity)
        if result["status"] == "stale_cursor":
            return processed, snapshot, cursor, True
        if result["status"] not in ("stored", "duplicate"):
            raise TaskStoreError("ingest_rejected")
        snapshot = {"status": "stored", "raw": stable_json(next_cursor), "value": next_cursor}
        cursor = next_cursor
        processed += 1


def tail_once(
    store: TaskStore,
    qa_file: str,
    source_repo: str = DEFAULT_SOURCE_REPOSITORY,
) -> int:
    """Drain the bound inode and block when rotation lineage cannot be verified."""
    snapshot = store.read_cursor()
    if snapshot["status"] == "stored" and snapshot["value"]["file"]["status"] == "unbound":
        raise WatcherRecoveryBlocked("cursor_file_unbound")
    try:
        stream = open(qa_file, "rb")
    except FileNotFoundError:
        if snapshot["status"] == "stored" and snapshot["value"]["file"]["status"] == "bound":
            raise WatcherRecoveryBlocked("active_file_missing") from None
        return 0
    with stream:
        cursor, cursor_file = _effective_cursor(snapshot, stream)
        if snapshot["status"] == "missing":
            initialization = store.initialize_cursor(cursor)
            if initialization["status"] == "stored":
                snapshot = {"status": "stored", "raw": stable_json(cursor), "value": cursor}
            elif initialization["status"] == "stale_cursor":
                snapshot = store.read_cursor()
                if snapshot["status"] == "missing":
                    return 0
                cursor, cursor_file = _effective_cursor(snapshot, stream)
            else:
                raise TaskStoreError("cursor_wrong_type")
        active_stat = os.fstat(stream.fileno())
        active_file = {"device": int(active_stat.st_dev), "inode": int(active_stat.st_ino)}
        processed = 0
        if cursor_file != active_file:
            archived_path = _find_archived_file(qa_file, cursor_file["device"], cursor_file["inode"])
            if archived_path is None:
                raise WatcherRecoveryBlocked("rotation_archive_missing")
            try:
                archived_stream = open(archived_path, "rb")
            except OSError:
                raise WatcherRecoveryBlocked("rotation_archive_unavailable") from None
            with archived_stream:
                archived_stat = os.fstat(archived_stream.fileno())
                if (int(archived_stat.st_dev), int(archived_stat.st_ino)) != (
                    cursor_file["device"], cursor_file["inode"],
                ):
                    raise WatcherRecoveryBlocked("rotation_archive_unavailable")
                count, snapshot, cursor, stale = _drain(
                    store, snapshot, cursor, cursor_file, archived_stream, source_repo, archived=True,
                )
                processed += count
                if stale:
                    return processed
            raise WatcherRecoveryBlocked("rotation_chain_unverified")
        count, _, _, _ = _drain(
            store, snapshot, cursor, active_file, stream, source_repo, archived=False,
        )
        return processed + count


def main() -> None:
    """Run the credential-free shadow tailer; no model/GitHub work is started here."""
    import redis

    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    qa_file = os.environ.get("QA_FILE", "/qa/qa-history.jsonl")
    client = redis.Redis.from_url(redis_url, decode_responses=True, socket_timeout=30)
    store = TaskStore(client)
    print(json.dumps({"status": "watcher_started", "mode": "shadow", "namespace": "ops:v2"}), flush=True)
    while True:
        try:
            tail_once(store, qa_file)
        except Exception as error:
            if isinstance(error, WatcherRecoveryBlocked):
                print(json.dumps({"status": "recovery_blocked", "code": error.code}), flush=True)
            else:
                code = error.code if isinstance(error, TaskStoreError) else "intake_error"
                print(json.dumps({"status": "watcher_error", "code": code}), flush=True)
        time.sleep(10)


if __name__ == "__main__":
    main()
