"""QA cursor and observation persistence checks against isolated Redis 7."""

import contextlib
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "ops" / "worker"))

import redis
from ci_contracts import (
    ci_cursor_key,
    make_ci_attempt_event,
    make_ci_failure_event,
    make_ci_monitor_event,
    make_ci_page_event,
)
from task_contracts import (
    Cursor, FailureOccurrence, MAX_SAFE_COUNTER, MAX_SAFE_TIMESTAMP_MS, classify_incident,
    make_occurrence_id, stable_json, validate_qa_record, validate_stored_event, validate_task,
)
from task_store import (
    CURSOR_KEY, QUEUE_KEY, QUEUE_REGISTRY_KEY, TaskStore, TaskStoreError,
    observations_key, occurrence_key, task_key,
)
from watcher import tail_once

TS = "2026-10-01T12:00:00.000Z"
COUNTER_LIMIT = MAX_SAFE_COUNTER
SOURCE = "ManddarinShop/Hikoutei-Website"
DISPOSABLE_ENV = "HIKOUTEI_OPS_TEST_DISPOSABLE"
REDIS_RUN_ID_ENV = "HIKOUTEI_OPS_TEST_REDIS_RUN_ID"
DISPOSABLE_GUARD_ERROR = "recovery tests require a matching runner-owned disposable Redis identity guard"


def boot(seed: int, mode: str = "local") -> dict[str, object]:
    return {"type": "boot", "ts": TS, "seed": seed, "syncMode": mode}


def qa_line(record: object) -> bytes:
    return (json.dumps(record, separators=(",", ":")) + "\n").encode()


def initial_cursor(device: int, inode: int) -> Cursor:
    return {
        "schema_version": 2,
        "file": {"status": "bound", "device": device, "inode": inode},
        "generation": 0,
        "offset": 0,
        "boundary_sha256": hashlib.sha256(b"").hexdigest(),
        "boot_context": {"status": "unknown"},
    }


def stored_boot_event(seed: object, offset: int = 0) -> dict[str, object]:
    raw = qa_line(boot(seed))
    digest = hashlib.sha256(raw).hexdigest()
    file = {"status": "bound", "device": 1, "inode": 2}
    return {
        "schema_version": 2,
        "occurrence_id": make_occurrence_id(SOURCE, 1, 2, 0, offset, digest),
        "source_repo": SOURCE,
        "generation": 0,
        "offset": offset,
        "file": file,
        "raw_sha256": digest,
        "kind": "boot",
        "record": {"type": "boot", "ts": TS, "seed": seed, "sync_mode": "local"},
    }


def failure(detail: str, *, seed: int = 7, step: int = 1, ts: str = TS) -> dict[str, object]:
    return {"type": "failure", "ts": ts, "seed": seed, "step": step, "op": "step", "detail": detail}


def make_failure_event(raw: bytes, *, mode: str = "unknown") -> tuple[FailureOccurrence, dict[str, object], Cursor]:
    validated = validate_qa_record(json.loads(raw))
    assert validated["status"] == "valid" and validated["value"]["type"] == "failure"
    record = validated["value"]
    identity = classify_incident(SOURCE, record, mode)
    digest = hashlib.sha256(raw).hexdigest()
    occurrence_id = make_occurrence_id(SOURCE, 1, 2, 0, 0, digest)
    file = {"status": "bound", "device": 1, "inode": 2}
    event: FailureOccurrence = {
        "schema_version": 2,
        "occurrence_id": occurrence_id,
        "source_repo": SOURCE,
        "generation": 0,
        "offset": 0,
        "file": file,
        "raw_sha256": digest,
        "kind": "failure",
        "record": record,
        "mode": mode,
        "incident_id": identity["id"],
    }
    cursor: Cursor = {
        "schema_version": 2,
        "file": file,
        "generation": 0,
        "offset": len(raw),
        "boundary_sha256": hashlib.sha256(raw[-128:]).hexdigest(),
        "boot_context": {"status": "unknown"},
    }
    return event, identity, cursor


def make_ci_failure(run_id: int):
    run = {
        "source_repo": SOURCE, "run_id": run_id, "run_attempt": 1,
        "workflow_id": 12, "workflow_path": ".github/workflows/ci.yml",
        "head_sha": "a" * 40, "head_ref": "main",
        "status": "completed", "conclusion": "failure",
    }
    jobs = [{
        "id": run_id + 100, "run_id": run_id, "run_attempt": 1,
        "name": "test", "status": "completed", "conclusion": "failure",
        "steps": [{"name": "Run tests", "status": "completed", "conclusion": "failure"}],
    }]
    text = f"unclassified failure {run_id}"
    diagnostics = [{
        "job_id": run_id + 100, "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "text": text, "truncated": False,
    }]
    return make_ci_failure_event(run, jobs, diagnostics)


class InjectLuaFailure:
    def __init__(self, client, target: str):
        self.client = client
        self.target = target
        self.injected = False

    def __getattr__(self, name):
        return getattr(self.client, name)

    def eval(self, script, numkeys, *parts):
        markers = {
            "registration": "redis.call('XADD', KEYS[4], '*', 'task_id', ARGV[6])",
            "finalize_registration": "redis.call('HSET', KEYS[5], ARGV[6], stream_id)",
            "task": "redis.call('SET', KEYS[3], encoded_task)",
            "observation_index": "redis.call('ZADD', KEYS[6], now_ms, ARGV[5])",
        }
        marker = markers[self.target]
        if not self.injected and marker in script:
            script = script.replace(marker, "redis.call('NO_SUCH_TEST_COMMAND')", 1)
            self.injected = True
        return self.client.eval(script, numkeys, *parts)


class FixedLuaTime:
    marker = "local time = redis.call('TIME')"

    def __init__(self, client, seconds: int, microseconds: int = 0):
        self.client = client
        self.seconds = seconds
        self.microseconds = microseconds
        self.injected = False

    def __getattr__(self, name):
        return getattr(self.client, name)

    def eval(self, script, numkeys, *parts):
        if self.marker not in script:
            raise AssertionError("test script did not expose the Redis TIME seam")
        script = script.replace(
            self.marker,
            f"local time = {{{self.seconds}, {self.microseconds}}}",
            1,
        )
        self.injected = True
        return self.client.eval(script, numkeys, *parts)


class RedisBackedRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        url = os.environ.get("HIKOUTEI_OPS_TEST_REDIS_URL")
        if not url:
            raise unittest.SkipTest("run ops/test/run_recovery_tests.sh for isolated Redis 7 integration tests")
        expected_run_id = os.environ.get(REDIS_RUN_ID_ENV)
        if (
            os.environ.get(DISPOSABLE_ENV) != "1"
            or expected_run_id is None
            or re.fullmatch(r"[0-9a-f]{40}", expected_run_id) is None
        ):
            raise RuntimeError(DISPOSABLE_GUARD_ERROR)
        cls.redis = redis.Redis.from_url(url, decode_responses=True, socket_timeout=3)
        kwargs = cls.redis.connection_pool.connection_kwargs
        if kwargs.get("host") not in ("127.0.0.1", "localhost", "::1") or kwargs.get("db") != 15:
            raise RuntimeError("recovery tests require their loopback-only disposable Redis DB 15")
        info = cls.redis.info("server")
        if not str(info.get("redis_version", "")).startswith("7."):
            raise RuntimeError("recovery tests require Redis 7")
        cls.redis.ping()
        if info.get("run_id") != expected_run_id:
            cls.redis.close()
            raise RuntimeError(DISPOSABLE_GUARD_ERROR)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "redis"):
            cls.redis.close()

    def setUp(self) -> None:
        # Reuse the server-identity-validated runner connection for every destructive reset.
        self.redis.flushdb()
        self.store = TaskStore(self.redis)

    def _enqueue_counter_task(self) -> str:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            path.write_bytes(qa_line(failure("count drift at step 1: runtime=2 model=1", seed=95)))
            self.assertEqual(tail_once(self.store, str(path)), 1)
        return self.store.queued_ids()[0]

    def _enqueue_two_counter_tasks(self) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            path.write_bytes(
                qa_line(failure("count drift at step 1: runtime=96 model=95", seed=95))
                + qa_line(failure("expected revision 6, observed 5", seed=96))
            )
            self.assertEqual(tail_once(self.store, str(path)), 2)
        task_ids = self.store.queued_ids()
        self.assertEqual(len(task_ids), 2)
        return task_ids

    def _replace_task_counters(self, task_id: str, **counters: int) -> str:
        task = self.store.load_task(task_id)
        assert task is not None
        raw = stable_json({**task, **counters})
        self.redis.set(task_key(task_id), raw)
        return raw

    def _counter_state(self, task_id: str) -> tuple[object, ...]:
        return (
            self.redis.get(task_key(task_id)),
            self.redis.get(CURSOR_KEY),
            self.redis.xrange(QUEUE_KEY),
            self.redis.hgetall(QUEUE_REGISTRY_KEY),
            self.store.observation_ids(task_id),
            tuple(sorted((key, self.redis.get(key)) for key in self.redis.scan_iter("ops:v2:occurrence:*"))),
        )

    def _namespace_bytes(self) -> dict[str, bytes | None]:
        return {key: self.redis.dump(key) for key in self.redis.scan_iter("ops:v2:*")}

    def test_url_only_and_invalid_disposable_guards_reject_before_any_write(self) -> None:
        url = os.environ["HIKOUTEI_OPS_TEST_REDIS_URL"]
        cases = ("url_only", "missing_run_id", "mismatched_run_id")

        for case in cases:
            with self.subTest(case=case):
                self.redis.flushdb()
                self.redis.set("ops:v2:guard-sentinel", "preserve")
                before = {key: self.redis.dump(key) for key in self.redis.scan_iter()}
                env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "HIKOUTEI_OPS_TEST_REDIS_URL": url,
                    "PYTHONPATH": os.pathsep.join((
                        str(ROOT / "ops" / "test"), str(ROOT / "ops" / "worker"), str(ROOT),
                    )),
                }
                if case != "url_only":
                    env[DISPOSABLE_ENV] = "1"
                if case == "mismatched_run_id":
                    env[REDIS_RUN_ID_ENV] = "0" * 40
                result = subprocess.run(
                    [sys.executable, "-m", "unittest", "test_recovery_store.RedisBackedRecoveryTests.test_initial_cursor_binding_is_atomic_and_rejects_noninitial_shapes"],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(DISPOSABLE_GUARD_ERROR, result.stderr)
                self.assertEqual(
                    {key: self.redis.dump(key) for key in self.redis.scan_iter()},
                    before,
                )
                self.assertEqual(self.redis.get("ops:v2:guard-sentinel"), "preserve")

    def test_initial_cursor_binding_is_atomic_and_rejects_noninitial_shapes(self) -> None:
        first = initial_cursor(1, 2)
        second = initial_cursor(3, 4)
        malformed = (
            {**first, "offset": 1},
            {**first, "generation": 1},
            {**first, "file": {"status": "unbound"}},
            {**first, "boot_context": {"status": "known", "seed": 1, "mode": "local"}},
        )
        for cursor in malformed:
            with self.subTest(cursor=cursor), self.assertRaisesRegex(TaskStoreError, "invalid_initial_cursor"):
                self.store.initialize_cursor(cursor)
        self.assertEqual(self.store.read_cursor(), {"status": "missing"})

        barrier = Barrier(2)

        def bind(cursor: Cursor):
            barrier.wait()
            return self.store.initialize_cursor(cursor)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(bind, (first, second)))
        self.assertCountEqual([result["status"] for result in results], ["stored", "stale_cursor"])
        stored = self.store.read_cursor()
        self.assertEqual(stored["status"], "stored")
        assert stored["status"] == "stored"
        winner = first if results[0]["status"] == "stored" else second
        self.assertEqual(stored["value"], winner)

        self.redis.delete(CURSOR_KEY)
        self.redis.lpush(CURSOR_KEY, "wrong-type")
        self.assertEqual(self.store.initialize_cursor(first), {"status": "wrong_type"})

    def test_missing_queue_with_registration_fails_without_mutating_other_keys(self) -> None:
        task_id = self._enqueue_counter_task()
        before = {
            key: self.redis.dump(key)
            for key in self.redis.scan_iter("ops:v2:*")
            if key != QUEUE_KEY
        }
        self.redis.delete(QUEUE_KEY)

        with self.assertRaisesRegex(TaskStoreError, "queue_registry_without_queue"):
            self.store.queued_ids()

        after = {key: self.redis.dump(key) for key in self.redis.scan_iter("ops:v2:*")}
        self.assertEqual(after, before)
        self.assertIsNotNone(self.store.load_task(task_id))

    def test_ingress_error_before_queue_registration_retries_without_advancing(self) -> None:
        raw = qa_line(failure("registration marker recovery", seed=99))
        event, identity, cursor = make_failure_event(raw)
        marker = "redis.call('HSET', KEYS[5], ARGV[6], '__pending__')"

        class InjectPendingFailure:
            def __init__(self, client):
                self.client = client
                self.injected = False

            def __getattr__(self, name):
                return getattr(self.client, name)

            def eval(self, script, numkeys, *parts):
                if not self.injected and marker in script:
                    script = script.replace(marker, "redis.call('NO_SUCH_TEST_COMMAND')", 1)
                    self.injected = True
                return self.client.eval(script, numkeys, *parts)

        broken = InjectPendingFailure(self.redis)
        with self.assertRaises(redis.exceptions.ResponseError):
            TaskStore(broken).ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertTrue(broken.injected)
        before = self._namespace_bytes()
        self.assertEqual(self.store.queued_ids(), [])
        self.assertEqual(self._namespace_bytes(), before)
        self.assertEqual(self.store.read_cursor(), {"status": "missing"})

        self.assertEqual(
            self.store.ingest_failure({"status": "missing"}, cursor, event, identity),
            {"status": "duplicate"},
        )
        self.assertEqual(self.store.queued_ids(), [identity["id"]])

    def test_pending_stream_registration_is_discoverable_and_repaired_on_retry(self) -> None:
        raw = qa_line(failure("pending registration recovery", seed=98))
        event, identity, cursor = make_failure_event(raw)
        target = "if registration ~= stream_id then redis.call('HSET', KEYS[5], ARGV[6], stream_id) end"

        class InjectFinalizeFailure:
            def __init__(self, client):
                self.client = client
                self.injected = False

            def __getattr__(self, name):
                return getattr(self.client, name)

            def eval(self, script, numkeys, *parts):
                if not self.injected and target in script:
                    script = script.replace(target, "redis.call('NO_SUCH_TEST_COMMAND')", 1)
                    self.injected = True
                return self.client.eval(script, numkeys, *parts)

        broken = InjectFinalizeFailure(self.redis)
        with self.assertRaises(redis.exceptions.ResponseError):
            TaskStore(broken).ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertTrue(broken.injected)
        self.assertEqual(self.store.queued_ids(), [identity["id"]])
        self.assertIsNone(self.store.load_task(identity["id"]))

        self.assertEqual(
            self.store.ingest_failure({"status": "missing"}, cursor, event, identity),
            {"status": "duplicate"},
        )
        self.assertEqual(self.store.queued_ids(), [identity["id"]])
        self.assertIsNotNone(self.store.load_task(identity["id"]))

    def test_queued_ids_only_returns_queued_or_expired_tasks(self) -> None:
        task_id = self._enqueue_counter_task()
        task = self.store.load_task(task_id)
        assert task is not None
        self.redis.set(task_key(task_id), stable_json({**task, "status": "investigating", "owner": "worker", "lease_until_ms": MAX_SAFE_TIMESTAMP_MS}))
        self.assertEqual(self.store.queued_ids(), [])
        self.redis.set(task_key(task_id), stable_json({**task, "status": "investigating", "owner": "worker", "lease_until_ms": 0}))
        self.assertEqual(self.store.queued_ids(), [task_id])

    def test_empty_namespace_has_no_queued_ids(self) -> None:
        self.assertEqual(self.store.queued_ids(), [])

    def test_queued_ids_rejects_empty_retained_stream(self) -> None:
        task_id = self._enqueue_counter_task()
        stream_id, _ = self.redis.xrange(QUEUE_KEY)[0]
        self.assertEqual(self.redis.xdel(QUEUE_KEY, stream_id), 1)
        self.assertEqual(self.redis.type(QUEUE_KEY), "stream")
        before = self._namespace_bytes()

        with self.assertRaisesRegex(TaskStoreError, "queue_invalid_registration"):
            self.store.queued_ids()

        self.assertEqual(self._namespace_bytes(), before)
        self.assertIsNotNone(self.redis.get(task_key(task_id)))

    def test_queued_ids_rejects_missing_finalized_entry_in_nonempty_stream(self) -> None:
        self._enqueue_two_counter_tasks()
        stream_ids = [stream_id for stream_id, _ in self.redis.xrange(QUEUE_KEY)]
        self.assertEqual(self.redis.xdel(QUEUE_KEY, stream_ids[0]), 1)
        before = self._namespace_bytes()

        with self.assertRaisesRegex(TaskStoreError, "queue_invalid_registration"):
            self.store.queued_ids()

        self.assertEqual(self._namespace_bytes(), before)

    def test_queued_ids_rejects_mismatched_finalized_reference(self) -> None:
        task_ids = self._enqueue_two_counter_tasks()
        stream_ids = {
            fields["task_id"]: stream_id
            for stream_id, fields in self.redis.xrange(QUEUE_KEY)
        }
        self.assertEqual(self.redis.xdel(QUEUE_KEY, stream_ids[task_ids[0]]), 1)
        self.redis.hset(QUEUE_REGISTRY_KEY, task_ids[0], "0-1")
        before = self._namespace_bytes()

        with self.assertRaisesRegex(TaskStoreError, "queue_invalid_registration"):
            self.store.queued_ids()

        self.assertEqual(self._namespace_bytes(), before)

    def test_queued_ids_rejects_duplicate_finalized_reference(self) -> None:
        task_ids = self._enqueue_two_counter_tasks()
        stream_ids = {
            fields["task_id"]: stream_id
            for stream_id, fields in self.redis.xrange(QUEUE_KEY)
        }
        self.assertEqual(self.redis.xdel(QUEUE_KEY, stream_ids[task_ids[1]]), 1)
        self.redis.hset(QUEUE_REGISTRY_KEY, task_ids[1], stream_ids[task_ids[0]])
        before = self._namespace_bytes()

        with self.assertRaisesRegex(TaskStoreError, "queue_invalid_registration"):
            self.store.queued_ids()

        self.assertEqual(self._namespace_bytes(), before)

    def test_missing_queue_rejects_wrong_type_and_pending_registry(self) -> None:
        self.redis.rpush(QUEUE_REGISTRY_KEY, "not-a-hash")
        with self.assertRaisesRegex(TaskStoreError, "queue_registry_wrong_type"):
            self.store.queued_ids()
        self.assertEqual(self.redis.lrange(QUEUE_REGISTRY_KEY, 0, -1), ["not-a-hash"])

        self.redis.delete(QUEUE_REGISTRY_KEY)
        self.redis.hset(QUEUE_REGISTRY_KEY, "inc_" + "0" * 64, "__pending__")
        pending = self.redis.dump(QUEUE_REGISTRY_KEY)
        with self.assertRaisesRegex(TaskStoreError, "queue_registry_without_queue"):
            self.store.queued_ids()
        self.assertEqual(self.redis.dump(QUEUE_REGISTRY_KEY), pending)
        self.assertEqual(self.redis.type(QUEUE_KEY), "none")

    def test_ingest_lua_rejects_every_unsafe_task_timestamp_without_writes(self) -> None:
        for index, field in enumerate(("created_at_ms", "updated_at_ms", "error_at_ms", "lease_until_ms", "blocked_at_ms"), start=2):
            with self.subTest(field=field):
                self.redis.flushdb()
                self.store = TaskStore(self.redis)
                task_id = self._enqueue_counter_task()
                task = self.store.load_task(task_id)
                assert task is not None
                if field == "lease_until_ms":
                    task = {**task, "status": "investigating", "owner": "worker", "lease_until_ms": 1000}
                elif field == "blocked_at_ms":
                    task = {**task, "status": "blocked", "reason_code": "prior_error", "blocked_at_ms": 1000}
                self.assertEqual(validate_task(task)["status"], "valid")
                self.redis.set(task_key(task_id), stable_json(task))
                if field == "error_at_ms":
                    invalid_task = {**task, "error": {"status": "recorded", "code": "prior_error", "at_ms": 1 << 53}}
                else:
                    invalid_task = {**task, field: 1 << 53}
                raw_task = stable_json(invalid_task)
                self.redis.set(task_key(task_id), raw_task)
                before = self._namespace_bytes()
                raw_event = qa_line(failure(f"count drift at step {index}: runtime={index + 10} model={index + 9}", seed=95, step=index))
                event, identity, cursor = make_failure_event(raw_event)
                result = self.store.ingest_failure(self.store.read_cursor(), cursor, event, identity)
                self.assertEqual(result, {"status": "invalid_state"})
                self.assertEqual(self.redis.get(task_key(task_id)), raw_task)
                self.assertEqual(self._namespace_bytes(), before)
                with self.assertRaisesRegex(TaskStoreError, "task_invalid_state"):
                    self.store.load_task(task_id)

    def test_ingest_rejects_out_of_range_redis_time_without_writes(self) -> None:
        event, identity, cursor = make_failure_event(qa_line(failure("time bound", seed=97)))
        before = self._namespace_bytes()
        clock = FixedLuaTime(self.redis, seconds=100_000_000_000)
        result = TaskStore(clock).ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertTrue(clock.injected)
        self.assertEqual(result, {"status": "timestamp_out_of_range"})
        self.assertEqual(self._namespace_bytes(), before)

        clock = FixedLuaTime(self.redis, seconds=MAX_SAFE_TIMESTAMP_MS // 1000, microseconds=999_999)
        result = TaskStore(clock).ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertTrue(clock.injected)
        self.assertEqual(result, {"status": "stored"})
        task = self.store.load_task(identity["id"])
        assert task is not None
        self.assertEqual(task["created_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(task["updated_at_ms"], MAX_SAFE_TIMESTAMP_MS)

    def test_claim_rejects_unsafe_stored_timestamp_without_writes(self) -> None:
        task_id = self._enqueue_counter_task()
        raw = self._replace_task_counters(task_id, created_at_ms=1 << 53)
        before = self._namespace_bytes()
        with self.assertRaisesRegex(TaskStoreError, "task_invalid_state"):
            self.store.claim(task_id, "worker")
        self.assertEqual(self.redis.get(task_key(task_id)), raw)
        self.assertEqual(self._namespace_bytes(), before)

    def test_claim_rejects_invalid_owner_and_lease_duration(self) -> None:
        task_id = self._enqueue_counter_task()
        before = self._namespace_bytes()
        for owner in ("é" * 65, "\ud800"):
            with self.subTest(owner=type(owner).__name__), self.assertRaisesRegex(TaskStoreError, "invalid_owner"):
                self.store.claim(task_id, owner)
        for lease_seconds in (0, -1, True, 86401):
            with self.subTest(lease_seconds=lease_seconds), self.assertRaisesRegex(TaskStoreError, "invalid_lease_duration"):
                self.store.claim(task_id, "worker", lease_seconds=lease_seconds)
        self.assertEqual(self._namespace_bytes(), before)

    def test_claim_counter_exhaustion_preserves_task_cursor_and_queue(self) -> None:
        for field in ("attempts", "epoch", "revision"):
            with self.subTest(field=field):
                self.redis.flushdb()
                self.store = TaskStore(self.redis)
                task_id = self._enqueue_counter_task()
                raw = self._replace_task_counters(task_id, **{field: COUNTER_LIMIT})
                before = self._counter_state(task_id)
                self.assertEqual(self.store.claim(task_id, "worker")["status"], "counter_exhausted")
                self.assertEqual(self._counter_state(task_id), before)
                self.assertEqual(self.redis.get(task_key(task_id)), raw)

    def test_claim_increments_all_max_minus_one_counters_exactly(self) -> None:
        task_id = self._enqueue_counter_task()
        self._replace_task_counters(
            task_id,
            attempts=COUNTER_LIMIT - 1,
            epoch=COUNTER_LIMIT - 1,
            revision=COUNTER_LIMIT - 1,
        )
        result = self.store.claim(task_id, "worker")
        self.assertEqual(result["status"], "claimed")
        assert result["status"] == "claimed"
        self.assertEqual(
            tuple(result["task"][field] for field in ("attempts", "epoch", "revision")),
            (COUNTER_LIMIT, COUNTER_LIMIT, COUNTER_LIMIT),
        )
        stored = self.store.load_task(task_id)
        assert stored is not None
        self.assertEqual(
            tuple(stored[field] for field in ("attempts", "epoch", "revision")),
            (COUNTER_LIMIT, COUNTER_LIMIT, COUNTER_LIMIT),
        )

    def test_renew_rejects_invalid_owner_epoch_and_lease_duration(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        before = self._namespace_bytes()
        for owner, epoch, lease_seconds, code in (
            ("bad\ud800", claimed["task"]["epoch"], 300, "invalid_owner"),
            ("worker", True, 300, "invalid_epoch"),
            ("worker", claimed["task"]["epoch"], 0, "invalid_lease_duration"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(TaskStoreError, code):
                self.store.renew(task_id, owner, epoch, lease_seconds=lease_seconds)
        self.assertEqual(self._namespace_bytes(), before)

    def test_renew_exhaustion_preserves_state_and_stale_owner_still_fails(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        self._replace_task_counters(task_id, revision=COUNTER_LIMIT)
        before = self._counter_state(task_id)
        self.assertEqual(self.store.renew(task_id, "stale", claimed["task"]["epoch"])["status"], "stale_owner")
        self.assertEqual(self._counter_state(task_id), before)
        self.assertEqual(self.store.renew(task_id, "worker", claimed["task"]["epoch"])["status"], "counter_exhausted")
        self.assertEqual(self._counter_state(task_id), before)

    def test_renew_increments_max_minus_one_revision_exactly(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        self._replace_task_counters(task_id, revision=COUNTER_LIMIT - 1)
        result = self.store.renew(task_id, "worker", claimed["task"]["epoch"])
        self.assertEqual(result["status"], "renewed")
        assert result["status"] == "renewed"
        self.assertEqual(result["task"]["revision"], COUNTER_LIMIT)
        stored = self.store.load_task(task_id)
        assert stored is not None
        self.assertEqual(stored["revision"], COUNTER_LIMIT)

    def test_transition_rejects_malformed_target_reason_and_revision(self) -> None:
        task_id = self._enqueue_counter_task()
        before = self._namespace_bytes()
        with self.assertRaisesRegex(TaskStoreError, "invalid_revision"):
            self.store.transition(task_id, "blocked", expected_revision=True, reason_code="bad")
        with self.assertRaisesRegex(TaskStoreError, "invalid_transition_target"):
            self.store.transition(task_id, "investigating", expected_revision=0)
        with self.assertRaisesRegex(ValueError, "invalid_reason_code"):
            self.store.transition(task_id, "blocked", expected_revision=0, reason_code="raw message!")
        self.assertEqual(self._namespace_bytes(), before)

    def test_transition_exhaustion_preserves_state_and_stale_owner_still_fails(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        self._replace_task_counters(task_id, revision=COUNTER_LIMIT)
        before = self._counter_state(task_id)
        self.assertEqual(
            self.store.release(task_id, "stale", claimed["task"]["epoch"], COUNTER_LIMIT)["status"],
            "stale_owner",
        )
        self.assertEqual(self._counter_state(task_id), before)
        self.assertEqual(
            self.store.release(task_id, "worker", claimed["task"]["epoch"], COUNTER_LIMIT)["status"],
            "counter_exhausted",
        )
        self.assertEqual(self._counter_state(task_id), before)

    def test_transition_increments_max_minus_one_revision_exactly(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        self._replace_task_counters(task_id, revision=COUNTER_LIMIT - 1)
        result = self.store.release(task_id, "worker", claimed["task"]["epoch"], COUNTER_LIMIT - 1)
        self.assertEqual(result["status"], "transitioned")
        assert result["status"] == "transitioned"
        self.assertEqual(result["task"]["revision"], COUNTER_LIMIT)
        self.assertEqual(self.store.load_task(task_id)["revision"], COUNTER_LIMIT)

    def test_release_missing_queued_and_wrong_type_states_do_not_write(self) -> None:
        task_id = self._enqueue_counter_task()
        before = self._namespace_bytes()
        self.assertEqual(self.store.release("inc_" + "0" * 64, "worker", 1, 0)["status"], "not_found")
        self.assertEqual(self.store.release(task_id, "worker", 0, 0)["status"], "invalid_transition")
        self.assertEqual(self._namespace_bytes(), before)

        self.redis.delete(task_key(task_id))
        self.redis.lpush(task_key(task_id), "wrong-type")
        before = self._namespace_bytes()
        with self.assertRaisesRegex(TaskStoreError, "task_wrong_type"):
            self.store.release(task_id, "worker", 1, 0)
        self.assertEqual(self._namespace_bytes(), before)

    def test_release_fences_owner_epoch_revision_and_expiry_without_writes(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        active = claimed["task"]
        for owner, epoch, revision, status in (
            ("stale", active["epoch"], active["revision"], "stale_owner"),
            ("worker", active["epoch"] + 1, active["revision"], "stale_owner"),
            ("worker", active["epoch"], active["revision"] - 1, "stale_state"),
        ):
            before = self._namespace_bytes()
            self.assertEqual(self.store.release(task_id, owner, epoch, revision)["status"], status)
            self.assertEqual(self._namespace_bytes(), before)

        expired = {**active, "lease_until_ms": 0}
        expired_raw = stable_json(expired)
        self.redis.set(task_key(task_id), expired_raw)
        before = self._namespace_bytes()
        self.assertEqual(
            self.store.release(task_id, "worker", active["epoch"], active["revision"])["status"],
            "expired",
        )
        self.assertEqual(self.redis.get(task_key(task_id)), expired_raw)
        self.assertEqual(self._namespace_bytes(), before)

        self.redis.set(task_key(task_id), stable_json(active))
        released = self.store.release(task_id, "worker", active["epoch"], active["revision"])
        self.assertEqual(released["status"], "transitioned")
        assert released["status"] == "transitioned"
        self.assertEqual(released["task"]["status"], "queued")
        self.assertEqual((released["task"]["attempts"], released["task"]["epoch"]), (1, 1))
        self.assertEqual(released["task"]["revision"], active["revision"] + 1)
        self.assertNotIn("owner", released["task"])
        self.assertNotIn("lease_until_ms", released["task"])
        self.assertEqual(self.store.queued_ids(), [task_id])

    def test_transition_revision_cas_allows_only_one_racing_writer(self) -> None:
        task_id = self._enqueue_counter_task()
        barrier = Barrier(2)

        def block(reason_code: str):
            barrier.wait()
            return self.store.transition(task_id, "blocked", expected_revision=0, reason_code=reason_code)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(block, ("first_reason", "second_reason")))
        self.assertCountEqual([result["status"] for result in results], ["transitioned", "stale_state"])
        task = self.store.load_task(task_id)
        assert task is not None
        self.assertEqual(task["status"], "blocked")
        self.assertEqual(task["revision"], 1)
        self.assertIn(task["reason_code"], ("first_reason", "second_reason"))

    def test_transition_rejects_malformed_raw_state_without_mutation(self) -> None:
        task_id = self._enqueue_counter_task()
        task = self.store.load_task(task_id)
        assert task is not None
        raw = stable_json({**task, "attempts": 1 << 53})
        self.redis.set(task_key(task_id), raw)
        before = self._namespace_bytes()
        with self.assertRaisesRegex(TaskStoreError, "task_invalid_state"):
            self.store.transition(task_id, "blocked", expected_revision=0, reason_code="invalid_state")
        self.assertEqual(self._namespace_bytes(), before)
        self.assertEqual(self.redis.get(task_key(task_id)), raw)

    def test_blocked_error_and_requeue_attempt_history_are_durable(self) -> None:
        task_id = self._enqueue_counter_task()
        blocked = self.store.transition(task_id, "blocked", expected_revision=0, reason_code="malformed_input")
        self.assertEqual(blocked["task"]["status"], "blocked")
        self.assertEqual(blocked["task"]["error"], {
            "status": "recorded", "code": "malformed_input", "at_ms": blocked["task"]["blocked_at_ms"],
        })
        queued = self.store.transition(task_id, "queued", expected_revision=blocked["task"]["revision"])
        self.assertEqual(queued["task"]["status"], "queued")
        self.assertEqual(queued["task"]["error"]["code"], "malformed_input")
        self.assertEqual(queued["task"]["attempts"], 0)
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        blocked_again = self.store.transition(
            task_id, "blocked", expected_revision=claimed["task"]["revision"],
            owner="worker", epoch=claimed["task"]["epoch"], reason_code="retry_blocked",
        )
        assert blocked_again["status"] == "transitioned"
        requeued = self.store.transition(
            task_id, "queued", expected_revision=blocked_again["task"]["revision"],
        )
        assert requeued["status"] == "transitioned"
        self.assertEqual((requeued["task"]["attempts"], requeued["task"]["epoch"]), (1, 1))
        self.assertEqual(requeued["task"]["error"]["code"], "retry_blocked")
        self.assertEqual(self.store.queued_ids(), [task_id])
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)

    def test_lifecycle_transitions_keep_state_shapes_and_error_codes(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "reviewer", lease_seconds=30)
        assert claimed["status"] == "claimed"
        investigating = claimed["task"]
        for forbidden in ("fixing", "verifying", "reviewing", "pr_open", "awaiting_merge", "resolved"):
            with self.subTest(target=forbidden), self.assertRaisesRegex(TaskStoreError, "invalid_transition_target"):
                self.store.transition(task_id, forbidden, expected_revision=investigating["revision"])
        stale = self.store.transition(
            task_id, "blocked", expected_revision=investigating["revision"],
            owner="stale-owner", epoch=investigating["epoch"] - 1, reason_code="stale_owner",
        )
        self.assertEqual(stale["status"], "stale_owner")
        blocked = self.store.transition(
            task_id, "blocked", expected_revision=investigating["revision"],
            owner="reviewer", epoch=investigating["epoch"], reason_code="awaiting_evidence",
        )
        self.assertEqual(blocked["task"]["status"], "blocked")
        self.assertNotIn("owner", blocked["task"])
        self.assertNotIn("lease_until_ms", blocked["task"])
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)

    def test_max_timestamp_round_trips_through_claim_transition_and_release(self) -> None:
        task_id = self._enqueue_counter_task()
        task = self.store.load_task(task_id)
        assert task is not None
        task = {
            **task,
            "created_at_ms": MAX_SAFE_TIMESTAMP_MS,
            "updated_at_ms": MAX_SAFE_TIMESTAMP_MS,
            "error": {"status": "recorded", "code": "prior_error", "at_ms": MAX_SAFE_TIMESTAMP_MS},
        }
        self.redis.set(task_key(task_id), stable_json(task))
        now_ms = MAX_SAFE_TIMESTAMP_MS - 1_000
        clock = FixedLuaTime(self.redis, now_ms // 1000, (now_ms % 1000) * 1000)
        claimed = TaskStore(clock).claim(task_id, "worker", lease_seconds=1)
        self.assertTrue(clock.injected)
        assert claimed["status"] == "claimed"
        self.assertEqual(claimed["task"]["created_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(claimed["task"]["error"]["at_ms"], MAX_SAFE_TIMESTAMP_MS)
        released = TaskStore(clock).release(
            task_id, "worker", claimed["task"]["epoch"], claimed["task"]["revision"],
        )
        self.assertEqual(released["status"], "transitioned")
        assert released["status"] == "transitioned"
        self.assertEqual(released["task"]["created_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(released["task"]["error"]["at_ms"], MAX_SAFE_TIMESTAMP_MS)

        claimed_again = self.store.claim(task_id, "worker")
        assert claimed_again["status"] == "claimed"
        blocked = self.store.transition(
            task_id, "blocked", expected_revision=claimed_again["task"]["revision"],
            owner="worker", epoch=claimed_again["task"]["epoch"], reason_code="finished",
        )
        self.assertEqual(blocked["status"], "transitioned")
        assert blocked["status"] == "transitioned"
        self.assertEqual(blocked["task"]["created_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(blocked["task"]["error"]["at_ms"], blocked["task"]["blocked_at_ms"])

        max_blocked = {
            **blocked["task"],
            "updated_at_ms": MAX_SAFE_TIMESTAMP_MS,
            "blocked_at_ms": MAX_SAFE_TIMESTAMP_MS,
            "error": {"status": "recorded", "code": "finished", "at_ms": MAX_SAFE_TIMESTAMP_MS},
        }
        self.redis.set(task_key(task_id), stable_json(max_blocked))
        queued = self.store.transition(task_id, "queued", expected_revision=max_blocked["revision"])
        self.assertEqual(queued["status"], "transitioned")
        assert queued["status"] == "transitioned"
        self.assertEqual(queued["task"]["created_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(queued["task"]["error"]["at_ms"], MAX_SAFE_TIMESTAMP_MS)

    def test_invalid_lifecycle_edges_do_not_write(self) -> None:
        task_id = self._enqueue_counter_task()
        before = self._namespace_bytes()
        self.assertEqual(self.store.transition(task_id, "queued", expected_revision=0)["status"], "invalid_transition")
        blocked = self.store.transition(task_id, "blocked", expected_revision=0, reason_code="blocked")
        assert blocked["status"] == "transitioned"
        before = self._namespace_bytes()
        self.assertEqual(
            self.store.transition(
                task_id, "blocked", expected_revision=blocked["task"]["revision"], reason_code="blocked",
            )["status"],
            "invalid_transition",
        )
        self.assertEqual(self._namespace_bytes(), before)

    def test_transition_and_release_time_bounds_reject_before_writes(self) -> None:
        task_id = self._enqueue_counter_task()
        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        before = self._namespace_bytes()
        clock = FixedLuaTime(self.redis, seconds=MAX_SAFE_TIMESTAMP_MS // 1000 + 1)
        result = TaskStore(clock).release(
            task_id, "worker", claimed["task"]["epoch"], claimed["task"]["revision"],
        )
        self.assertTrue(clock.injected)
        self.assertEqual(result["status"], "timestamp_out_of_range")
        self.assertEqual(self._namespace_bytes(), before)

        self.redis.flushdb()
        self.store = TaskStore(self.redis)
        task_id = self._enqueue_counter_task()
        clock = FixedLuaTime(
            self.redis,
            seconds=MAX_SAFE_TIMESTAMP_MS // 1000,
            microseconds=999_999,
        )
        blocked = TaskStore(clock).transition(
            task_id, "blocked", expected_revision=0, reason_code="max_time",
        )
        self.assertTrue(clock.injected)
        self.assertEqual(blocked["status"], "transitioned")
        assert blocked["status"] == "transitioned"
        self.assertEqual(blocked["task"]["updated_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(blocked["task"]["blocked_at_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(blocked["task"]["error"]["at_ms"], MAX_SAFE_TIMESTAMP_MS)

    def test_owner_uses_utf8_byte_limit_for_input_and_stored_task_validation(self) -> None:
        task_id = self._enqueue_counter_task()
        queued = self.store.load_task(task_id)
        assert queued is not None
        for invalid_owner in ("é" * 65, "\ud800"):
            with self.subTest(owner=type(invalid_owner).__name__), self.assertRaisesRegex(TaskStoreError, "invalid_owner"):
                self.store.claim(task_id, invalid_owner)
            self.assertEqual(self.store.load_task(task_id), queued)

        owner = "é" * 64
        claimed = self.store.claim(task_id, owner)
        self.assertEqual(claimed["status"], "claimed")
        assert claimed["status"] == "claimed"
        self.assertEqual(claimed["task"]["owner"], owner)
        renewed = self.store.renew(task_id, owner, claimed["task"]["epoch"])
        self.assertEqual(renewed["status"], "renewed")
        assert renewed["status"] == "renewed"
        malformed = {**renewed["task"], "owner": "\ud800"}
        self.redis.set(task_key(task_id), json.dumps(malformed, ensure_ascii=True))
        with self.assertRaisesRegex(TaskStoreError, "task_invalid_state"):
            self.store.load_task(task_id)

    def test_lease_expiry_reclaim_fences_previous_owner_and_stale_renew(self) -> None:
        task_id = self._enqueue_counter_task()
        first = self.store.claim(task_id, "owner-a", lease_seconds=1)
        self.assertEqual(first["status"], "claimed")
        first_task = first["task"]
        self.assertEqual(first_task["status"], "investigating")
        self.assertEqual(self.store.claim(task_id, "owner-b", lease_seconds=1)["status"], "busy")
        expired = {**first_task, "lease_until_ms": 0}
        self.redis.set(task_key(task_id), stable_json(expired))
        self.assertEqual(self.store.renew(task_id, "owner-a", first_task["epoch"], lease_seconds=1)["status"], "expired")
        self.assertCountEqual(self.store.queued_ids(), [task_id])
        second = self.store.claim(task_id, "owner-b", lease_seconds=1)
        self.assertEqual(second["status"], "claimed")
        self.assertEqual((second["task"]["attempts"], second["task"]["epoch"]), (2, 2))
        self.assertEqual(self.store.renew(task_id, "owner-a", first_task["epoch"], lease_seconds=1)["status"], "stale_owner")
        self.assertEqual(self.store.renew(task_id, "owner-b", second["task"]["epoch"], lease_seconds=1)["status"], "renewed")

    def test_load_task_rejects_counter_at_2_to_53(self) -> None:
        task_id = self._enqueue_counter_task()
        raw = self._replace_task_counters(task_id, attempts=1 << 53)
        self.assertEqual(self.redis.get(task_key(task_id)), raw)
        with self.assertRaisesRegex(TaskStoreError, "task_invalid_state"):
            self.store.load_task(task_id)

    def test_claim_and_renew_at_max_safe_timestamp(self) -> None:
        task_id = self._enqueue_counter_task()
        now_ms = MAX_SAFE_TIMESTAMP_MS - 1_000
        clock = FixedLuaTime(self.redis, now_ms // 1000, (now_ms % 1000) * 1000)
        claimed = TaskStore(clock).claim(task_id, "worker", lease_seconds=1)
        self.assertTrue(clock.injected)
        self.assertEqual(claimed["status"], "claimed")
        assert claimed["status"] == "claimed"
        self.assertEqual(claimed["task"]["lease_until_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(claimed["task"]["updated_at_ms"], now_ms)

        clock = FixedLuaTime(self.redis, now_ms // 1000, (now_ms % 1000) * 1000)
        renewed = TaskStore(clock).renew(task_id, "worker", claimed["task"]["epoch"], lease_seconds=1)
        self.assertTrue(clock.injected)
        self.assertEqual(renewed["status"], "renewed")
        assert renewed["status"] == "renewed"
        self.assertEqual(renewed["task"]["lease_until_ms"], MAX_SAFE_TIMESTAMP_MS)
        self.assertEqual(renewed["task"]["updated_at_ms"], now_ms)

    def test_claim_and_renew_time_overflow_reject_before_writes(self) -> None:
        task_id = self._enqueue_counter_task()
        seconds_at_max = MAX_SAFE_TIMESTAMP_MS // 1000
        seconds_over_max = seconds_at_max + 1
        before = self._namespace_bytes()
        clock = FixedLuaTime(self.redis, seconds=seconds_over_max)
        self.assertEqual(TaskStore(clock).claim(task_id, "worker")["status"], "timestamp_out_of_range")
        self.assertTrue(clock.injected)
        self.assertEqual(self._namespace_bytes(), before)

        claimed = self.store.claim(task_id, "worker")
        assert claimed["status"] == "claimed"
        before = self._namespace_bytes()
        clock = FixedLuaTime(self.redis, seconds=seconds_over_max)
        self.assertEqual(TaskStore(clock).renew(task_id, "worker", claimed["task"]["epoch"])["status"], "timestamp_out_of_range")
        self.assertTrue(clock.injected)
        self.assertEqual(self._namespace_bytes(), before)

        investigating = {**claimed["task"], "lease_until_ms": MAX_SAFE_TIMESTAMP_MS}
        raw_task = stable_json(investigating)
        self.redis.set(task_key(task_id), raw_task)
        before = self._namespace_bytes()
        clock = FixedLuaTime(self.redis, seconds=seconds_at_max, microseconds=998_999)
        self.assertEqual(TaskStore(clock).renew(task_id, "worker", claimed["task"]["epoch"])["status"], "timestamp_out_of_range")
        self.assertTrue(clock.injected)
        self.assertEqual(self.redis.get(task_key(task_id)), raw_task)
        self.assertEqual(self._namespace_bytes(), before)

    def test_ingest_lua_rejects_task_counter_at_2_to_53_before_any_write(self) -> None:
        task_id = self._enqueue_counter_task()
        raw = self._replace_task_counters(task_id, attempts=1 << 53)
        before = self._counter_state(task_id)
        event, identity, cursor = make_failure_event(
            qa_line(failure("count drift at step 2: runtime=3 model=2", seed=95, step=2)),
        )
        self.assertEqual(identity["id"], task_id)
        self.assertEqual(self.store.ingest_failure(self.store.read_cursor(), cursor, event, identity), {"status": "invalid_state"})
        self.assertEqual(self._counter_state(task_id), before)
        self.assertEqual(self.redis.get(task_key(task_id)), raw)

    def test_invalid_stored_boot_seed_rejects_before_namespace_write(self) -> None:
        for seed in (True, -1, 1 << 32):
            with self.subTest(seed=seed):
                event = stored_boot_event(seed)
                before = self._namespace_bytes()
                with self.assertRaisesRegex(TaskStoreError, "invalid_occurrence"):
                    self.store.ingest_observation(
                        {"status": "missing"}, initial_cursor(1, 2), event,
                    )
                self.assertEqual(self._namespace_bytes(), before)

    def test_observation_ingest_preserves_cursor_cas_and_duplicate_behavior(self) -> None:
        event = stored_boot_event(1)
        raw = qa_line(boot(1))
        cursor = initial_cursor(1, 2)
        cursor["offset"] = len(raw)
        cursor["boundary_sha256"] = hashlib.sha256(raw[-128:]).hexdigest()
        self.assertEqual(self.store.ingest_observation({"status": "missing"}, cursor, event), {"status": "stored"})
        snapshot = self.store.read_cursor()
        self.assertEqual(snapshot["status"], "stored")
        self.assertEqual(snapshot["value"], cursor)
        self.assertEqual(self.store.ingest_observation({"status": "missing"}, cursor, event), {"status": "stale_cursor"})
        self.assertEqual(self.store.ingest_observation(snapshot, cursor, event), {"status": "duplicate"})
        self.assertEqual(self.store.read_cursor()["value"], cursor)

    def test_atomic_wrong_types_do_not_partially_write_and_legacy_keys_survive(self) -> None:
        raw = qa_line(failure("unknown numeric 12 is retained", seed=99))
        event, identity, cursor = make_failure_event(raw)
        legacy_pos = self.redis.set("q:watcher:pos", "987")
        legacy_stream = self.redis.xadd("q:fix", {"legacy": "untouched"})
        self.redis.set("q:dedupe:legacy", "keep")

        self.redis.set(QUEUE_KEY, "wrong-queue-type")
        result = self.store.ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertEqual(result, {"status": "wrong_type", "key_role": "queue"})
        self.assertIsNone(self.redis.get(occurrence_key(event["occurrence_id"])))
        self.assertIsNone(self.redis.get(task_key(identity["id"])))
        self.assertIsNone(self.redis.get(CURSOR_KEY))
        self.assertEqual(self.redis.get(QUEUE_KEY), "wrong-queue-type")

        self.redis.delete(QUEUE_KEY)
        self.redis.lpush(CURSOR_KEY, "legacy-cursor-type")
        result = self.store.ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertEqual(result, {"status": "wrong_type", "key_role": "cursor"})
        self.assertIsNone(self.redis.get(occurrence_key(event["occurrence_id"])))
        self.assertIsNone(self.redis.get(task_key(identity["id"])))
        self.assertEqual(self.redis.lrange(CURSOR_KEY, 0, -1), ["legacy-cursor-type"])

        self.assertEqual(self.redis.get("q:watcher:pos"), "987")
        self.assertEqual(self.redis.xrange("q:fix")[0][0], legacy_stream)
        self.assertEqual(self.redis.get("q:dedupe:legacy"), "keep")
        self.assertEqual(legacy_pos, True)

    def test_failure_ingest_reuses_incident_and_preserves_evidence_across_restart(self) -> None:
        raw1 = qa_line(failure("count drift at step 1: runtime=2 model=1", seed=7, step=1))
        event1, identity, cursor1 = make_failure_event(raw1)
        self.assertEqual(self.store.ingest_failure({"status": "missing"}, cursor1, event1, identity), {"status": "stored"})
        first_snapshot = self.store.read_cursor()
        assert first_snapshot["status"] == "stored"

        raw2 = qa_line(failure("count drift at step 2: runtime=3 model=2", seed=7, step=2))
        event2, identity2, cursor2 = make_failure_event(raw2)
        self.assertEqual(identity2, identity)
        offset = len(raw1)
        digest = hashlib.sha256(raw2).hexdigest()
        event2["offset"] = offset
        event2["occurrence_id"] = make_occurrence_id(SOURCE, 1, 2, 0, offset, digest)
        cursor2["offset"] = offset + len(raw2)
        cursor2["boundary_sha256"] = hashlib.sha256((raw1 + raw2)[-128:]).hexdigest()
        self.assertEqual(self.store.ingest_failure(first_snapshot, cursor2, event2, identity), {"status": "stored"})
        final_snapshot = self.store.read_cursor()
        self.assertEqual(final_snapshot["value"], cursor2)

        restarted = TaskStore(self.redis)
        self.assertEqual(restarted.ingest_failure(final_snapshot, cursor2, event2, identity), {"status": "duplicate"})
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)
        self.assertEqual(self.redis.hgetall(QUEUE_REGISTRY_KEY), {identity["id"]: self.redis.xrange(QUEUE_KEY)[0][0]})
        task = restarted.load_task(identity["id"])
        self.assertIsNotNone(task)
        self.assertEqual(restarted.observation_ids(identity["id"]), [event1["occurrence_id"], event2["occurrence_id"]])
        self.assertEqual(self.redis.get(occurrence_key(event1["occurrence_id"])), stable_json(event1))
        self.assertEqual(self.redis.get(occurrence_key(event2["occurrence_id"])), stable_json(event2))

    def test_partial_failure_registration_is_repaired_without_duplicate_stream_entry(self) -> None:
        raw = qa_line(failure("registration recovery", seed=8))
        event, identity, cursor = make_failure_event(raw)
        target = "if registration ~= stream_id then redis.call('HSET', KEYS[5], ARGV[6], stream_id) end"

        class InjectLuaFailure:
            def __init__(self, client):
                self.client = client
                self.injected = False

            def __getattr__(self, name):
                return getattr(self.client, name)

            def eval(self, script, numkeys, *parts):
                if not self.injected and target in script:
                    script = script.replace(target, "redis.call('NO_SUCH_TEST_COMMAND')", 1)
                    self.injected = True
                return self.client.eval(script, numkeys, *parts)

        broken = InjectLuaFailure(self.redis)
        with self.assertRaises(redis.exceptions.ResponseError):
            TaskStore(broken).ingest_failure({"status": "missing"}, cursor, event, identity)
        self.assertTrue(broken.injected)
        self.assertEqual(self.redis.hget(QUEUE_REGISTRY_KEY, identity["id"]), "__pending__")
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)
        self.assertIsNone(self.redis.get(task_key(identity["id"])))
        self.assertEqual(self.store.read_cursor(), {"status": "missing"})
        self.assertEqual(self.redis.zcard(observations_key(identity["id"])), 0)

        self.assertEqual(self.store.ingest_failure({"status": "missing"}, cursor, event, identity), {"status": "duplicate"})
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)
        stream_id = self.redis.xrange(QUEUE_KEY)[0][0]
        self.assertEqual(self.redis.hget(QUEUE_REGISTRY_KEY, identity["id"]), stream_id)
        self.assertIsNotNone(self.store.load_task(identity["id"]))
        self.assertEqual(self.store.observation_ids(identity["id"]), [event["occurrence_id"]])
        self.assertEqual(self.store.read_cursor()["value"], cursor)

    def test_repeat_records_reuse_one_task_and_survive_restart(self) -> None:
        first = failure("count drift at step 4: runtime=8 model=7", seed=12, step=4)
        second = failure("count drift at step 91: runtime=100 model=99", seed=12, step=91, ts="2026-10-01T12:00:05.000Z")
        records = [boot(12), first, second]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            path.write_bytes(b"".join(map(qa_line, records)))
            self.assertEqual(tail_once(self.store, str(path)), 3)
            snapshot = self.store.read_cursor()
            self.assertEqual(snapshot["status"], "stored")
            self.assertEqual(snapshot["value"]["offset"], path.stat().st_size)
            task_ids = self.store.queued_ids()
            self.assertEqual(len(task_ids), 1)
            self.assertEqual(self.redis.type(QUEUE_KEY), "stream")
            self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)
            observations = self.store.observation_ids(task_ids[0])
            self.assertEqual(len(observations), 2)
            self.assertNotEqual(observations[0], observations[1])
            task = self.store.load_task(task_ids[0])
            self.assertIsNotNone(task)
            self.assertEqual(task["mode"], "local")
            restarted = TaskStore(self.redis)
            self.assertEqual(tail_once(restarted, str(path)), 0)
            self.assertEqual(restarted.observation_ids(task_ids[0]), observations)
            self.assertEqual(restarted.queued_ids(), task_ids)

    def test_partial_line_waits_then_poison_is_quarantined_before_advance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            complete = qa_line(boot(5))
            failure_bytes = qa_line(failure("expected revision 5, observed 4", seed=5))
            split = len(failure_bytes) // 2
            path.write_bytes(complete + failure_bytes[:split])
            self.assertEqual(tail_once(self.store, str(path)), 1)
            cursor_before = self.store.read_cursor()
            self.assertEqual(cursor_before["value"]["offset"], len(complete))
            with path.open("ab") as output:
                output.write(failure_bytes[split:])
            self.assertEqual(tail_once(self.store, str(path)), 1)
            self.assertEqual(len(self.store.queued_ids()), 1)

            poison = b"secret-value-that-must-not-be-logged\n"
            with path.open("ab") as output:
                output.write(poison + qa_line({"type": "unknown", "value": "safe"}))
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
                self.assertEqual(tail_once(self.store, str(path)), 2)
            self.assertNotIn("secret-value-that-must-not-be-logged", captured.getvalue())
            stored_events = [
                json.loads(self.redis.get(key))
                for key in self.redis.scan_iter("ops:v2:occurrence:*")
            ]
            quarantined = [event for event in stored_events if event.get("kind") == "quarantined"]
            self.assertEqual(len(quarantined), 2)
            self.assertTrue(all(event["status"] == "blocked" for event in quarantined))
            self.assertTrue(all("secret-value-that-must-not-be-logged" not in json.dumps(event) for event in quarantined))

    def test_empty_new_active_file_blocks_and_retains_old_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            path.write_bytes(qa_line(boot(83)))
            self.assertEqual(tail_once(self.store, str(path)), 1)
            before = self.store.read_cursor()
            archive = path.with_suffix(".rotated")
            path.rename(archive)
            path.write_bytes(b"")
            source_bytes = {archive: archive.read_bytes(), path: path.read_bytes()}

            for restarted in (self.store, TaskStore(self.redis)):
                with self.assertRaises(Exception) as blocked:
                    tail_once(restarted, str(path))
                self.assertEqual(getattr(blocked.exception, "code", None), "rotation_chain_unverified")
                self.assertEqual(restarted.read_cursor()["raw"], before["raw"])
                self.assertEqual({file: file.read_bytes() for file in source_bytes}, source_bytes)

    def test_missing_bound_active_path_blocks_without_advancing_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            self.assertEqual(tail_once(self.store, str(path)), 0)
            path.write_bytes(qa_line(boot(84)))
            self.assertEqual(tail_once(self.store, str(path)), 1)
            before = self.store.read_cursor()
            path.unlink()

            with self.assertRaises(Exception) as blocked:
                tail_once(self.store, str(path))
            self.assertEqual(getattr(blocked.exception, "code", None), "active_file_missing")
            self.assertEqual(self.store.read_cursor()["raw"], before["raw"])

    def test_missing_rotation_archive_blocks_without_advancing_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "qa-history.jsonl"
            path.write_bytes(qa_line(boot(92)))
            self.assertEqual(tail_once(self.store, str(path)), 1)
            before = self.store.read_cursor()
            archive = root / "unavailable"
            path.rename(archive)
            archive.unlink()
            path.write_bytes(qa_line(boot(93)) + qa_line(failure("must not skip old inode", seed=93)))

            with self.assertRaises(Exception) as blocked:
                tail_once(self.store, str(path))
            self.assertEqual(getattr(blocked.exception, "code", None), "rotation_archive_missing")
            self.assertEqual(self.store.read_cursor()["raw"], before["raw"])
            self.assertEqual(len(self.store.queued_ids()), 0)

    def test_same_inode_overwrite_is_explicitly_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            original = qa_line(boot(1)) + qa_line(failure("count drift at step 1: runtime=2 model=1", seed=1))
            path.write_bytes(original)
            original_inode = path.stat().st_ino
            self.assertEqual(tail_once(self.store, str(path)), 2)
            cursor_before = self.store.read_cursor()

            replacement = b"malformed-prefix\\n" + qa_line(boot(2)) + qa_line(
                failure("count drift at step 2: runtime=3 model=2", seed=2)
            )
            with path.open("wb") as output:
                output.write(replacement)
            self.assertEqual(path.stat().st_ino, original_inode)
            with self.assertRaises(Exception) as blocked:
                tail_once(self.store, str(path))
            self.assertEqual(getattr(blocked.exception, "code", None), "active_file_overwritten")
            self.assertEqual(self.store.read_cursor()["raw"], cursor_before["raw"])

    def test_processing_error_leaves_failure_cursor_pending_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            prefix = qa_line(boot(8))
            raw = qa_line(failure("count drift at step 2: runtime=4 model=3", seed=8))
            path.write_bytes(prefix)
            self.assertEqual(tail_once(self.store, str(path)), 1)
            cursor_before = self.store.read_cursor()
            self.redis.set(QUEUE_KEY, "wrong-type")
            with path.open("ab") as output:
                output.write(raw)
            with self.assertRaisesRegex(Exception, "ingest_rejected"):
                tail_once(self.store, str(path))
            self.assertEqual(self.store.read_cursor()["raw"], cursor_before["raw"])
            self.assertEqual(self.redis.type(QUEUE_KEY), "string")
            self.assertEqual(list(self.redis.scan_iter("ops:v2:task:*")), [])
            self.assertEqual(
                [json.loads(self.redis.get(key))["kind"] for key in self.redis.scan_iter("ops:v2:occurrence:*")],
                ["boot"],
            )
            self.redis.delete(QUEUE_KEY)
            self.assertEqual(tail_once(self.store, str(path)), 1)
            self.assertEqual(len(self.store.queued_ids()), 1)

    def test_pending_registration_with_matching_stream_entry_replays(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            prefix = qa_line(boot(73))
            path.write_bytes(prefix + qa_line(failure("finalize registration retry", seed=73)))
            failing = InjectLuaFailure(self.redis, "finalize_registration")
            with self.assertRaises(redis.exceptions.ResponseError):
                tail_once(TaskStore(failing), str(path))

            self.assertTrue(failing.injected)
            self.assertEqual(self.store.read_cursor()["value"]["offset"], len(prefix))
            task_id = next(iter(self.redis.hgetall(QUEUE_REGISTRY_KEY)))
            self.assertEqual(self.redis.hget(QUEUE_REGISTRY_KEY, task_id), "__pending__")
            self.assertEqual(self.store.queued_ids(), [task_id])
            self.assertEqual(self.store.claim(task_id, "reviewer")["status"], "not_found")

            self.assertEqual(tail_once(self.store, str(path)), 1)
            self.assertEqual(self.redis.hget(QUEUE_REGISTRY_KEY, task_id), self.redis.xrange(QUEUE_KEY)[0][0])
            self.assertEqual(self.store.queued_ids(), [task_id])
            self.assertEqual(self.store.load_task(task_id)["status"], "queued")

    def test_registration_command_failure_leaves_cursor_pending_and_retry_repairs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            prefix = qa_line(boot(70))
            path.write_bytes(prefix + qa_line(failure("registration failure retry", seed=70)))
            failing = InjectLuaFailure(self.redis, "registration")
            with self.assertRaises(redis.exceptions.ResponseError):
                tail_once(TaskStore(failing), str(path))
            self.assertTrue(failing.injected)
            self.assertEqual(self.store.read_cursor()["value"]["offset"], len(prefix))
            self.assertEqual(len(list(self.redis.scan_iter("ops:v2:occurrence:*"))), 2)
            self.assertEqual(len(list(self.redis.scan_iter("ops:v2:task:*"))), 0)
            before = self._namespace_bytes()
            with self.assertRaisesRegex(TaskStoreError, "queue_registry_without_queue"):
                self.store.queued_ids()
            self.assertEqual(self._namespace_bytes(), before)

            self.assertEqual(tail_once(self.store, str(path)), 1)
            task_id = self.store.queued_ids()[0]
            self.assertEqual(self.redis.type(QUEUE_KEY), "stream")
            registrations = [
                stream_id for stream_id, fields in self.redis.xrange(QUEUE_KEY)
                if fields.get("task_id") == task_id
            ]
            self.assertEqual(len(registrations), 1)

    def test_observation_index_failure_keeps_task_unclaimable_and_retry_repairs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            prefix = qa_line(boot(72))
            path.write_bytes(prefix + qa_line(failure("observation index failure retry", seed=72)))
            failing = InjectLuaFailure(self.redis, "observation_index")
            with self.assertRaises(redis.exceptions.ResponseError):
                tail_once(TaskStore(failing), str(path))
            self.assertTrue(failing.injected)
            self.assertEqual(self.store.read_cursor()["value"]["offset"], len(prefix))
            task_id = self.redis.xrange(QUEUE_KEY)[0][1]["task_id"]
            stream_id = self.redis.xrange(QUEUE_KEY)[0][0]
            self.assertEqual(self.redis.hget(QUEUE_REGISTRY_KEY, task_id), stream_id)
            self.assertEqual(self.store.observation_ids(task_id), [])
            self.assertEqual(self.store.queued_ids(), [task_id])
            self.assertEqual(self.store.claim(task_id, "reviewer")["status"], "not_found")

            self.assertEqual(tail_once(TaskStore(self.redis), str(path)), 1)
            occurrence_ids = [
                key.rsplit(":", 1)[-1]
                for key in self.redis.scan_iter("ops:v2:occurrence:*")
                if json.loads(self.redis.get(key))["kind"] == "failure"
            ]
            self.assertEqual(self.store.observation_ids(task_id), occurrence_ids)
            self.assertEqual(self.store.load_task(task_id)["status"], "queued")
            self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)
            self.assertEqual(tail_once(TaskStore(self.redis), str(path)), 0)
            self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)

    def test_registration_survives_later_task_write_failure_and_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            prefix = qa_line(boot(71))
            path.write_bytes(prefix + qa_line(failure("task write failure retry", seed=71)))
            failing = InjectLuaFailure(self.redis, "task")
            with self.assertRaises(redis.exceptions.ResponseError):
                tail_once(TaskStore(failing), str(path))
            self.assertTrue(failing.injected)
            self.assertEqual(self.store.read_cursor()["value"]["offset"], len(prefix))
            self.assertEqual(self.redis.type(QUEUE_KEY), "stream")
            task_id = self.redis.xrange(QUEUE_KEY)[0][1]["task_id"]
            self.assertIn(task_id, self.store.queued_ids())
            self.assertIsNone(self.store.load_task(task_id))

            self.assertEqual(tail_once(self.store, str(path)), 1)
            self.assertEqual(self.store.load_task(task_id)["status"], "queued")
            registrations = [
                stream_id for stream_id, fields in self.redis.xrange(QUEUE_KEY)
                if fields.get("task_id") == task_id
            ]
            self.assertEqual(len(registrations), 1)

    def test_quarantine_resets_boot_context_across_restart_until_valid_boot(self) -> None:
        malformed_lines = (
            qa_line({"type": "boot", "ts": TS, "seed": 72, "syncMode": "sync", "extra": True}),
            b"x" * (1024 * 1024 + 1) + b"\n",
        )
        for mode in ("local", "sync"):
            for malformed in malformed_lines:
                with self.subTest(mode=mode, malformed_bytes=len(malformed)):
                    self.redis.flushdb()
                    self.store = TaskStore(self.redis)
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / "qa-history.jsonl"
                        path.write_bytes(qa_line(boot(72, mode)) + malformed)
                        self.assertEqual(tail_once(self.store, str(path)), 2)
                        self.assertEqual(self.store.read_cursor()["value"]["boot_context"], {"status": "unknown"})

                        restarted = TaskStore(self.redis)
                        with path.open("ab") as output:
                            output.write(qa_line(failure("same seed after poison", seed=72)))
                        self.assertEqual(tail_once(restarted, str(path)), 1)
                        task_id = restarted.queued_ids()[0]
                        self.assertEqual(restarted.load_task(task_id)["mode"], "unknown")

                        with path.open("ab") as output:
                            output.write(qa_line(boot(72, mode)) + qa_line(failure("mode restored", seed=72)))
                        self.assertEqual(tail_once(restarted, str(path)), 2)
                        modes = {restarted.load_task(key)["mode"] for key in restarted.queued_ids()}
                        self.assertIn("unknown", modes)
                        self.assertIn(mode, modes)

    def test_observation_index_retry_does_not_reset_existing_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            first = qa_line(failure("count drift at step 4: runtime=8 model=7", seed=12, step=4))
            second = qa_line(failure("count drift at step 5: runtime=8 model=7", seed=12, step=5))
            path.write_bytes(qa_line(boot(12)) + first)
            self.assertEqual(tail_once(self.store, str(path)), 2)
            task_id = self.store.queued_ids()[0]
            claimed = self.store.claim(task_id, "reviewer")
            self.assertEqual(claimed["status"], "claimed")
            before_task = claimed["task"]
            before_observations = self.store.observation_ids(task_id)
            with path.open("ab") as output:
                output.write(second)

            failing = InjectLuaFailure(self.redis, "observation_index")
            with self.assertRaises(redis.exceptions.ResponseError):
                tail_once(TaskStore(failing), str(path))
            self.assertTrue(failing.injected)
            self.assertEqual(self.store.read_cursor()["value"]["offset"], len(qa_line(boot(12))) + len(first))
            self.assertEqual(self.store.load_task(task_id), before_task)
            self.assertEqual(self.store.observation_ids(task_id), before_observations)

            self.assertEqual(tail_once(TaskStore(self.redis), str(path)), 1)
            self.assertEqual(self.store.load_task(task_id), before_task)
            self.assertEqual(len(self.store.observation_ids(task_id)), 2)
            self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)

    def test_partial_initial_file_stays_bound_through_restart_and_archive_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            original_line = qa_line(boot(87))
            split = len(original_line) // 2
            path.write_bytes(original_line[:split])
            self.assertEqual(tail_once(self.store, str(path)), 0)
            initial = self.store.read_cursor()
            self.assertEqual(initial["status"], "stored")
            original_inode = path.stat().st_ino

            restarted = TaskStore(self.redis)
            self.assertEqual(tail_once(restarted, str(path)), 0)
            self.assertEqual(restarted.read_cursor()["raw"], initial["raw"])
            archive = path.with_suffix(".rotated")
            path.rename(archive)
            path.write_bytes(qa_line(boot(88)))
            with self.assertRaises(Exception) as incomplete:
                tail_once(restarted, str(path))
            self.assertEqual(getattr(incomplete.exception, "code", None), "rotation_archive_incomplete")
            self.assertEqual(restarted.read_cursor()["raw"], initial["raw"])

            with archive.open("ab") as output:
                output.write(original_line[split:])
            with self.assertRaises(Exception) as blocked:
                tail_once(TaskStore(self.redis), str(path))
            self.assertEqual(getattr(blocked.exception, "code", None), "rotation_chain_unverified")
            cursor = self.store.read_cursor()["value"]
            self.assertEqual(cursor["file"]["inode"], original_inode)
            self.assertEqual(cursor["offset"], len(original_line))
            events = [json.loads(self.redis.get(key)) for key in self.redis.scan_iter("ops:v2:occurrence:*")]
            self.assertEqual([event["record"]["seed"] for event in events if event["kind"] == "boot"], [87])

    def test_unverified_a_to_b_to_c_rotation_blocks_without_skipping_or_mutating_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            initial = qa_line(boot(80, "sync")) + qa_line(failure("first sync incident", seed=80))
            path.write_bytes(initial)
            self.assertEqual(tail_once(self.store, str(path)), 2)
            before = self.store.read_cursor()["value"]

            pending = qa_line(failure("last safely drained A record", seed=80))
            with path.open("ab") as output:
                output.write(pending)
            archive_a = path.with_suffix(".A")
            path.rename(archive_a)
            bytes_b = qa_line(boot(81, "local")) + qa_line(failure("must not ingest B", seed=81))
            path.write_bytes(bytes_b)
            archive_b = path.with_suffix(".B")
            path.rename(archive_b)
            bytes_c = qa_line(boot(82, "sync")) + qa_line(failure("must not ingest C", seed=82))
            path.write_bytes(bytes_c)
            source_bytes = {file: file.read_bytes() for file in (archive_a, archive_b, path)}

            for restarted in (self.store, TaskStore(self.redis), TaskStore(self.redis)):
                with self.assertRaises(Exception) as blocked:
                    tail_once(restarted, str(path))
                self.assertEqual(getattr(blocked.exception, "code", None), "rotation_chain_unverified")
                cursor = restarted.read_cursor()["value"]
                self.assertEqual(cursor["file"]["inode"], archive_a.stat().st_ino)
                self.assertEqual(cursor["generation"], before["generation"])
                self.assertEqual(cursor["offset"], len(initial) + len(pending))
                events = [json.loads(self.redis.get(key)) for key in self.redis.scan_iter("ops:v2:occurrence:*")]
                failure_details = {event["record"]["detail"] for event in events if event["kind"] == "failure"}
                self.assertEqual(failure_details, {"first sync incident", "last safely drained A record"})
                self.assertEqual(len(restarted.queued_ids()), 2)
                self.assertEqual(self.redis.xlen(QUEUE_KEY), 2)
                self.assertEqual({file: file.read_bytes() for file in source_bytes}, source_bytes)

    def test_rotation_drains_complete_prefix_then_blocks_partial_archive_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            initial = qa_line(boot(90, "local"))
            path.write_bytes(initial)
            self.assertEqual(tail_once(self.store, str(path)), 1)
            summary = qa_line({
                "type": "summary", "ts": TS, "seed": 90, "iterations": 1, "failures": 0,
                "uptimeS": 1, "opCounters": {name: {"total": 0, "ok": 0, "fail": 0} for name in (
                    "create", "update", "delete", "duplicateInsert", "noOpUpdate", "deleteRecreate", "flushCycle")},
            })
            partial = qa_line(failure("partial archive failure", seed=90))
            split = len(partial) // 2
            with path.open("ab") as output:
                output.write(summary + partial[:split])
            archive = path.with_suffix(".rotated")
            path.rename(archive)
            path.write_bytes(qa_line(boot(91, "sync")) + qa_line(failure("new file failure", seed=91)))

            with self.assertRaises(Exception) as blocked:
                tail_once(self.store, str(path))
            self.assertEqual(getattr(blocked.exception, "code", None), "rotation_archive_incomplete")
            cursor = self.store.read_cursor()["value"]
            self.assertEqual(cursor["file"]["inode"], archive.stat().st_ino)
            self.assertEqual(cursor["offset"], len(initial) + len(summary))
            self.assertEqual(len(self.store.queued_ids()), 0)

            with archive.open("ab") as output:
                output.write(partial[split:])
            active_bytes, archive_bytes = path.read_bytes(), archive.read_bytes()
            with self.assertRaises(Exception) as blocked:
                tail_once(TaskStore(self.redis), str(path))
            self.assertEqual(getattr(blocked.exception, "code", None), "rotation_chain_unverified")
            cursor = self.store.read_cursor()["value"]
            self.assertEqual(cursor["file"]["inode"], archive.stat().st_ino)
            self.assertEqual(cursor["offset"], len(initial) + len(summary) + len(partial))
            task_ids = self.store.queued_ids()
            self.assertEqual(len(task_ids), 1)
            self.assertEqual(self.store.load_task(task_ids[0])["mode"], "local")
            events = [json.loads(self.redis.get(key)) for key in self.redis.scan_iter("ops:v2:occurrence:*")]
            self.assertEqual(
                {event["record"]["detail"] for event in events if event["kind"] == "failure"},
                {"partial archive failure"},
            )
            self.assertEqual((path.read_bytes(), archive.read_bytes()), (active_bytes, archive_bytes))

    def test_sync_and_mismatched_seed_modes_are_not_inferred(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            records = [
                boot(1, "sync"),
                failure("count drift at step 1: runtime=2 model=1", seed=1),
                boot(2, "local"),
                failure("count drift at step 2: runtime=3 model=2", seed=1),
                {"type": "summary", "ts": TS, "seed": 3, "iterations": 1, "failures": 0,
                 "uptimeS": 1, "opCounters": {name: {"total": 0, "ok": 0, "fail": 0} for name in (
                     "create", "update", "delete", "duplicateInsert", "noOpUpdate", "deleteRecreate", "flushCycle")}},
                failure("count drift at step 3: runtime=4 model=3", seed=2),
            ]
            path.write_bytes(b"".join(map(qa_line, records)))
            self.assertEqual(tail_once(self.store, str(path)), len(records))
        tasks = [self.store.load_task(task_id) for task_id in self.store.queued_ids()]
        self.assertEqual({task["mode"] for task in tasks if task is not None}, {"sync", "unknown"})
        events = [self.store.load_occurrence(key.rsplit(":", 1)[-1]) for key in self.redis.scan_iter("ops:v2:occurrence:*")]
        failures = sorted(
            (event for event in events if event and event.get("kind") == "failure"),
            key=lambda event: event["offset"],
        )
        self.assertEqual([event["mode"] for event in failures], ["sync", "unknown", "unknown"])

    def test_stored_boot_seed_is_bounded_on_validation_and_load(self) -> None:
        valid = stored_boot_event(0xFFFFFFFF)
        self.assertEqual(validate_stored_event(valid)["status"], "valid")
        self.redis.set(occurrence_key(valid["occurrence_id"]), stable_json(valid))
        self.assertEqual(self.store.load_occurrence(valid["occurrence_id"])["record"]["seed"], 0xFFFFFFFF)

        for offset, seed in enumerate((0x100000000, True, -1), start=1):
            event = stored_boot_event(seed, offset)
            self.assertEqual(validate_stored_event(event)["status"], "invalid")
            self.redis.set(occurrence_key(event["occurrence_id"]), stable_json(event))
            with self.assertRaisesRegex(TaskStoreError, "occurrence_invalid_state"):
                self.store.load_occurrence(event["occurrence_id"])

    def test_ci_cursor_and_failure_ingress_are_independent_of_qa_file_state(self) -> None:
        event, identity = make_ci_failure(37607928772)
        self.assertEqual(self.store.read_cursor(), {"status": "missing"})
        self.assertEqual(self.store.initialize_ci_cursor(SOURCE), {"status": "stored"})
        expected = self.store.read_ci_cursor(SOURCE)
        self.assertEqual(expected["status"], "stored")
        assert expected["status"] == "stored"
        before = expected["raw"]

        self.assertEqual(self.store.ingest_ci_failure(expected, event, identity), {"status": "stored"})
        self.assertEqual(self.store.read_ci_cursor(SOURCE)["raw"], before)
        self.assertEqual(self.store.read_cursor(), {"status": "missing"})
        loaded = self.store.load_occurrence(event["occurrence_id"])
        self.assertEqual(loaded, event)
        task = self.store.load_task(identity["id"])
        self.assertEqual(task["status"], "queued")
        self.assertEqual(self.store.queued_ids(), [identity["id"]])
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)
        self.assertEqual(self.store.observation_ids(identity["id"]), [event["occurrence_id"]])

    def test_ci_monitor_incidents_share_the_registered_queue_and_keep_page_pending(self) -> None:
        event, identity = make_ci_monitor_event(SOURCE, 0, 1, "github_forbidden")
        self.store.initialize_ci_cursor(SOURCE)
        expected = self.store.read_ci_cursor(SOURCE)
        assert expected["status"] == "stored"

        self.assertEqual(self.store.ingest_ci_failure(expected, event, identity), {"status": "stored"})
        self.assertEqual(self.store.ingest_ci_failure(expected, event, identity), {"status": "duplicate"})
        self.assertEqual(self.store.read_ci_cursor(SOURCE)["raw"], expected["raw"])
        self.assertEqual(self.store.load_occurrence(event["occurrence_id"]), event)
        self.assertEqual(self.store.queued_ids(), [identity["id"]])
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)

    def test_ci_failure_partial_registration_replays_without_advancing_cursor(self) -> None:
        event, identity = make_ci_failure(37607928773)
        self.store.initialize_ci_cursor(SOURCE)
        expected = self.store.read_ci_cursor(SOURCE)
        assert expected["status"] == "stored"
        before = expected["raw"]
        failing = TaskStore(InjectLuaFailure(self.redis, "observation_index"))

        with self.assertRaises(redis.ResponseError):
            failing.ingest_ci_failure(expected, event, identity)

        self.assertEqual(failing.read_ci_cursor(SOURCE)["raw"], before)
        self.assertEqual(failing.load_occurrence(event["occurrence_id"]), event)
        self.assertIsNone(failing.load_task(identity["id"]))
        self.assertEqual(self.redis.hget(QUEUE_REGISTRY_KEY, identity["id"]), self.redis.xrange(QUEUE_KEY)[0][0])
        self.assertEqual(
            self.store.ingest_ci_failure(expected, event, identity), {"status": "duplicate"},
        )
        self.assertEqual(self.store.read_ci_cursor(SOURCE)["raw"], before)
        self.assertIsNotNone(self.store.load_task(identity["id"]))
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 1)

    def test_ci_observation_is_immutable_and_does_not_advance_page_cursor(self) -> None:
        run = {
            "source_repo": SOURCE, "run_id": 37607928775, "run_attempt": 1,
            "workflow_id": 12, "workflow_path": ".github/workflows/ci.yml",
            "head_sha": "b" * 40, "head_ref": "develop",
            "status": "completed", "conclusion": "success",
        }
        event = make_ci_attempt_event(run, [])
        self.store.initialize_ci_cursor(SOURCE)
        expected = self.store.read_ci_cursor(SOURCE)
        assert expected["status"] == "stored"
        before = expected["raw"]

        self.assertEqual(self.store.ingest_ci_observation(expected, event), {"status": "stored"})
        self.assertEqual(self.store.ingest_ci_observation(expected, event), {"status": "duplicate"})
        self.assertEqual(self.store.read_ci_cursor(SOURCE)["raw"], before)
        self.assertEqual(self.store.load_occurrence(event["occurrence_id"]), event)

        malformed = {**event, "run": {**run, "head_ref": ""}}
        self.redis.set(occurrence_key(event["occurrence_id"]), stable_json(malformed))
        with self.assertRaisesRegex(TaskStoreError, "occurrence_invalid_state"):
            self.store.load_occurrence(event["occurrence_id"])

    def test_ci_page_checkpoint_uses_payload_identity_and_cursor_cas(self) -> None:
        repo = SOURCE
        self.store.initialize_ci_cursor(repo)
        expected = self.store.read_ci_cursor(repo)
        assert expected["status"] == "stored"
        digest = hashlib.sha256(b"page-one").hexdigest()
        page = make_ci_page_event(repo, 0, 1, digest, [91])
        invalid_next_cursor = {
            "schema_version": 2, "source_repo": repo, "pass_id": 0,
            "next_page": 3, "previous_page_ids": [91],
        }
        with self.assertRaisesRegex(TaskStoreError, "ci_page_invalid"):
            self.store.commit_ci_page(expected, invalid_next_cursor, page)
        self.assertEqual(self.store.read_ci_cursor(repo)["raw"], expected["raw"])
        next_cursor = {
            "schema_version": 2, "source_repo": repo, "pass_id": 0,
            "next_page": 2, "previous_page_ids": [91],
        }

        self.assertEqual(self.store.commit_ci_page(expected, next_cursor, page), {"status": "stored"})
        cursor = self.store.read_ci_cursor(repo)
        self.assertEqual(cursor["value"], next_cursor)
        self.assertEqual(self.store.load_occurrence(page["occurrence_id"]), page)

        later = make_ci_page_event(repo, 0, 1, hashlib.sha256(b"different-page").hexdigest(), [92])
        later_next_cursor = {**next_cursor, "previous_page_ids": [92]}
        self.assertEqual(self.store.commit_ci_page(expected, later_next_cursor, later), {"status": "stale_cursor"})
        self.assertIsNone(self.store.load_occurrence(later["occurrence_id"]))
        self.assertEqual(self.store.read_cursor(), {"status": "missing"})

    def test_ci_ingress_wrong_types_fail_before_writes_and_preserve_qa_cursor(self) -> None:
        event, identity = make_ci_failure(37607928774)
        qa_sentinel = stable_json(initial_cursor(44, 55))
        self.redis.set(CURSOR_KEY, qa_sentinel)
        self.store.initialize_ci_cursor(SOURCE)
        expected = self.store.read_ci_cursor(SOURCE)
        assert expected["status"] == "stored"
        ci_key = ci_cursor_key(SOURCE)

        self.redis.set(QUEUE_KEY, "wrong-queue-type")
        before_cursor = self.redis.get(ci_key)
        result = self.store.ingest_ci_failure(expected, event, identity)
        self.assertEqual(result, {"status": "wrong_type", "key_role": "queue"})
        self.assertIsNone(self.redis.get(occurrence_key(event["occurrence_id"])))
        self.assertIsNone(self.redis.get(task_key(identity["id"])))
        self.assertEqual(self.redis.get(ci_key), before_cursor)
        self.assertEqual(self.redis.get(CURSOR_KEY), qa_sentinel)

        self.redis.delete(QUEUE_KEY)
        self.redis.delete(ci_key)
        self.redis.lpush(ci_key, "wrong-ci-cursor-type")
        result = self.store.ingest_ci_failure({"status": "missing"}, event, identity)
        self.assertEqual(result, {"status": "wrong_type", "key_role": "cursor"})
        self.assertIsNone(self.redis.get(occurrence_key(event["occurrence_id"])))
        self.assertIsNone(self.redis.get(task_key(identity["id"])))
        self.assertEqual(self.redis.get(CURSOR_KEY), qa_sentinel)

    def test_stale_cursor_cannot_advance_or_write_late_occurrence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "qa-history.jsonl"
            path.write_bytes(qa_line(boot(20)))
            self.assertEqual(tail_once(self.store, str(path)), 1)
        old = self.store.read_cursor()
        assert old["status"] == "stored"
        file = old["value"]["file"]
        assert file["status"] == "bound"
        raw1 = qa_line({"type": "summary", "ts": TS, "seed": 20, "iterations": 0, "failures": 0,
                        "uptimeS": 0, "opCounters": {name: {"total": 0, "ok": 0, "fail": 0} for name in (
                            "create", "update", "delete", "duplicateInsert", "noOpUpdate", "deleteRecreate", "flushCycle")}})
        event_id1 = make_occurrence_id(SOURCE, file["device"], file["inode"], 0, old["value"]["offset"], hashlib.sha256(raw1).hexdigest())
        event_id2 = make_occurrence_id(SOURCE, file["device"], file["inode"], 0, old["value"]["offset"] + 1, hashlib.sha256(raw1).hexdigest())
        record = validate_qa_record(json.loads(raw1))
        assert record["status"] == "valid"
        base: dict[str, Any] = {
            "schema_version": 2,
            "source_repo": SOURCE,
            "generation": 0,
            "file": file,
            "raw_sha256": hashlib.sha256(raw1).hexdigest(),
            "kind": "summary",
            "record": record["value"],
        }
        cursor1: Cursor = {**old["value"], "offset": old["value"]["offset"] + len(raw1)}
        cursor1["boundary_sha256"] = hashlib.sha256(raw1[-128:]).hexdigest()
        cursor2: Cursor = {**cursor1, "offset": cursor1["offset"] + 1}
        event1 = {**base, "occurrence_id": event_id1, "offset": old["value"]["offset"]}
        event2 = {**base, "occurrence_id": event_id2, "offset": old["value"]["offset"] + 1}
        self.assertEqual(self.store.ingest_observation(old, cursor1, event1)["status"], "stored")
        self.assertEqual(self.store.ingest_observation(old, cursor2, event2)["status"], "stale_cursor")
        self.assertIsNone(self.store.load_occurrence(event_id2))
        self.assertEqual(self.store.read_cursor()["raw"], json.dumps(cursor1, sort_keys=True, separators=(",", ":")))

class StoreKeyBoundaryTests(unittest.TestCase):
    def test_observations_key_preserves_valid_task_key(self):
        task_id = "inc_" + "a" * 64
        self.assertEqual(observations_key(task_id), "ops:v2:observations:" + task_id)

    def test_observations_key_rejects_invalid_task_ids(self):
        invalid_ids = (
            None,
            7,
            "inc_short",
            "bad_" + "a" * 64,
            "INC_" + "a" * 64,
            "inc_" + "A" * 64,
        )
        for task_id in invalid_ids:
            with self.subTest(task_id=task_id):
                try:
                    observations_key(task_id)
                except TaskStoreError as error:
                    self.assertEqual(error.code, "invalid_task_id")
                    if isinstance(task_id, str):
                        self.assertNotIn(task_id, str(error))
                else:
                    self.fail("invalid task ID was accepted")


if __name__ == "__main__":
    unittest.main()
