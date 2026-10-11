"""QA cursor and observation persistence checks against isolated Redis 7."""

import hashlib
import json
import os
import re
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

ROOT = Path(__file__).resolve().parents[2]

sys.path.insert(0, str(ROOT / "ops" / "worker"))

import redis
from task_contracts import (
    Cursor, FailureOccurrence, MAX_SAFE_COUNTER, MAX_SAFE_TIMESTAMP_MS, classify_incident,
    make_occurrence_id, stable_json, validate_qa_record, validate_task,
)
from task_store import (
    CURSOR_KEY, QUEUE_KEY, QUEUE_REGISTRY_KEY, TaskStore, TaskStoreError,
    observations_key, occurrence_key, task_key,
)

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
        raw = qa_line(failure("count drift at step 1: runtime=2 model=1", seed=95))
        event, identity, cursor = make_failure_event(raw)
        self.assertEqual(
            self.store.ingest_failure(self.store.read_cursor(), cursor, event, identity),
            {"status": "stored"},
        )
        return identity["id"]

    def _enqueue_two_counter_tasks(self) -> list[str]:
        first_raw = qa_line(failure("count drift at step 1: runtime=96 model=95", seed=95))
        first_event, first_identity, first_cursor = make_failure_event(first_raw)
        self.assertEqual(
            self.store.ingest_failure(self.store.read_cursor(), first_cursor, first_event, first_identity),
            {"status": "stored"},
        )

        second_raw = qa_line(failure("UNKNOWN expected revision 6, observed 5", seed=96))
        second_event, second_identity, second_cursor = make_failure_event(second_raw)
        offset = len(first_raw)
        digest = hashlib.sha256(second_raw).hexdigest()
        second_event["offset"] = offset
        second_event["occurrence_id"] = make_occurrence_id(SOURCE, 1, 2, 0, offset, digest)
        second_cursor["offset"] = offset + len(second_raw)
        second_cursor["boundary_sha256"] = hashlib.sha256((first_raw + second_raw)[-128:]).hexdigest()
        self.assertNotEqual(first_identity["id"], second_identity["id"], "fixtures must exercise two task registrations")
        self.assertEqual(
            self.store.ingest_failure(self.store.read_cursor(), second_cursor, second_event, second_identity),
            {"status": "stored"},
        )
        task_ids = [first_identity["id"], second_identity["id"]]
        self.assertEqual(self.redis.xlen(QUEUE_KEY), 2)
        self.assertCountEqual(self.store.queued_ids(), task_ids)
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
