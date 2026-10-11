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
    Cursor, FailureOccurrence, classify_incident, make_occurrence_id, stable_json,
    validate_qa_record,
)
from task_store import (
    CURSOR_KEY, QUEUE_KEY, QUEUE_REGISTRY_KEY, TaskStore, TaskStoreError,
    observations_key, occurrence_key, task_key,
)

TS = "2026-10-01T12:00:00.000Z"
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
