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
from task_contracts import Cursor, stable_json, make_occurrence_id
from task_store import CURSOR_KEY, TaskStore, TaskStoreError, observations_key

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
