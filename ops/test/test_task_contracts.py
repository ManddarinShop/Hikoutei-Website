"""Pure contract checks for recovery grouping and untrusted JSON promotion."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "worker"))

from task_contracts import (  # noqa: E402
    BASE_BRANCH_BY_REPOSITORY,
    ContractError,
    MAX_SAFE_COUNTER,
    MAX_SAFE_TIMESTAMP_MS,
    classify_incident,
    is_safe_timestamp_ms,
    make_occurrence_id,
    validate_cursor,
    validate_qa_record,
    validate_stored_event,
    validate_task,
)

TS = "2026-10-01T12:00:00.000Z"


def failure(detail: str, *, op: str = "step", seed: int = 7, step: int = 1) -> dict[str, object]:
    return {"type": "failure", "ts": TS, "seed": seed, "step": step, "op": op, "detail": detail}


class TaskContractTests(unittest.TestCase):
    def test_known_count_drift_groups_across_volatile_numbers(self) -> None:
        first = validate_qa_record(failure("count drift at step 4: runtime=8 model=7"))
        second = validate_qa_record(failure("count drift at step 99: runtime=100 model=99", step=99))
        self.assertEqual(first["status"], "valid")
        self.assertEqual(second["status"], "valid")
        assert first["status"] == second["status"] == "valid"
        first_id = classify_incident("ManddarinShop/Hikoutei-Website", first["value"], "local")
        second_id = classify_incident("ManddarinShop/Hikoutei-Website", second["value"], "local")
        self.assertEqual(first_id["id"], second_id["id"])
        self.assertEqual(first_id["error_family"], "count_drift")
        self.assertEqual(first_id["component"], "entity_count")

    def test_unknown_numeric_messages_and_modes_remain_distinct(self) -> None:
        a = validate_qa_record(failure("expected revision 41, observed 40"))
        b = validate_qa_record(failure("expected revision 42, observed 40"))
        assert a["status"] == b["status"] == "valid"
        local = classify_incident("ManddarinShop/Hikoutei-Website", a["value"], "local")
        changed = classify_incident("ManddarinShop/Hikoutei-Website", b["value"], "local")
        sync = classify_incident("ManddarinShop/Hikoutei-Website", a["value"], "sync")
        self.assertNotEqual(local["id"], changed["id"])
        self.assertNotEqual(local["id"], sync["id"])
        self.assertTrue(local["error_family"].startswith("unclassified:"))

    def test_source_registry_and_future_base_mapping_are_fixed(self) -> None:
        self.assertEqual(BASE_BRANCH_BY_REPOSITORY["ManddarinShop/Hikoutei"], "develop")
        self.assertEqual(BASE_BRANCH_BY_REPOSITORY["ManddarinShop/Hikoutei-Website"], "main")
        record = validate_qa_record(failure("count drift at step 1: runtime=1 model=0"))
        assert record["status"] == "valid"
        with self.assertRaises(ContractError) as raised:
            classify_incident("someone/fork", record["value"], "local")
        self.assertEqual(raised.exception.code, "unknown_source_repository")

    def test_malformed_external_shapes_do_not_raise_or_promote(self) -> None:
        self.assertEqual(validate_qa_record([])["status"], "invalid")
        self.assertEqual(validate_qa_record({"type": "boot", "ts": TS, "seed": 1, "syncMode": []})["status"], "invalid")
        malformed_cursor = {
            "schema_version": 2,
            "file": {"status": "bound", "device": True, "inode": 3},
            "generation": 0,
            "offset": 0,
            "boundary_sha256": "0" * 64,
            "boot_context": {"status": "unknown"},
        }
        self.assertEqual(validate_cursor(malformed_cursor)["status"], "invalid")

    def test_task_status_is_discriminated_and_identity_bound(self) -> None:
        record = validate_qa_record(failure("count drift at step 1: runtime=1 model=0"))
        assert record["status"] == "valid"
        identity = classify_incident("ManddarinShop/Hikoutei-Website", record["value"], "unknown")
        task = {
            "schema_version": 2,
            **identity,
            "status": "queued",
            "attempts": 0,
            "epoch": 0,
            "revision": 0,
            "created_at_ms": 1,
            "updated_at_ms": 1,
            "error": {"status": "none"},
        }
        self.assertEqual(validate_task(task)["status"], "valid")
        malformed = {**task, "owner": "unexpected-in-queued"}
        self.assertEqual(validate_task(malformed)["status"], "invalid")
        changed_identity = {**task, "mode": "sync"}
        self.assertEqual(validate_task(changed_identity)["status"], "invalid")

    def test_task_counters_fit_exact_lua_json_integer_range(self) -> None:
        record = validate_qa_record(failure("counter validation"))
        assert record["status"] == "valid"
        identity = classify_incident("ManddarinShop/Hikoutei-Website", record["value"], "unknown")
        task = {
            "schema_version": 2,
            **identity,
            "status": "queued",
            "attempts": 0,
            "epoch": 0,
            "revision": 0,
            "created_at_ms": 1,
            "updated_at_ms": 1,
            "error": {"status": "none"},
        }
        self.assertEqual(MAX_SAFE_COUNTER, (1 << 31) - 1)
        for field in ("attempts", "epoch", "revision"):
            self.assertEqual(validate_task({**task, field: MAX_SAFE_COUNTER})["status"], "valid")
            for invalid in (MAX_SAFE_COUNTER + 1, 1 << 53, True, -1, 1.5):
                with self.subTest(field=field, invalid=invalid):
                    self.assertEqual(validate_task({**task, field: invalid})["status"], "invalid")

        # File positions are unbounded here, but task timestamps pass through Lua cjson.
        self.assertEqual(validate_task({**task, "created_at_ms": 1 << 53, "updated_at_ms": 1 << 53})["status"], "invalid")
        cursor = {
            "schema_version": 2,
            "file": {"status": "bound", "device": 1 << 53, "inode": 1 << 53},
            "generation": 1 << 53,
            "offset": 1 << 53,
            "boundary_sha256": "0" * 64,
            "boot_context": {"status": "unknown"},
        }
        self.assertEqual(validate_cursor(cursor)["status"], "valid")

    def test_task_timestamps_are_bounded_in_every_lifecycle_shape(self) -> None:
        record = validate_qa_record(failure("timestamp validation"))
        assert record["status"] == "valid"
        identity = classify_incident("ManddarinShop/Hikoutei-Website", record["value"], "unknown")
        base = {
            "schema_version": 2,
            **identity,
            "attempts": 0,
            "epoch": 0,
            "revision": 0,
            "status": "queued",
            "created_at_ms": 1,
            "updated_at_ms": 1,
            "error": {"status": "none"},
        }
        timestamp_cases = (
            ("created_at_ms", base),
            ("updated_at_ms", base),
            ("at_ms", {**base, "error": {"status": "recorded", "code": "prior_error", "at_ms": 1}}),
            ("lease_until_ms", {**base, "status": "investigating", "owner": "worker", "lease_until_ms": 1}),
            ("blocked_at_ms", {**base, "status": "blocked", "reason_code": "blocked", "blocked_at_ms": 1}),
        )
        invalid_timestamps = (MAX_SAFE_TIMESTAMP_MS + 1, 1 << 53, True, -1, 1.5)
        self.assertTrue(is_safe_timestamp_ms(MAX_SAFE_TIMESTAMP_MS))
        for field, task in timestamp_cases:
            with self.subTest(field=field):
                candidate = dict(task)
                if field == "at_ms":
                    candidate["error"] = {**task["error"], "at_ms": MAX_SAFE_TIMESTAMP_MS}
                else:
                    candidate[field] = MAX_SAFE_TIMESTAMP_MS
                self.assertEqual(validate_task(candidate)["status"], "valid")
                for invalid in invalid_timestamps:
                    with self.subTest(field=field, invalid=invalid):
                        candidate = dict(task)
                        if field == "at_ms":
                            candidate["error"] = {**task["error"], "at_ms": invalid}
                        else:
                            candidate[field] = invalid
                        self.assertEqual(validate_task(candidate)["status"], "invalid")
                        self.assertFalse(is_safe_timestamp_ms(invalid))

    def test_phase_one_accepts_only_queued_investigating_and_blocked(self) -> None:
        record = validate_qa_record(failure("count drift at step 1: runtime=1 model=0"))
        assert record["status"] == "valid"
        identity = classify_incident("ManddarinShop/Hikoutei-Website", record["value"], "unknown")
        base = {
            "schema_version": 2,
            **identity,
            "attempts": 1,
            "epoch": 1,
            "revision": 1,
            "created_at_ms": 1,
            "updated_at_ms": 1,
            "error": {"status": "none"},
        }
        investigating = {
            **base,
            "status": "investigating",
            "owner": "worker",
            "lease_until_ms": 100,
        }
        self.assertEqual(validate_task(investigating)["status"], "valid")
        self.assertEqual(validate_task({**investigating, "owner": "é" * 64})["status"], "valid")
        self.assertEqual(validate_task({**investigating, "owner": "é" * 65})["status"], "invalid")
        self.assertEqual(validate_task({**investigating, "owner": "\ud800"})["status"], "invalid")
        self.assertEqual(validate_task({**base, "status": "active", "owner": "worker", "lease_until_ms": 100})["status"], "invalid")
        for status, evidence in (
            ("pr", {"pr_url": "https://github.com/org/repo/pull/1", "pr_at_ms": 1}),
            ("verified", {"verified_at_ms": 1}),
            ("resolved", {"resolved_at_ms": 1}),
        ):
            self.assertEqual(validate_task({**base, "status": status, **evidence})["status"], "invalid")

    def test_stored_boot_seed_uses_ingress_uint32_bound(self) -> None:
        event = {
            "schema_version": 2,
            "occurrence_id": make_occurrence_id(
                "ManddarinShop/Hikoutei-Website", 1, 2, 0, 0, "0" * 64,
            ),
            "source_repo": "ManddarinShop/Hikoutei-Website",
            "generation": 0,
            "offset": 0,
            "file": {"status": "bound", "device": 1, "inode": 2},
            "raw_sha256": "0" * 64,
            "kind": "boot",
            "record": {"type": "boot", "ts": TS, "seed": 0xFFFFFFFF, "sync_mode": "local"},
        }
        self.assertEqual(validate_stored_event(event)["status"], "valid")
        for invalid_seed in (0x100000000, True, -1):
            malformed = {**event, "record": {**event["record"], "seed": invalid_seed}}
            self.assertEqual(validate_stored_event(malformed)["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
