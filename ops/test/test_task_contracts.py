"""Pure contract checks for recovery grouping and untrusted JSON promotion."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "worker"))

from task_contracts import (  # noqa: E402
    BASE_BRANCH_BY_REPOSITORY,
    ContractError,
    classify_incident,
    validate_cursor,
    validate_qa_record,
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


if __name__ == "__main__":
    unittest.main()
