import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "worker"))
from task_store import TaskStoreError, observations_key


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
