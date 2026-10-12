"""Focused tests for the bounded CI provider contracts."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "worker"))

from ci_contracts import (  # noqa: E402
    initial_ci_cursor,
    normalize_job,
    normalize_run,
    validate_ci_cursor,
)

LIBRARY = "ManddarinShop/Hikoutei"
WEBSITE = "ManddarinShop/Hikoutei-Website"
SHA = "4e0bb14386bd14765bfde772fdbdb5ce46479219"


def run_row(
    repo,
    run_id,
    *,
    attempt=1,
    workflow_id=7,
    path=".github/workflows/ci.yml",
    ref="main",
    sha=SHA,
    status="completed",
    conclusion="success",
):
    return {
        "id": run_id,
        "run_attempt": attempt,
        "workflow_id": workflow_id,
        "path": path + "@refs/heads/" + ref,
        "head_sha": sha,
        "head_branch": ref,
        "status": status,
        "conclusion": conclusion,
        "url": f"https://api.github.com/repos/{repo}/actions/runs/{run_id}",
        "html_url": f"https://github.com/{repo}/actions/runs/{run_id}",
    }


def job_row(repo, run, job_id, *, conclusion="success", name="test", steps=None):
    return {
        "id": job_id,
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "run_url": f"https://api.github.com/repos/{repo}/actions/runs/{run['id']}",
        "url": f"https://api.github.com/repos/{repo}/actions/jobs/{job_id}",
        "html_url": f"https://github.com/{repo}/actions/runs/{run['id']}/job/{job_id}",
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "steps": steps or [{"name": "Run", "status": "completed", "conclusion": conclusion}],
    }


class CICollectorTests(unittest.TestCase):
    def test_ci_cursor_requires_exact_per_repository_page_state(self):
        initial = initial_ci_cursor(LIBRARY)
        self.assertEqual(validate_ci_cursor(initial, LIBRARY)["status"], "valid")
        self.assertEqual(validate_ci_cursor(initial, WEBSITE)["status"], "invalid")
        self.assertEqual(validate_ci_cursor({**initial, "pass_id": True}, LIBRARY)["status"], "invalid")
        self.assertEqual(validate_ci_cursor({**initial, "schema_version": 2.0}, LIBRARY)["status"], "invalid")
        self.assertEqual(validate_ci_cursor({**initial, "next_page": 2}, LIBRARY)["status"], "invalid")
        self.assertEqual(validate_ci_cursor({**initial, "next_page": 2, "previous_page_ids": [9]}, LIBRARY)["status"], "valid")
        self.assertEqual(validate_ci_cursor({**initial, "previous_page_ids": [9]}, LIBRARY)["status"], "invalid")

    def test_run_identity_and_state_are_bound_to_the_expected_repository_attempt(self):
        raw = run_row(WEBSITE, 42)
        run = normalize_run(raw, WEBSITE)
        self.assertEqual((run["status"], run["conclusion"]), ("completed", "success"))
        pending = normalize_run(run_row(WEBSITE, 42, status="in_progress", conclusion=None), WEBSITE)
        self.assertEqual((pending["status"], pending["conclusion"]), ("in_progress", None))
        self.assertIsNone(normalize_run({**raw, "repository": {"full_name": LIBRARY}}, WEBSITE))
        self.assertIsNone(normalize_run(raw, WEBSITE, expected_run_id=43))
        self.assertIsNone(normalize_run(raw, WEBSITE, expected_attempt=2))
        self.assertIsNone(normalize_run({**raw, "id": True}, WEBSITE))
        self.assertIsNone(normalize_run({**raw, "url": "http://api.github.com/wrong"}, WEBSITE))
        self.assertIsNone(normalize_run({**raw, "head_sha": "not-a-sha"}, WEBSITE))
        self.assertIsNone(normalize_run({**raw, "head_branch": "../main"}, WEBSITE))
        self.assertIsNone(normalize_run(run_row(WEBSITE, 42, status="in_progress", conclusion="success"), WEBSITE))
        self.assertIsNone(normalize_run(run_row(WEBSITE, 42, conclusion="unknown"), WEBSITE))

    def test_job_identity_and_step_states_are_bound_to_the_run_attempt(self):
        raw_run = run_row(WEBSITE, 42)
        run = normalize_run(raw_run, WEBSITE)
        job = job_row(WEBSITE, raw_run, 7)
        normalized = normalize_job(job, run)
        self.assertEqual((normalized["status"], normalized["steps"][0]["status"]), ("completed", "completed"))
        pending = {
            **job,
            "status": "in_progress",
            "conclusion": None,
            "steps": [{"name": "Run", "status": "queued", "conclusion": None}],
        }
        self.assertEqual(normalize_job(pending, run)["status"], "in_progress")
        self.assertIsNone(normalize_job({**job, "run_id": 43}, run))
        self.assertIsNone(normalize_job({**job, "run_attempt": 2}, run))
        self.assertIsNone(normalize_job({**job, "id": True}, run))
        self.assertIsNone(normalize_job({**job, "run_url": "https://api.github.com/wrong"}, run))
        self.assertIsNone(normalize_job({**job, "steps": [{"name": "Run", "status": "failed", "conclusion": "failure"}]}, run))
        self.assertIsNone(normalize_job({**job, "steps": [{"name": "Run", "status": "in_progress", "conclusion": "success"}]}, run))
        self.assertIsNone(normalize_job({**job, "status": "in_progress", "conclusion": "success"}, run))


if __name__ == "__main__":
    unittest.main()
