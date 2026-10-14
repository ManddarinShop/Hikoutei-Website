"""Focused tests for the bounded CI provider contracts."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "worker"))

from ci_contracts import (  # noqa: E402
    initial_ci_cursor,
    make_ci_failure_event,
    normalize_job,
    normalize_run,
    sanitize_diagnostic,
    scenario_mode,
    scenario_verdicts,
    validate_ci_cursor,
    validate_ci_event,
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


def full_verdict(run_id, *, status="failed", tab="QARecord_Input", steps=None):
    return {
        "status": status,
        "runId": str(run_id),
        "tab": tab,
        "elapsedMs": 318883,
        "apiCalls": 4,
        "throttled429": 0,
        "steps": steps or [
            {"name": "auth", "status": "ok"},
            {"name": "discover-tab", "status": "ok", "detail": "QARecord_Input"},
            {"name": "read-headers", "status": "ok", "detail": "6 columns"},
            {"name": "append-canary", "status": "ok", "detail": "6 cells"},
            {"name": "sync-boot", "status": "ok"},
            {"name": "ingest-poll", "status": "failed", "detail": "ingest-timeout"},
            {"name": "cleanup", "status": "ok"},
        ],
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


    def test_scenario_json_duplicate_keys_never_classify(self):
        valid = json.dumps(full_verdict(42))
        duplicate_run = valid.replace('"runId": "42"', '"runId": "41", "runId": "42"')
        duplicate_status = valid.replace('"status": "failed"', '"status": "misconfigured", "status": "failed"', 1)
        duplicate_step = valid.replace(
            '"name": "auth", "status": "ok"',
            '"name": "auth", "status": "failed", "status": "ok"',
        )
        legacy_minimal = '{"status":"failed","runId":"42","runId":"42","steps":[{"name":"sync-boot","status":"ok"}]}'
        for text in (duplicate_run, duplicate_status, duplicate_step, legacy_minimal):
            with self.subTest(text=text):
                diagnostics = [{"job_id": 1, "sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text, "truncated": False}]
                self.assertEqual(scenario_verdicts(diagnostics, 42), [])
                self.assertEqual(scenario_mode(diagnostics, 42), "unknown")

    def test_diagnostic_redaction_decodes_json_uri_string_tokens(self):
        cases = (
            r'{"database_url":"postgres:\/\/user:fake-db-sensitive-17@example.invalid/app","id":17,"step":"keep exactly"}',
            r'{"database_url":"postgres:\u002f\u002fuser:fake-db-sensitive-17@example.invalid/app","id":17,"step":"keep exactly"}',
            r'{"database_url":"postgr\u0065s:\u002f\u002fuser:fake-db-sensitive-17@example.invalid/app","id":17,"step":"keep exactly"}',
        )
        expected = '{"database_url":"[redacted-url]","id":17,"step":"keep exactly"}'
        for text in cases:
            with self.subTest(text=text):
                clean = sanitize_diagnostic(text)
                self.assertEqual(clean, expected)
                self.assertEqual(json.loads(clean), {
                    "database_url": "[redacted-url]", "id": 17, "step": "keep exactly",
                })
                self.assertEqual(sanitize_diagnostic(clean), clean)
                self.assertNotIn("fake-db-sensitive-17", clean)

        encoded_uri_key = r'{"postgres:\u002f\u002fuser:fake-key-secret@example.invalid/db":"keep","step":17}'
        clean_key = sanitize_diagnostic(encoded_uri_key)
        self.assertEqual(clean_key, '{"[redacted-url]":"keep","step":17}')
        self.assertEqual(json.loads(clean_key), {"[redacted-url]": "keep", "step": 17})
        self.assertEqual(sanitize_diagnostic(clean_key), clean_key)
        self.assertNotIn("fake-key-secret", clean_key)

    def test_diagnostic_redaction_decodes_escaped_credentials_and_preserves_safe_json(self):
        fake_pat = "ghp_" + "A" * 24
        fake_ci_token = "fake-ci-secret-57"
        cases = (
            (r'{"message":"\u0067hp_' + "A" * 24 + r'","count":17,"plain":"keep exactly"}', fake_pat, ""),
            (r'{"message":"\u0042earer fake-bearer-value-71","count":17,"plain":"keep exactly"}', "fake-bearer-value-71", ""),
            (r'{"message":"\u0066ake-ci-secret-57","count":17,"plain":"keep exactly"}', fake_ci_token, fake_ci_token),
            (r'{"message":"\u002d\u002d\u002d\u002d\u002dBEGIN PRIVATE KEY\u002d\u002d\u002d\u002d\u002d\nFAKE_ESCAPED_PRIVATE_KEY\n\u002d\u002d\u002d\u002d\u002dEND PRIVATE KEY\u002d\u002d\u002d\u002d\u002d","count":17,"plain":"keep exactly"}', "FAKE_ESCAPED_PRIVATE_KEY", ""),
        )
        for text, secret, token in cases:
            with self.subTest(secret=secret[:12]):
                clean = sanitize_diagnostic(text, token)
                decoded = json.loads(clean)
                self.assertNotIn(secret, json.dumps(decoded))
                self.assertEqual((decoded["count"], decoded["plain"]), (17, "keep exactly"))
                self.assertEqual(sanitize_diagnostic(clean, token), clean)

        compound_pat = "ghp_" + "C" * 24
        compound_text = (
            r'{"api_key_\u0067hp_' + "C" * 24
            + r'":"fake-field-value-79","count":17,"plain":"keep exactly"}'
        )
        compound_clean = sanitize_diagnostic(compound_text)
        compound_decoded = json.loads(compound_clean)
        compound_json = json.dumps(compound_decoded)
        self.assertNotIn(compound_pat, compound_json)
        self.assertNotIn("fake-field-value-79", compound_json)
        self.assertEqual(compound_decoded, {
            "api_key_[redacted]": "[redacted]",
            "count": 17,
            "plain": "keep exactly",
        })
        self.assertEqual(sanitize_diagnostic(compound_clean), compound_clean)

        key_secret = "ghp_" + "B" * 24
        encoded_key = r'{"\u0067hp_' + "B" * 24 + r'":"keep exactly","count":17}'
        clean_key = sanitize_diagnostic(encoded_key)
        self.assertEqual(json.loads(clean_key), {"[redacted]": "keep exactly", "count": 17})
        self.assertNotIn(key_secret, clean_key)
        self.assertEqual(sanitize_diagnostic(clean_key), clean_key)

        bearer_key_secret = "fake-bearer-key-73"
        bearer_key_cases = (
            r'{"Bearer fake-bearer-key-73":"keep exactly","count":17}',
            r'{"\u0042earer fake-bearer-key-73":"keep exactly","count":17}',
        )
        for text in bearer_key_cases:
            with self.subTest(bearer_key=text):
                clean_bearer_key = sanitize_diagnostic(text)
                self.assertEqual(json.loads(clean_bearer_key), {
                    "Bearer [redacted]": "keep exactly", "count": 17,
                })
                self.assertNotIn(bearer_key_secret, clean_bearer_key)
                self.assertEqual(sanitize_diagnostic(clean_bearer_key), clean_bearer_key)

        encoded_secret_key = r'{"api_\u006bey":"fake-field-secret-73","co\u0075nt":17}'
        clean_secret_key = sanitize_diagnostic(encoded_secret_key)
        self.assertEqual(clean_secret_key, r'{"api_key":"[redacted]","co\u0075nt":17}')
        self.assertEqual(sanitize_diagnostic(clean_secret_key), clean_secret_key)

    def test_ci_event_rejects_escaped_pat_and_accepts_rehashed_sanitized_evidence(self):
        raw_run = run_row(WEBSITE, 42, conclusion="failure")
        run = normalize_run(raw_run, WEBSITE)
        job = normalize_job(job_row(WEBSITE, raw_run, 7, conclusion="failure"), run)
        escaped_pat = r'{"message":"\u0067hp_' + "A" * 24 + '"}'

        def diagnostic(text):
            return {
                "job_id": job["id"],
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "text": text,
                "truncated": False,
            }

        def event_status(text):
            event, _identity = make_ci_failure_event(run, [job], [diagnostic(text)])
            return validate_ci_event(event)["status"]

        self.assertEqual(event_status(escaped_pat), "invalid")
        self.assertEqual(event_status(sanitize_diagnostic(escaped_pat)), "valid")
        escaped_key = r'{"api_\u006bey":"fake-field-secret-73","count":17}'
        self.assertEqual(event_status(escaped_key), "invalid")
        self.assertEqual(event_status(sanitize_diagnostic(escaped_key)), "valid")

    def test_ci_diagnostic_unicode_must_encode_as_utf8(self):
        raw_run = run_row(WEBSITE, 42, conclusion="failure")
        run = normalize_run(raw_run, WEBSITE)
        job = normalize_job(job_row(WEBSITE, raw_run, 7, conclusion="failure"), run)

        def validate_text(text, truncated):
            try:
                digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            except UnicodeEncodeError:
                digest = "0" * 64
            diagnostic = {"job_id": 7, "sha256": digest, "text": text, "truncated": truncated}
            return validate_ci_event(make_ci_failure_event(run, [job], [diagnostic])[0])

        invalid = {"status": "invalid", "code": "ci_diagnostic_fields"}
        for text in (json.loads('"\\ud800"'), json.loads('"\\udfff"')):
            for truncated in (False, True):
                with self.subTest(text=repr(text), truncated=truncated):
                    self.assertEqual(validate_text(text, truncated), invalid)
        for truncated in (False, True):
            self.assertEqual(validate_text("diagnostic 😀", truncated)["status"], "valid")

if __name__ == "__main__":
    unittest.main()
