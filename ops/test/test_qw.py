import hashlib
import io
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "worker"))
import qw


def issue(number, title, **overrides):
    result = {
        "number": number,
        "title": title,
        "state": "open",
        "html_url": f"https://github.com/owner/repo/issues/{number}",
    }
    result.update(overrides)
    return result


class FindIssueTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"PAT": "dummy-token"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_finds_both_legacy_title_markers_and_honors_repo(self):
        signature = "a6558002853af295"
        for title in (
            f"[qa-failure {signature}] existing issue",
            f"SIG:{signature} existing issue",
        ):
            with self.subTest(title=title), patch.object(qw, "gh", return_value=[issue(706, title)]) as request:
                self.assertEqual(qw.find_issue(signature, "other/project"), 706)
                self.assertIn("/repos/other/project/issues?", request.call_args.args[1])

    def test_finds_closed_issues_with_both_legacy_title_markers(self):
        signature = "a6558002853af295"
        for title in (
            f"[qa-failure {signature}] existing issue",
            f"SIG:{signature} existing issue",
        ):
            with self.subTest(title=title), patch.object(
                qw, "gh", return_value=[issue(706, title, state="closed")]
            ) as request:
                self.assertEqual(qw.find_issue(signature, "owner/repo"), 706)
                self.assertIn("state=all", request.call_args.args[1])

    def test_rejects_partial_sig_marker_match(self):
        signature = "a6558002853af295"
        with patch.object(qw, "gh", return_value=[issue(706, f"SIG:{signature}0")]):
            self.assertIsNone(qw.find_issue(signature, "owner/repo"))

    def test_finds_issue_after_five_full_pages(self):
        signature = "a6558002853af295"
        pages = [
            [issue(page * 100 + number + 1, f"unrelated issue {page}-{number}") for number in range(100)]
            for page in range(5)
        ]
        pages.append([issue(706, f"[qa-failure {signature}] found on page six")])
        with patch.object(qw, "gh", side_effect=pages) as request:
            self.assertEqual(qw.find_issue(signature, "owner/repo"), 706)
        self.assertEqual(request.call_count, 6)
        self.assertIn("page=6", request.call_args.args[1])

    def test_finds_closed_issue_after_first_page(self):
        signature = "a6558002853af295"
        first_page = [issue(number + 1, f"unrelated issue {number}") for number in range(100)]
        second_page = [issue(101, f"SIG:{signature} closed issue", state="closed")]
        with patch.object(qw, "gh", side_effect=[first_page, second_page]) as request:
            self.assertEqual(qw.find_issue(signature, "owner/repo"), 101)
        self.assertEqual(request.call_count, 2)
        self.assertTrue(all("state=all" in call.args[1] for call in request.call_args_list))

    def test_skips_pull_request_list_entries(self):
        signature = "a6558002853af295"
        pull_request = issue(706, f"[qa-failure {signature}] PR title", pull_request={"url": "https://api.github.com/repos/owner/repo/pulls/706"})
        with patch.object(qw, "gh", return_value=[pull_request]):
            self.assertIsNone(qw.find_issue(signature, "owner/repo"))

    def test_successful_absence_returns_none(self):
        with patch.object(qw, "gh", return_value=[issue(42, "unrelated")]):
            self.assertIsNone(qw.find_issue("a6558002853af295", "owner/repo"))

    def test_default_repository_uses_gh_repo(self):
        with patch.object(qw, "GH_REPO", "default/project"), patch.object(qw, "gh", return_value=[]) as request:
            self.assertIsNone(qw.find_issue("a6558002853af295"))
        self.assertIn("/repos/default/project/issues?", request.call_args.args[1])

    def test_malformed_response_and_issue_data_raise_structured_errors(self):
        malformed = [
            (None, "invalid_response"),
            ({"items": []}, "invalid_response"),
            (["not an issue"], "invalid_issue"),
            ([issue(True, "bad id")], "invalid_issue"),
            ([issue("706", "bad id")], "invalid_issue"),
            ([issue(0, "bad id")], "invalid_issue"),
            ([issue(706, None)], "invalid_issue"),
            ([issue(706, "invalid state", state="locked")], "invalid_issue"),
            ([issue(706, "bad URL", html_url="/issues/706")], "invalid_issue"),
            ([issue(706, "malformed URL", html_url="https://[")], "invalid_issue"),
        ]
        for response, code in malformed:
            with self.subTest(response=response), patch.object(qw, "gh", return_value=response):
                with self.assertRaises(qw.IssueLookupError) as raised:
                    qw.find_issue("a6558002853af295", "owner/repo")
                self.assertEqual(raised.exception.domain, "github_issue_lookup")
                self.assertEqual(raised.exception.code, code)

    def test_overfull_page_is_a_structured_response_error(self):
        page = [issue(number + 1, f"issue {number}") for number in range(101)]
        with patch.object(qw, "gh", return_value=page):
            with self.assertRaises(qw.IssueLookupError) as raised:
                qw.find_issue("a6558002853af295", "owner/repo")
        self.assertEqual(raised.exception.code, "invalid_response")

    def test_repeated_page_is_a_structured_pagination_error(self):
        page = [issue(number + 1, f"issue {number}") for number in range(100)]
        with patch.object(qw, "gh", side_effect=[page, page]):
            with self.assertRaises(qw.IssueLookupError) as raised:
                qw.find_issue("a6558002853af295", "owner/repo")
        self.assertEqual(raised.exception.code, "pagination_stalled")

    def test_http_auth_and_rate_errors_are_not_absence(self):
        for status in (401, 403, 429):
            error = urllib.error.HTTPError("https://api.github.com", status, "failure", None, io.BytesIO())
            with self.subTest(status=status), patch.object(qw, "gh", side_effect=error):
                with self.assertRaises(qw.IssueLookupError) as raised:
                    qw.find_issue("a6558002853af295", "owner/repo")
                self.assertEqual(raised.exception.code, "request_failed")
                self.assertEqual(raised.exception.http_status, status)

    def test_network_error_is_not_absence(self):
        with patch.object(qw, "gh", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(qw.IssueLookupError) as raised:
                qw.find_issue("a6558002853af295", "owner/repo")
        self.assertEqual(raised.exception.code, "request_failed")

    def test_lookup_failure_never_posts(self):
        calls = []

        def request(method, path, body=None):
            calls.append((method, path, body))
            raise urllib.error.HTTPError(path, 403, "forbidden", None, io.BytesIO())

        with patch.object(qw, "GH_REPO", "owner/repo"), patch.object(qw, "gh", side_effect=request):
            with self.assertRaises(qw.IssueLookupError):
                qw.file_issue("failure detail", "seed", "step")
        self.assertEqual([method for method, _, _ in calls], ["GET"])

    def test_retry_after_lost_post_response_finds_closed_issue_without_mutation(self):
        detail = "same full-detail failure"
        signature = qw.sig(detail)
        stored_issues = []
        calls = []

        def request(method, path, body=None):
            calls.append((method, path, body))
            if method == "GET":
                return list(stored_issues)
            if method == "POST":
                stored_issues.append(issue(706, f"[qa-failure {signature}] {detail}", state="closed"))
                raise RuntimeError("response lost after GitHub stored the issue")
            raise AssertionError(f"unexpected GitHub mutation: {method}")

        with patch.object(qw, "GH_REPO", "owner/repo"), patch.object(qw, "gh", side_effect=request):
            with self.assertRaisesRegex(RuntimeError, "response lost"):
                qw.file_issue(detail, "seed", "step")
            qw.file_issue(detail, "seed", "step")

        self.assertEqual([method for method, _, _ in calls].count("POST"), 1)
        self.assertEqual([method for method, _, _ in calls].count("PATCH"), 0)
        self.assertEqual(qw.sig(detail), hashlib.sha1(detail.encode()).hexdigest()[:16])


if __name__ == "__main__":
    unittest.main()
