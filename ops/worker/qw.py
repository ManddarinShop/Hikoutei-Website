import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

GH_REPO = os.environ.get("GH_REPO", "ManddarinShop/Hikoutei")


def sig(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:16]


def gh(method: str, path: str, body=None):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        method=method,
        headers={
            "Authorization": f"Bearer {os.environ['PAT']}",
            "Accept": "application/vnd.github+json",
        },
    )
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data=data, timeout=30) as r:
        return json.load(r) if r.status != 204 else None


class IssueLookupError(RuntimeError):
    """A GitHub lookup failure that must not be treated as an absent issue."""

    domain = "github_issue_lookup"

    def __init__(self, code: str, message: str, *, http_status: int | None = None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def find_issue(sig_hash: str, repo: str | None = None) -> int | None:
    """Return a matching open or closed issue, or None after a complete listing."""
    repository = GH_REPO if repo is None else repo
    parts = repository.split("/") if isinstance(repository, str) else []
    if len(parts) != 2 or not all(parts):
        raise IssueLookupError("invalid_repository", "GitHub repository must be owner/name")

    seen_numbers: set[int] = set()
    sig_marker = re.compile(rf"SIG:{re.escape(sig_hash)}(?![0-9A-Fa-f])")
    legacy_marker = f"[qa-failure {sig_hash}]"
    page = 1
    while True:
        path = (
            f"/repos/{urllib.parse.quote(parts[0], safe='')}/"
            f"{urllib.parse.quote(parts[1], safe='')}/issues?"
            f"{urllib.parse.urlencode({'state': 'all', 'per_page': 100, 'page': page})}"
        )
        try:
            issues = gh("GET", path)
        except Exception as exc:
            status = exc.code if isinstance(exc, urllib.error.HTTPError) else None
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()
            raise IssueLookupError(
                "request_failed", "GitHub issue listing request failed", http_status=status
            ) from exc

        if not isinstance(issues, list) or len(issues) > 100:
            raise IssueLookupError("invalid_response", f"GitHub issue page {page} was malformed")

        page_number_set: set[int] = set()
        page_issues: list[tuple[int, str | None]] = []
        for issue in issues:
            if not isinstance(issue, dict):
                raise IssueLookupError("invalid_issue", f"Malformed issue on page {page}")
            number = issue.get("number")
            if isinstance(number, bool) or not isinstance(number, int) or number < 1:
                raise IssueLookupError("invalid_issue", f"Malformed issue number on page {page}")
            if number in page_number_set:
                raise IssueLookupError("pagination_stalled", f"Duplicate issue on page {page}")
            page_number_set.add(number)

            if "pull_request" in issue:
                if not isinstance(issue["pull_request"], dict):
                    raise IssueLookupError("invalid_issue", f"Malformed pull request on page {page}")
                page_issues.append((number, None))
                continue

            title = issue.get("title")
            state = issue.get("state")
            url = issue.get("html_url")
            try:
                parsed_url = urllib.parse.urlsplit(url) if isinstance(url, str) else None
            except ValueError:
                parsed_url = None
            if (
                not isinstance(title, str)
                or not title
                or state not in ("open", "closed")
                or parsed_url is None
                or parsed_url.scheme != "https"
                or parsed_url.netloc != "github.com"
                or parsed_url.path.rstrip("/").rsplit("/", 2)[-2:] != ["issues", str(number)]
            ):
                raise IssueLookupError("invalid_issue", f"Malformed issue on page {page}")
            page_issues.append((number, title))

        if not page_number_set:
            return None
        if not page_number_set.difference(seen_numbers):
            raise IssueLookupError("pagination_stalled", f"GitHub issue pagination stalled at page {page}")
        seen_numbers.update(page_number_set)

        for number, title in page_issues:
            if title is not None and (legacy_marker in title or sig_marker.search(title)):
                return number

        if len(issues) < 100:
            return None
        page += 1


_SECRETS: list[str] = []


def _register_secret(s: str) -> None:
    if s:
        _SECRETS.append(s)


def _redact(text: str) -> str:
    import os as _os
    for s in _SECRETS + [_os.environ.get("PAT", ""), _os.environ.get("ZEN_KEY", "")]:
        if s:
            text = text.replace(s, "***")
    return text


def _get_text(path: str, limit: int = 6000) -> str:
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={"Authorization": f"Bearer {os.environ['PAT']}",
                 "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")[-limit:]


def ci_failed_logs(sha: str, limit: int = 8000) -> str:
    """Failed CI job logs for a commit. Needs PAT Actions:read; degrades gracefully."""
    try:
        runs = gh("GET", f"/repos/{GH_REPO}/actions/runs?head_sha={sha}&per_page=5")
    except Exception:
        return "(CI run list unavailable: PAT needs Actions read permission)"
    texts = []
    for wr in (runs or {}).get("workflow_runs", []):
        try:
            jobs = gh("GET", f"/repos/{GH_REPO}/actions/runs/{wr['id']}/jobs?per_page=30")
        except Exception:
            continue
        for j in jobs.get("jobs", []):
            if j.get("conclusion") != "failure":
                continue
            try:
                logs = _get_text(f"/repos/{GH_REPO}/actions/jobs/{j['id']}/logs", 4000)
            except Exception as e:
                logs = f"(log fetch failed: {e})"
            texts.append(f"### {wr.get('name')} / {j.get('name')}\n{logs}")
            if sum(map(len, texts)) > limit:
                break
    return "\n".join(texts)[:limit] if texts else "(no failed jobs found)"


def file_issue(detail: str, seed: str, step: str) -> None:
    h = sig(detail)
    if find_issue(h) is not None:
        return  # one issue per signature; no comment spam in v1
    gh("POST", f"/repos/{GH_REPO}/issues", {
        "title": f"[qa-failure {h}] {detail[:100]}",
        "body": f"QA failure signature (auto-filed, not yet auto-PR class).\n\n```\n{detail}\n```\n\nlast seen: seed={seed} step={step}",
    })
