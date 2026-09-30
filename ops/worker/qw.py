import hashlib
import json
import os
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


def find_issue(sig_hash: str):
    # NB: quote the whole query with urlencode; quote() would turn the
    # space separators into %2B and GitHub answers 422 (crashed the watcher).
    q = urllib.parse.urlencode({"q": f"repo:{GH_REPO} in:title SIG:{sig_hash}"})
    res = gh("GET", f"/search/issues?{q}")
    return res.get("items", [{}])[0].get("number") if res.get("total_count") else None


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
    if find_issue(h):
        return  # one issue per signature; no comment spam in v1
    gh("POST", f"/repos/{GH_REPO}/issues", {
        "title": f"[qa-failure {h}] {detail[:100]}",
        "body": f"QA failure signature (auto-filed, not yet auto-PR class).\n\n```\n{detail}\n```\n\nlast seen: seed={seed} step={step}",
    })
