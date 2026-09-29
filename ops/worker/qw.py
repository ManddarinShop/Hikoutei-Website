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
    q = urllib.parse.quote(f"repo:{GH_REPO} in:title SIG:{sig_hash}")
    res = gh("GET", f"/search/issues?q={q}")
    return res.get("items", [{}])[0].get("number") if res.get("total_count") else None


def file_issue(detail: str, seed: str, step: str) -> None:
    h = sig(detail)
    if find_issue(h):
        return  # one issue per signature; no comment spam in v1
    gh("POST", f"/repos/{GH_REPO}/issues", {
        "title": f"[qa-failure {h}] {detail[:100]}",
        "body": f"QA failure signature (auto-filed, not yet auto-PR class).\n\n```\n{detail}\n```\n\nlast seen: seed={seed} step={step}",
    })
