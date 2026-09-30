"""Fixer: Redis Streams (q:fix) -> worktree -> opencode -> branch+PR.

At-least-once + idempotent: branch fix/qa-<dedupe>, PR created only if
no open PR exists for the head branch. Stale leases reclaimed via XAUTOCLAIM.
Attempts > 3 -> DLQ stream + issue, then ack.

Secrets hygiene: PAT/ZEN never appear in logs. GitHub git-over-HTTPS
uses Basic auth (x-access-token), NOT Bearer. Exceptions are redacted
before printing.
"""
import base64
import json
import os
import socket
import subprocess
import time

import redis

import qw

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
GROUP = "workers"
NAME = f"{socket.gethostname()}-{os.getpid()}"
MODEL = os.environ.get("MODEL", "opencode/muse-spark-1.3-contributor-free")
LIB = "/work/lib"
LEASE_MS = int(os.environ.get("LEASE_MS", "1200000"))  # 20 min
MAX_ATTEMPTS = 3

def _git_auth_args() -> list[str]:
    basic = base64.b64encode(f"x-access-token:{os.environ['PAT']}".encode()).decode()
    qw._register_secret(basic)
    return ["-c", f"http.extraHeader=AUTHORIZATION: basic {basic}"]


r = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=30)
print(f"worker {NAME} up, model={MODEL}", flush=True)
try:
    r.xgroup_create("q:fix", GROUP, mkstream=True)
except redis.ResponseError as e:
    if "BUSYGROUP" not in str(e):
        raise


def sh(*args, cwd=None, timeout=120, env=None, check=True):
    env = {"GIT_TERMINAL_PROMPT": "0", **(env or os.environ)}
    return subprocess.run(args, cwd=cwd, timeout=timeout, env=env,
                          capture_output=True, text=True, check=check)


def open_pr(branch: str):
    prs = qw.gh("GET", f"/repos/{qw.GH_REPO}/pulls?head=ManddarinShop:{branch}&state=open")
    return prs[0]["html_url"] if prs else None


def _ahead(wt: str, branch: str) -> int:
    remote = sh("git", "-C", wt, "ls-remote", "--heads", "origin", branch,
                check=False).stdout.strip()
    base = branch if remote else "origin/main"
    out = sh("git", "-C", wt, "rev-list", "--count", f"{base}..HEAD",
             check=False).stdout.strip()
    return int(out or 0)


def process(msg_id: str, f: dict) -> bool:
    is_rework = f.get("kind") == "rework"
    dedupe = f["dedupe"]
    seed, step = f.get("seed", ""), f.get("step", "")
    branch = f["branch"] if is_rework else f"fix/qa-{dedupe[:12]}"
    wt = f"/work/wt-{dedupe[:12]}"
    t0 = time.time()
    verdict = {"task": dedupe, "model": MODEL, "kind": f.get("kind", "fix")}

    sh("git", "-C", LIB, "worktree", "prune", check=False)
    subprocess.run(["rm", "-rf", wt], check=False)
    if is_rework:
        sh("git", "-C", LIB, "fetch", "-q", "origin", f"{branch}:{branch}", timeout=300)
        sh("git", "-C", LIB, "worktree", "add", wt, branch)
    else:
        sh("git", "-C", LIB, "fetch", "-q", "origin", "main", timeout=300)
        out = sh("git", "-C", LIB, "worktree", "add", "-b", branch, wt, "origin/main", check=False)
        if out.returncode != 0:  # branch exists from a previous attempt -> resume it
            sh("git", "-C", LIB, "worktree", "add", wt, branch)

    porcelain = sh("git", "-C", wt, "status", "--porcelain").stdout.strip()
    prompt = ""
    if is_rework:
        logs = qw.ci_failed_logs(f.get("sha", ""))
        prompt = (
            "CI failed on this branch. Fix forward minimally, working-tree files only, no commits.\n"
            "NEVER revert prior commits on this branch just to green CI; "
            "if the failure looks unrelated to this branch, change nothing and say so.\n"
            "See git log for prior fix attempts on this branch.\n"
            f"Branch={branch} failing_sha={f.get('sha', '')}\nCI logs:\n{logs}"
        )
    elif not porcelain and _ahead(wt, branch) == 0:
        prompt = (
            "Fix the bug below in this repo (minimal diff, no refactoring, "
            "edit working-tree files only, no branches/commits).\n"
            "NEVER submit an empty or revert-only change.\n"
            f"QA failure: {f.get('detail', '')}\nseed={seed} step={step} op={f.get('op', '')}\n"
            "Do not run builds or test suites (too heavy here); keep the change obviously correct."
        )
    if prompt:
        auth = {"opencode": {"type": "api", "key": os.environ["ZEN_KEY"]}}
        env = dict(os.environ, OPENCODE_AUTH_CONTENT=json.dumps(auth))
        proc = subprocess.run(["opencode", "run", "--auto", "--model", MODEL, prompt],
                              cwd=wt, timeout=600, env=env,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            verdict.update(status="opencode_failed", latency_s=round(time.time() - t0, 1))
            print(json.dumps(verdict), flush=True)
            return False
        porcelain = sh("git", "-C", wt, "status", "--porcelain").stdout.strip()
        if not porcelain:
            pr_url = open_pr(branch)  # fix landed earlier and PR exists -> adopt
            if pr_url:
                verdict.update(status="pr_adopted", pr_url=pr_url,
                               latency_s=round(time.time() - t0, 1))
                print(json.dumps(verdict), flush=True)
                sh("git", "-C", LIB, "worktree", "remove", "--force", wt, check=False)
                return True
            verdict.update(status="no_change", latency_s=round(time.time() - t0, 1))
            print(json.dumps(verdict), flush=True)
            return False

    if porcelain:
        sh("git", "-C", wt, "add", "-A")
        if seed or step:
            msg = f"fix(qa): {f.get('detail', '')[:80]} (seed={seed} step={step})"
        else:
            msg = f"fix(qa): rework {branch} for CI ({f.get('sha', '')[:8]})"
        sh("git", "-C", wt, "commit", "-m", msg)
    sh("git", "-C", wt, *_git_auth_args(),
       "push", "--set-upstream", "origin", branch, timeout=300)

    net = sh("git", "-C", wt, "diff", "--stat", f"origin/main...{branch}",
             check=False).stdout.strip()
    if not net:  # fix cancelled out (e.g. revert) -> never ship green-but-empty
        pr_url = open_pr(branch)
        if pr_url:
            num = pr_url.rstrip("/").split("/")[-1]
            qw.gh("POST", f"/repos/{qw.GH_REPO}/issues/{num}/comments",
                  {"body": "Auto-closing: branch net-diff vs main is empty."})
            qw.gh("PATCH", f"/repos/{qw.GH_REPO}/pulls/{num}", {"state": "closed"})
        qw.file_issue(f"empty net-diff on {branch}, not shipped", "", "")
        verdict.update(status="empty_guarded", latency_s=round(time.time() - t0, 1))
        print(json.dumps(verdict), flush=True)
        sh("git", "-C", LIB, "worktree", "remove", "--force", wt, check=False)
        return True

    pr_url = open_pr(branch)
    if not pr_url:
        pr = qw.gh("POST", f"/repos/{qw.GH_REPO}/pulls", {
            "title": f"fix(qa): {f.get('detail', '')[:80]}",
            "head": branch, "base": "main",
            "body": f"Auto-fix from live QA.\n\n```\n{f.get('detail', '')}\n```\n\nseed={seed} step={step} model={MODEL}",
        })
        pr_url = pr["html_url"]
    verdict.update(status="pr", pr_url=pr_url, latency_s=round(time.time() - t0, 1))
    print(json.dumps(verdict), flush=True)  # run record -> Loki via vector
    sh("git", "-C", LIB, "worktree", "remove", "--force", wt, check=False)
    return True


def fail(task_id: str, f: dict) -> None:
    n = r.incr(f"q:att:{f['dedupe']}")
    r.expire(f"q:att:{f['dedupe']}", 86400)
    if n > MAX_ATTEMPTS:
        r.xadd("q:fix:dlq", f)
        try:
            qw.file_issue(f.get("detail", ""), f.get("seed", ""), f.get("step", ""))
        except Exception as e:
            print(json.dumps({"task": f.get("dedupe"), "status": "issue_failed",
                              "error": qw._redact(str(e))[:200]}), flush=True)
        r.xack("q:fix", GROUP, task_id)


def main() -> None:
    while True:
        try:
            claimed = r.xautoclaim("q:fix", GROUP, NAME, LEASE_MS, "0-0", count=5)
            batch = [(mid, fields) for mid, fields in claimed[1]]
            try:
                fresh = r.xreadgroup(GROUP, NAME, {"q:fix": ">"}, count=5, block=10000)
            except redis.TimeoutError:
                continue  # block interval elapsed, no new tasks
            for _, msgs in fresh or []:
                batch += msgs
            for mid, fields in batch:
                try:
                    ok = process(mid, fields)
                except Exception as e:  # reclaim later; never lose the task
                    print(json.dumps({"task": fields.get("dedupe"), "status": "error",
                                      "error": qw._redact(str(e))[:200]}), flush=True)
                    continue
                if ok:
                    r.delete(f"q:att:{fields['dedupe']}")
                    r.xack("q:fix", GROUP, mid)
                else:
                    fail(mid, fields)
        except redis.ConnectionError:
            time.sleep(5)


if __name__ == "__main__":
    main()
