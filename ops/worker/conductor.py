"""Central AI orchestrator: watches infra health + Q, fixes infra incidents.

Loop (60s): demo/qa health endpoints, disk, container restarts, Q lag.
Breach -> deduped task on q:infra -> opencode diagnoses within the
service allowlist (inspect/logs/restart only) -> verify -> run record.
Needs-human verdicts become GitHub issues. Nothing else mutates infra.
"""
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.request

import redis

import qw

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
NAME = f"{socket.gethostname()}-{os.getpid()}"
MODEL = os.environ.get("MODEL", "opencode/muse-spark-1.3-contributor-free")
INTERVAL = int(os.environ.get("CONDUCTOR_INTERVAL", "60"))
DISK_LIMIT = int(os.environ.get("DISK_LIMIT", "85"))
ALLOW = [s.strip() for s in os.environ.get("INFRA_ALLOW", "").split(",") if s.strip()]
AUTO = os.environ.get("INFRA_AUTO_RESTART", "1") == "1"
DEMO_HEALTH = os.environ.get("DEMO_HEALTH", "http://demo-server:3101/api/health")
QA_HEALTH = os.environ.get("QA_HEALTH", "http://qa:3201/api/qa-health")

r = redis.Redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=30)
try:
    r.xgroup_create("q:infra", "conductors", mkstream=True)
except redis.ResponseError as e:
    if "BUSYGROUP" not in str(e):
        raise


def get_json(url: str, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.load(resp)


def docker_ps() -> list[dict]:
    out = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}} {{.Status}}"],
                         capture_output=True, text=True, timeout=30)
    rows = []
    for line in out.stdout.splitlines():
        name, _, status = line.partition(" ")
        rows.append({"name": name, "status": status})
    return rows


def allowed(name: str) -> bool:
    return any(name == a or (a.endswith("*") and name.startswith(a[:-1])) for a in ALLOW)


def check() -> list[dict]:
    """Return [{kind, key, detail, ...}] incidents."""
    found = []
    for label, url in (("demo", DEMO_HEALTH), ("qa", QA_HEALTH)):
        try:
            body = get_json(url)
            if not body.get("ok", False):
                found.append({"kind": f"{label}_down", "key": label,
                              "detail": f"{url} ok=false: {json.dumps(body)[:300]}"})
        except Exception as e:
            found.append({"kind": f"{label}_down", "key": label,
                          "detail": f"{url} unreachable: {qw._redact(str(e))[:200]}"})
    if shutil.disk_usage("/").used * 100 // shutil.disk_usage("/").total >= DISK_LIMIT:
        found.append({"kind": "disk", "key": "root", "detail": f"disk usage over {DISK_LIMIT}%"})
    for c in docker_ps():
        if ("Restarting" in c["status"] or "Exited" in c["status"]) and allowed(c["name"]):
            found.append({"kind": "container", "key": c["name"],
                          "detail": f"{c['name']} {c['status']}"})
    try:
        pending = r.xpending("q:fix", "workers") or {}
        if (pending.get("min_idle_time") or 0) > 30 * 60 * 1000:
            found.append({"kind": "q_stuck", "key": "qfix", "detail": "q:fix task idle over 30m"})
    except redis.ResponseError:
        pass
    try:  # library CI on our fix branches (needs PAT Checks:read)
        prs = qw.gh("GET", f"/repos/{qw.GH_REPO}/pulls?state=open&per_page=50")
        for pr in prs:
            head = (pr.get("head") or {}).get("ref", "")
            sha = (pr.get("head") or {}).get("sha", "")
            if not head.startswith("fix/qa-") or not sha:
                continue
            runs = qw.gh("GET", f"/repos/{qw.GH_REPO}/commits/{sha}/check-runs?per_page=20")
            crs = runs.get("check_runs", [])
            if not crs:
                continue
            if all(c.get("conclusion") in ("success", "skipped", "neutral") for c in crs):
                continue
            if any(c.get("conclusion") == "failure" for c in crs):
                found.append({"kind": "ci_fail", "key": f"{head}@{sha[:8]}",
                              "detail": f"CI failed on {head}@{sha[:8]}",
                              "branch": head, "sha": sha})
    except Exception:
        pass
    return found


def raise_incidents(found: list[dict]) -> None:
    for inc in found:
        dk = f"q:infra:dedupe:{inc['kind']}:{inc['key']}"
        if r.set(dk, "1", nx=True, ex=3600):
            r.xadd("q:infra", {"kind": inc["kind"], "key": inc["key"],
                               "detail": inc["detail"],
                               "branch": inc.get("branch", ""), "sha": inc.get("sha", ""),
                               "ts": str(int(time.time()))})
            print(json.dumps({"incident": inc["kind"], "key": inc["key"]}), flush=True)


PROMPT = (
    "You are the infra conductor for one incident. Diagnose within the allowlist only.\n"
    f"Allowed services: {', '.join(ALLOW) or '(none)'} / allowed actions: docker inspect, docker logs, docker restart.\n"
    "FORBIDDEN: rm/prune, volume/network changes, secrets, code edits, anything off-allowlist.\n"
    "If the fix needs a forbidden action, change NOTHING and explain what a human should do.\n"
    "Incident kind={kind} key={key}: {detail}\n"
    "Health to re-verify: demo={demo} qa={qa}"
)


def process(msg_id: str, f: dict) -> bool:
    t0 = time.time()
    verdict = {"infra_task": f.get("kind"), "key": f.get("key"), "model": MODEL}
    if f.get("kind") == "ci_fail":  # hand to fix workers with CI context
        dd = f"ci-{f.get('sha', '')[:12]}"
        if r.set(f"q:dedupe:{dd}", "1", nx=True, ex=7 * 86400):
            r.xadd("q:fix", {"kind": "rework", "dedupe": dd,
                             "branch": f.get("branch", ""), "sha": f.get("sha", ""),
                             "detail": f.get("detail", "")})
        verdict.update(status="handed_off")
        print(json.dumps(verdict), flush=True)
        return True
    if not AUTO:
        qw.file_issue(f"infra: {f.get('kind')} {f.get('key')}: {f.get('detail', '')}", "", "")
        verdict.update(status="issue_only")
        print(json.dumps(verdict), flush=True)
        return True
    auth = {"opencode": {"type": "api", "key": os.environ["ZEN_KEY"]}}
    env = dict(os.environ, OPENCODE_AUTH_CONTENT=json.dumps(auth))
    prompt = PROMPT.format(kind=f.get("kind"), key=f.get("key"),
                           detail=f.get("detail", "")[:500],
                           demo=DEMO_HEALTH, qa=QA_HEALTH)
    proc = subprocess.run(["opencode", "run", "--auto", "--model", MODEL, prompt],
                          timeout=600, env=env, capture_output=True, text=True)
    ok = proc.returncode == 0
    # verify: re-run checks for the same kind
    still = [i for i in check() if i["kind"] == f.get("kind")]
    verdict.update(status="recovered" if ok and not still else "still_down",
                   latency_s=round(time.time() - t0, 1))
    print(json.dumps(verdict), flush=True)
    if verdict["status"] == "still_down":
        try:
            qw.file_issue(f"infra: {f.get('kind')} {f.get('key')} still down. {f.get('detail', '')[:200]}", "", "")
        except Exception as e:
            print(json.dumps({"infra_task": f.get("kind"), "status": "issue_failed",
                              "error": qw._redact(str(e))[:200]}), flush=True)
    return True


def main() -> None:
    print(f"conductor up, allow={ALLOW} auto={AUTO}", flush=True)
    try:  # reclaim tasks orphaned by a previous instance
        old = r.xautoclaim("q:infra", "conductors", NAME, 300000, "0-0", count=10)
        for mid, fields in old[1]:
            try:
                if process(mid, fields):
                    r.xack("q:infra", "conductors", mid)
            except Exception as e:
                print(json.dumps({"infra_task": fields.get("kind"), "status": "error",
                                  "error": qw._redact(str(e))[:200]}), flush=True)
    except redis.ResponseError:
        pass
    while True:
        try:
            raise_incidents(check())
            try:
                fresh = r.xreadgroup("conductors", NAME, {"q:infra": ">"}, count=1, block=10000)
            except redis.TimeoutError:
                fresh = None
            for _, msgs in fresh or []:
                for mid, fields in msgs:
                    try:
                        if process(mid, fields):
                            r.xack("q:infra", "conductors", mid)
                    except Exception as e:
                        print(json.dumps({"infra_task": fields.get("kind"),
                                          "status": "error",
                                          "error": qw._redact(str(e))[:200]}), flush=True)
        except redis.ConnectionError:
            time.sleep(5)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
