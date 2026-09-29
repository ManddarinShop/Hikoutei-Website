"""Tail qa-history.jsonl -> Redis Streams (q:fix) or GitHub issues.

- detail matching AUTO_PR_PREFIXES -> q:fix (dedupe by sha1, SET NX)
- everything else -> one auto-issue per signature (v1: no comment spam)
"""
import json
import os
import time

import redis

import qw

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
QA_FILE = os.environ.get("QA_FILE", "/qa/qa-history.jsonl")
POS_KEY = "q:watcher:pos"
PREFIXES = [p for p in os.environ.get("AUTO_PR_PREFIXES", "").split("\n") if p]

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)


def handle(rec: dict) -> None:
    detail = rec.get("detail", "")
    seed = str(rec.get("seed", ""))
    step = str(rec.get("step", ""))
    if any(detail.startswith(p) for p in PREFIXES):
        h = qw.sig(detail)
        if r.set(f"q:dedupe:{h}", "1", nx=True, ex=7 * 86400):
            r.xadd("q:fix", {"dedupe": h, "seed": seed, "step": step,
                             "op": str(rec.get("op", "")), "detail": detail,
                             "ts": str(rec.get("ts", ""))})
            print(f"enqueued {h}", flush=True)
    else:
        qw.file_issue(detail, seed, step)


def main() -> None:
    pos = int(r.get(POS_KEY) or 0)
    while True:
        try:
            size = os.path.getsize(QA_FILE)
            if size < pos:
                pos = 0  # rotated/truncated
            with open(QA_FILE) as f:
                f.seek(pos)
                for line in f:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("type") == "failure":
                        handle(rec)
                pos = f.tell()
            r.set(POS_KEY, pos)
        except FileNotFoundError:
            pass
        time.sleep(10)


if __name__ == "__main__":
    main()
