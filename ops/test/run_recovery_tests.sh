#!/bin/sh
# Run stdlib unittests against a throwaway, loopback-only Redis 7 container.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
python=${PYTHON:-python3}
name="hikoutei-v2-test-redis-$($python -c 'import uuid; print(uuid.uuid4().hex)')"
created=0

cleanup() {
  if [ "$created" -eq 1 ]; then
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT HUP INT TERM

docker run --rm --detach --name "$name" \
  --publish 127.0.0.1::6379 \
  redis:7-alpine redis-server --save '' --appendonly no >/dev/null
created=1
mapping=$(docker port "$name" 6379/tcp)
port=${mapping##*:}
case "$port" in
  ''|*[!0-9]*) echo "could not resolve ephemeral Redis port" >&2; exit 1 ;;
esac
export HIKOUTEI_OPS_TEST_REDIS_URL="redis://127.0.0.1:$port/15"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$repo_root:$repo_root/ops/worker${PYTHONPATH:+:$PYTHONPATH}"
cd "$repo_root"

run_id=$("$python" - "$HIKOUTEI_OPS_TEST_REDIS_URL" <<'PY'
import sys
import time
import redis

client = redis.Redis.from_url(sys.argv[1], decode_responses=True, socket_timeout=1)
for _ in range(100):
    try:
        if client.ping():
            info = client.info("server")
            if str(info.get("redis_version", "")).startswith("7."):
                run_id = info.get("run_id")
                if not isinstance(run_id, str) or len(run_id) != 40 or any(ch not in "0123456789abcdef" for ch in run_id):
                    raise SystemExit("ephemeral Redis 7 did not report a valid server run_id")
                break
    except redis.RedisError:
        time.sleep(0.1)
else:
    raise SystemExit("ephemeral Redis 7 did not become ready")
client.close()
print(run_id)
PY
)
export HIKOUTEI_OPS_TEST_DISPOSABLE=1
export HIKOUTEI_OPS_TEST_REDIS_RUN_ID="$run_id"

if [ "$#" -gt 0 ]; then
  "$python" -m unittest "$@"
else
  "$python" -m unittest discover -s ops/test -p 'test_*.py'
fi
