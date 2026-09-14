#!/usr/bin/env bash
# LLM failure triage (shared by drift-watch and health-ping).
#
# Reads a failure-evidence file, asks the triage LLM for a severity +
# RCA hypothesis + remediation, and renders an "AI triage" markdown
# section. The LLM only ever ADDS context: it cannot suppress paging,
# and every failure below is a silent no-op that leaves existing flows
# byte-for-byte identical.
#
# Silent no-ops (exit 0, no output file):
#   - TRIAGE_LLM_API_KEY is unset      (key gets added after this lands)
#   - evidence file missing/empty
#   - LLM call times out / errors / returns unparsable JSON
#
# Usage:
#   llm-triage.sh --mode drift|qa --evidence FILE --out FILE
#                 [--metrics FILE] [--open-issues FILE]
#
# Env:
#   TRIAGE_LLM_API_KEY    Bearer key for the Responses API (required).
#   TRIAGE_LLM_MODEL      Model id (default: muse-spark-1.3-contributor).
#   TRIAGE_LLM_ENDPOINT   Responses endpoint
#                         (default: https://opencode.ai/zen/v1/responses).
#   TRIAGE_FIXTURE_RESPONSE  Path to a canned API response (dry-run/tests).
#
# Evidence sources (ssh output, log tails, metrics CSV, issue titles) must
# stay secret-free: no sa.json, no .env values. A defensive redaction for
# common secret patterns runs before the prompt is built.
set -euo pipefail

MODE=""; EVIDENCE=""; OUT=""; METRICS=""; OPEN_ISSUES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --evidence) EVIDENCE="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --metrics) METRICS="$2"; shift 2;;
    --open-issues) OPEN_ISSUES="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ "$MODE" = "drift" ] || [ "$MODE" = "qa" ] || { echo "need --mode drift|qa" >&2; exit 2; }
[ -n "$EVIDENCE" ] && [ -n "$OUT" ] || { echo "need --evidence and --out" >&2; exit 2; }

# Skip path: no key, no evidence — existing flows continue untouched.
[ -n "${TRIAGE_LLM_API_KEY:-}" ] || exit 0
[ -s "$EVIDENCE" ] || exit 0

MODEL="${TRIAGE_LLM_MODEL:-muse-spark-1.3-contributor}"
ENDPOINT="${TRIAGE_LLM_ENDPOINT:-https://opencode.ai/zen/v1/responses}"

python3 - "$MODE" "$EVIDENCE" "$OUT" "$METRICS" "$OPEN_ISSUES" "$MODEL" <<'EOF'
import json, os, re, subprocess, sys, urllib.request

mode, evidence_path, out_path, metrics_path, issues_path, model = sys.argv[1:7]
endpoint = os.environ.get(
    "TRIAGE_LLM_ENDPOINT", "https://opencode.ai/zen/v1/responses")
dry_run = os.environ.get("TRIAGE_FIXTURE_RESPONSE", "") != ""

def read_capped(path, limit=12000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError:
        return ""
    return data if len(data) <= limit else data[-limit:]

def redact(text):
    # Defensive: evidence should already be secret-free; belt and braces.
    return re.sub(
        r"(?i)(api[_-]?key|secret|token|password|bearer)\s*[:=]\s*\S+",
        r"\1=[REDACTED]", text)

evidence = redact(read_capped(evidence_path))
metrics = redact(read_capped(metrics_path)) if metrics_path else ""
open_issues = redact(read_capped(issues_path)) if issues_path else ""
if not evidence.strip():
    sys.exit(0)

if mode == "drift":
    scope = ("The host-shape check failed (lines starting with DRIFT:). "
             "P1 = public edge not sync, missing caddy/demo-server container, "
             "k3s active, :443 not via docker-proxy, k8s listener. "
             "P2 = qa wiring unreachable only.")
else:
    scope = ("The QA oracle failed (ok:false or failures>0 in qa-health). "
             "Always P2 unless the payload shows the public demo edge itself "
             "is down, which is P1.")

system = ("You triage infra failures for a demo VM (Caddy + demo-server + "
          "qa containers, deployed by GitHub Actions). Reply with STRICT JSON "
          "only, no prose, no fences: "
          '{"severity":"P1|P2","rca_hypothesis":"...","suggested_remediation":["..."],'
          '"confidence":"low|med|high"}. ' + scope)

user_block = ("MODE: " + mode + "\n\nEVIDENCE:\n" + evidence +
              "\n\nRECENT METRICS (csv tail):\n" + (metrics or "(none)") +
              "\n\nOPEN ISSUES:\n" + (open_issues or "(none)"))

def call_llm():
    # Returns (api_payload, http_status|None). OpenAI Responses shape:
    # POST {endpoint} {model, instructions, input, max_output_tokens}.
    fixture = os.environ.get("TRIAGE_FIXTURE_RESPONSE", "")
    if fixture:
        with open(fixture, encoding="utf-8") as f:
            return json.load(f), None
    req_body = json.dumps({
        "model": model, "instructions": system, "input": user_block,
        "max_output_tokens": 1024,
    }).encode()
    req = urllib.request.Request(
        endpoint, data=req_body, method="POST",
        headers={"content-type": "application/json",
                 "authorization": "Bearer " + os.environ["TRIAGE_LLM_API_KEY"]})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp), resp.status
    except urllib.error.HTTPError as e:
        return None, e.code

def extract_text(api):
    parts = []
    for item in api.get("output", []) or []:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for block in item.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "output_text":
                parts.append(block.get("text", ""))
    if parts:
        return "".join(parts)
    t = api.get("output_text", "")
    return t if isinstance(t, str) else ""

try:
    api, status = call_llm()
    if dry_run:
        print(f"triage llm http status: {status}", flush=True)
    if api is None:
        raise ValueError(f"llm http {status}")
    text = extract_text(api).strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```$", "", text)
    triage = json.loads(text)
    assert triage.get("severity") in ("P1", "P2")
    assert triage.get("confidence") in ("low", "med", "high")
    assert isinstance(triage.get("rca_hypothesis"), str) and triage["rca_hypothesis"].strip()
    assert isinstance(triage.get("suggested_remediation"), list)
except Exception:
    sys.exit(0)  # unparsable/timeout/error: no triage section, flow continues

steps = "\n".join(f"  {i + 1}. {s}" for i, s in
                  enumerate(triage["suggested_remediation"][:5]) if str(s).strip())
md = ("## AI triage (provisional \u2014 verify before acting)\n\n"
      f"- Severity: **{triage['severity']}** (model confidence: {triage['confidence']}, "
      f"model `{model}`)\n"
      f"- Hypothesis: {triage['rca_hypothesis'].strip()}\n"
      + ("- Suggested remediation:\n" + steps + "\n" if steps else ""))
with open(out_path, "w", encoding="utf-8") as f:
    f.write(md)
EOF
