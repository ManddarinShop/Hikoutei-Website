# Hikoutei QA harness (skeleton)

Seeded random scenario ops against a local-only runtime, running 24/7 on
the demo VM. This skeleton proves the loop (build → ship → run → health);
real scenario splits, live-Sheets targets, and issue filing are later rounds.

## Run locally

```sh
npm ci
npm run start            # QA_SEED printed on boot; same seed replays the run
```

## Environment

- `QA_SEED` — PRNG seed (default: random, always logged)
- `QA_TICK_MS` — ms between steps (default 5000; this is correctness
  fuzzing, not load testing)
- `QA_PORT` — health port (default 3201)
- `QA_DB_PATH` — SQLite path (default `./qa.sqlite`, ephemeral in deploy)

## Contract

- Public EntityManager API only; no sync env (no credentials, no quota).
- Every step is checked against an in-memory model (counts + values).
- Mismatches are recorded with `{seed, step, op}` (see `/api/qa-health`),
  replayable via `QA_SEED=<seed>`.

## Verdict persistence

The DB stays ephemeral (`QA_DB_PATH`, deploy: `/tmp/qa.sqlite`) so a
recorded seed always replays identically. Only verdicts persist, as
append-only JSONL at `QA_HISTORY_PATH` (deploy: `/data/qa-history.jsonl`
via the `../data/qa:/data` volume; locally the path is created on demand
and a missing/unwritable path degrades to in-memory health with one warning).

- `{"type":"boot",ts,seed,syncMode}` — one line per (re)start.
- `{"type":"failure",ts,seed,step,op,detail}` — one line per mismatch.
- `{"type":"summary",ts,seed,iterations,failures,uptimeS,opCounters}` —
  every 60s, so iteration/uptime/per-op counters survive restarts.

`GET /api/qa-health` returns `{ok, seed, syncMode, uptimeS, iterations,
  failures, lastFailure, opCounters}` — the pre-Phase-2 fields are unchanged.
`opCounters` maps each scheduled op
(`create|update|delete|duplicateInsert|noOpUpdate|deleteRecreate|flushCycle`)
to `{total, ok, fail}`.
