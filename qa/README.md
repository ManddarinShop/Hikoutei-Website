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
