/**
 * Hikoutei QA harness skeleton (walking skeleton, NOT the full fuzzer).
 *
 * A seeded random loop drives a local-only runtime through the PUBLIC
 * EntityManager API (create/update/delete/flush) and checks every step
 * against an in-memory model mirror: row counts must match and reads must
 * return the writes. Any mismatch is recorded (NOT thrown) with the seed
 * and step so the exact run replays with the same `QA_SEED`.
 *
 * Deliberately local-only: no sync env is passed, so this needs no
 * credentials, no Sheet, and no quota. Live-Sheets fuzzing, issue filing,
 * and the Track 1/2 scenario splits are later rounds. The database is
 * ephemeral on purpose: every (re)start is a clean slate, so a recorded
 * seed always replays identically.
 *
 * HTTP surface:
 *   GET /api/qa-health   { ok, seed, iterations, failures, lastFailure }
 */

import { createServer } from "node:http";
import { createTypedSheets } from "hikoutei";
import { QARecord, type ExpectedRow, type ModelMirror } from "./entity.ts";
import {
  assertCount,
  assertRows,
  createRow,
  deleteRow,
  flushCycle,
  updateRow,
  type NewRow,
} from "./minops.ts";

const QA_PORT = Number(process.env.QA_PORT ?? 3201);
const QA_DB_PATH = process.env.QA_DB_PATH ?? "./qa.sqlite";
const QA_TICK_MS = Number(process.env.QA_TICK_MS ?? 5_000);
/** Cap the mirror so one run cannot grow the database without bound. */
const MODEL_ROW_LIMIT = 2_000;
/** Recent failure reports kept for the health endpoint (bounded). */
const FAILURE_BUFFER_LIMIT = 20;

const seedEnv = process.env.QA_SEED;
const SEED = seedEnv === undefined || seedEnv.trim() === ""
  ? (Math.random() * 0x100000000) >>> 0
  : Number(seedEnv) >>> 0;
console.log(`[qa] seed: ${SEED}`);

/** Deterministic PRNG: Math.random is forbidden — every run must replay. */
function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(SEED);

/** The model mirror: every row the runtime must hold, by id. */
const model: ModelMirror = new Map<string, ExpectedRow>();

interface FailureReport {
  readonly seed: number;
  readonly step: number;
  readonly op: string;
  readonly detail: string;
}

const failures: FailureReport[] = [];
let iterations = 0;

function recordFailure(step: number, op: string, error: unknown): void {
  failures.push({
    seed: SEED,
    step,
    op,
    detail: error instanceof Error ? error.message : String(error),
  });
  if (failures.length > FAILURE_BUFFER_LIMIT) failures.shift();
  console.error(`[qa] step ${step} op ${op} failed (seed ${SEED}):`, error);
}

function pick<T>(items: readonly T[]): T {
  const item = items[Math.floor(rng() * items.length)];
  if (item === undefined) throw new Error("pick from empty set");
  return item;
}

function randomRow(): ExpectedRow {
  return {
    name: `n_${Math.floor(rng() * 10000)}`,
    amount: Math.round(rng() * 10000) / 100,
    processed: rng() < 0.5,
  };
}

let idCounter = 0;

// ---------------------------------------------------------------------------
// Runtime (local-only: no sync env, so no credentials or quota needed)
// ---------------------------------------------------------------------------

const hikoutei = await createTypedSheets({
  dbName: QA_DB_PATH,
  entities: [QARecord],
});
console.log("[qa] runtime ready (local-only)");

// ---------------------------------------------------------------------------
// Ops: each mutates runtime + model identically, then flushes
// ---------------------------------------------------------------------------

async function opCreate(count: number): Promise<string[]> {
  const rows: NewRow[] = [];
  for (let i = 0; i < count; i += 1) {
    const id = `qa_${SEED.toString(36)}_${idCounter++}`;
    rows.push({ id, ...randomRow() });
  }
  return createRow(hikoutei, model, rows);
}

async function opUpdate(id: string): Promise<void> {
  await updateRow(hikoutei, model, id, randomRow());
}

async function opDelete(id: string): Promise<void> {
  await deleteRow(hikoutei, model, id);
}

/** Empty flush plus count check: exercises the no-op write path. */
async function opFlushCycle(): Promise<void> {
  await flushCycle(hikoutei);
}

/**
 * Duplicate-PK insert must be REJECTED without touching state (mirrors the
 * human-insert-duplicate-id family at entity level). A missing rejection
 * is the failure; an unchanged state after rejection is the pass.
 */
async function opDuplicateInsert(id: string, stepNo: number): Promise<void> {
  const em = hikoutei.em.fork();
  em.persist(em.create(QARecord, { id, ...randomRow() }));
  let rejected = false;
  try {
    await em.flush();
  } catch {
    rejected = true;
  }
  if (!rejected) {
    throw new Error(`duplicate insert accepted for ${id} at step ${stepNo} (expected rejection)`);
  }
  await assertCount(hikoutei, model, stepNo);
  await assertRows(hikoutei, model, [id], stepNo);
}

/**
 * Same-value rewrite must leave state identical (mirrors the
 * no-op-human-edit hypothesis: no churn, no ghosts).
 */
async function opNoOpUpdate(id: string, stepNo: number): Promise<void> {
  const expected = model.get(id);
  if (expected === undefined) throw new Error(`no-op target missing: ${id}`);
  await updateRow(hikoutei, model, id, expected);
  await assertCount(hikoutei, model, stepNo);
  await assertRows(hikoutei, model, [id], stepNo);
}

/**
 * Delete then re-create the same id with new values (mirrors the
 * delete-recreate family): the old row must vanish, the new one must read
 * back exactly. Composed from minimum ops.
 */
async function opDeleteRecreate(id: string, stepNo: number): Promise<void> {
  await deleteRow(hikoutei, model, id);
  const em = hikoutei.em.fork();
  if (await em.findOne(QARecord, { id }) !== null) {
    throw new Error(`deleted row ${id} still visible at step ${stepNo}`);
  }
  const row = randomRow();
  await createRow(hikoutei, model, [{ id, ...row }]);
  await assertRows(hikoutei, model, [id], stepNo);
}

/** One scheduled step: random op, then the oracle. Never throws. */
let stepRunning = false;

async function step(): Promise<void> {
  if (stepRunning) return;
  stepRunning = true;
  const stepNo = iterations++;
  try {
    const ids = [...model.keys()];
    const roll = rng();
    if (ids.length === 0 || roll < 0.3) {
      // Cap the mirror: evict a random row before growing past the limit.
      if (model.size >= MODEL_ROW_LIMIT) await opDelete(pick(ids));
      const created = await opCreate(1 + Math.floor(rng() * 3));
      await assertRows(hikoutei, model, created, stepNo);
    } else if (roll < 0.5) {
      const id = pick(ids);
      await opUpdate(id);
      await assertRows(hikoutei, model, [id], stepNo);
    } else if (roll < 0.65) {
      await opDelete(pick(ids));
    } else if (roll < 0.75) {
      await opDuplicateInsert(pick(ids), stepNo);
    } else if (roll < 0.85) {
      await opNoOpUpdate(pick(ids), stepNo);
    } else if (roll < 0.93) {
      await opDeleteRecreate(pick(ids), stepNo);
    } else {
      await opFlushCycle();
    }
    await assertCount(hikoutei, model, stepNo);
  } catch (error) {
    recordFailure(stepNo, "step", error);
  } finally {
    stepRunning = false;
  }
}

// ---------------------------------------------------------------------------
// HTTP surface
// ---------------------------------------------------------------------------

const app = createServer((req, res) => {
  if (req.url === "/api/qa-health" && req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({
      ok: failures.length === 0,
      seed: SEED,
      iterations,
      failures: failures.length,
      lastFailure: failures.at(-1) ?? null,
    }));
    return;
  }
  res.writeHead(404);
  res.end();
});

app.listen(QA_PORT, () => {
  console.log(`[qa] listening on http://localhost:${QA_PORT} (tick ${QA_TICK_MS}ms)`);
});

const timer = setInterval(() => {
  void step();
}, QA_TICK_MS);
timer.unref();
