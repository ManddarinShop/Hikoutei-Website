/**
 * Minimum-op units for QA scenario composition.
 *
 * Two lanes, matching the two ways a Sheet changes:
 *
 * - Server lane: EntityManager writes (create/update/delete/flush). Each op
 *   mutates the runtime AND the model mirror identically, then flushes. Pure
 *   functions of explicit arguments — randomness lives in the scheduler, so
 *   every call replays from its inputs.
 * - Human lane: thin typed wrappers over SheetsDirect cell primitives
 *   (read/write/append/delete). No oracle here — verification belongs to
 *   the composing scenario, which knows the expected outcome. Dormant until
 *   a QA sheet is configured (never the demo sheet).
 */

import { createTypedSheets } from "hikoutei";
import { QARecord, type ExpectedRow, type ModelMirror } from "./entity.ts";

type Runtime = Awaited<ReturnType<typeof createTypedSheets>>;
type Em = ReturnType<Runtime["em"]["fork"]>;

export interface NewRow extends ExpectedRow {
  readonly id: string;
}

// ---------------------------------------------------------------------------
// Server lane
// ---------------------------------------------------------------------------

/** Inserts rows; returns their ids for read-back checks. */
export async function createRow(
  runtime: Runtime,
  model: ModelMirror,
  rows: readonly NewRow[],
): Promise<string[]> {
  const em: Em = runtime.em.fork();
  const ids: string[] = [];
  for (const row of rows) {
    em.persist(em.create(QARecord, { ...row }));
    model.set(row.id, { name: row.name, amount: row.amount, processed: row.processed });
    ids.push(row.id);
  }
  await em.flush();
  return ids;
}

/** Replaces one row's fields wholesale. */
export async function updateRow(
  runtime: Runtime,
  model: ModelMirror,
  id: string,
  patch: ExpectedRow,
): Promise<void> {
  const em: Em = runtime.em.fork();
  const entity = await em.findOne(QARecord, { id });
  if (entity === null) throw new Error(`update target missing: ${id}`);
  entity.name = patch.name;
  entity.amount = patch.amount;
  entity.processed = patch.processed;
  await em.flush();
  model.set(id, patch);
}

/** Removes one row. */
export async function deleteRow(
  runtime: Runtime,
  model: ModelMirror,
  id: string,
): Promise<void> {
  const em: Em = runtime.em.fork();
  const entity = await em.findOne(QARecord, { id });
  if (entity === null) throw new Error(`delete target missing: ${id}`);
  em.remove(entity);
  await em.flush();
  model.delete(id);
}

/** Empty flush: exercises the no-op write path. */
export async function flushCycle(runtime: Runtime): Promise<void> {
  const em: Em = runtime.em.fork();
  await em.flush();
}

/** Runtime row count must equal the mirror size. */
export async function assertCount(
  runtime: Runtime,
  model: ModelMirror,
  step: number | string,
): Promise<void> {
  const em: Em = runtime.em.fork();
  const total = await em.count(QARecord);
  if (total !== model.size) {
    throw new Error(`count drift at step ${step}: runtime=${total} model=${model.size}`);
  }
}

/** Listed rows must read back exactly as mirrored (ghosts included). */
export async function assertRows(
  runtime: Runtime,
  model: ModelMirror,
  ids: readonly string[],
  step: number | string,
): Promise<void> {
  const em: Em = runtime.em.fork();
  for (const id of ids) {
    const expected = model.get(id);
    const found = await em.findOne(QARecord, { id });
    if (expected === undefined) {
      if (found !== null) throw new Error(`ghost row ${id} at step ${step}`);
      continue;
    }
    if (found === null) throw new Error(`missing row ${id} at step ${step}`);
    if (found.name !== expected.name || found.amount !== expected.amount || found.processed !== expected.processed) {
      throw new Error(
        `value drift on ${id} at step ${step}: ` +
        `runtime=(${found.name},${found.amount},${found.processed}) ` +
        `model=(${expected.name},${expected.amount},${expected.processed})`,
      );
    }
  }
}
