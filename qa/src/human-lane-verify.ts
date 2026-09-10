/**
 * Human-lane nightly verifier (QA sheet only, bounded).
 *
 * Activates the dormant human lane (`sheets.ts` SheetsDirect): it writes a
 * single dedicated canary row through the raw Sheets API — exactly like a
 * person typing — then proves the sync runtime ingests it into SQLite
 * through the public EntityManager.
 *
 * Cleanup is guaranteed by a single try/finally around the whole run: the
 * finally removes the canary from BOTH the sheet (located by id-column
 * scan, then `deleteRows`) and SQLite (EntityManager remove), closes the
 * runtime, and unlinks the key file — on success AND on failure. A
 * leftover canary would collide with the next run's dedicated id, so a
 * cleanup failure fails the verdict (loud, never silent residue).
 *
 * Runs ONLY against `QA_SYNC_SPREADSHEET_URL` (a QA-only sheet — never the
 * demo sheet); both env vars are fail-closed when empty. All Sheets API
 * calls are counted and HTTP 429 rejections are counted separately, so
 * quota/pacing pressure shows up in the output JSON. Prints progress to
 * stderr and exactly one JSON verdict to stdout; exits nonzero unless the
 * verdict is `passed`.
 *
 * Out of scope on purpose: the writeCell-into-conflict boundary needs
 * conflict-resolution choreography (human write raced with a server
 * write, then verdict on the recorded conflict). That step is reported as
 * `skipped` until this nightly is green — see the step below.
 */

import { unlinkSync, writeFileSync } from "node:fs";
import { createTypedSheets } from "hikoutei";
import { QARecord } from "./entity.ts";
import { columnToLetter, createSheetsDirect, type SheetsDirect } from "./sheets.ts";

/** Total wall-clock budget (the workflow wraps this with `timeout 15m`). */
const BUDGET_MS = Number(process.env.QA_VERIFY_BUDGET_MS ?? 720_000);
/** How long the Sheet→SQLite ingestion poll may take. */
const INGEST_TIMEOUT_MS = 300_000;
/** Interval between ingestion polls. */
const INGEST_POLL_MS = 5_000;
/** Upper sheet row bound for the canary id-column scan during cleanup. */
const SHEET_SCAN_MAX_ROWS = 5_000;
/** Ephemeral key file (same auth shape as the demo server). */
const SA_KEY_FILE = "/tmp/qa-verify-sa.json";
/** Canary fields in header order (discovered, not assumed). */
const CANARY_FIELDS = ["id", "name", "amount", "processed"] as const;

type StepStatus = "ok" | "failed" | "skipped";

interface StepResult {
  readonly name: string;
  readonly status: StepStatus;
  readonly detail?: string;
}

interface Verdict {
  readonly status: "passed" | "failed" | "misconfigured";
  readonly runId: string;
  readonly tab: string | null;
  readonly elapsedMs: number;
  readonly apiCalls: number;
  readonly throttled429: number;
  readonly steps: readonly StepResult[];
}

const startedAt = Date.now();
const deadlineAt = startedAt + BUDGET_MS;
const steps: StepResult[] = [];
let apiCalls = 0;
let throttled429 = 0;

function recordStep(name: string, status: StepStatus, detail?: string): void {
  steps.push(detail === undefined ? { name, status } : { name, status, detail });
  console.error(`[human-lane] ${name}: ${status}${detail === undefined ? "" : ` (${detail})`}`);
}

function expired(): boolean {
  return Date.now() >= deadlineAt;
}

/** Error class name only — values and messages never leave this module. */
function errorClass(error: unknown): string {
  return error instanceof Error && error.constructor.name !== ""
    ? error.constructor.name
    : "unknown";
}

/** True when a Sheets client error is an HTTP 429 (quota/pacing). */
function isThrottle(error: unknown): boolean {
  const text = error instanceof Error ? error.message : String(error);
  return /\b429\b/.test(text);
}

/** Counts one Sheets API call; rethrows after counting a 429 separately. */
async function counted<T>(fn: () => Promise<T>): Promise<T> {
  apiCalls += 1;
  try {
    return await fn();
  } catch (error) {
    if (isThrottle(error)) throttled429 += 1;
    throw error;
  }
}

function emit(status: Verdict["status"], runId: string, tab: string | null): never {
  const verdict: Verdict = {
    status,
    runId,
    tab,
    elapsedMs: Date.now() - startedAt,
    apiCalls,
    throttled429,
    steps,
  };
  process.stdout.write(`${JSON.stringify(verdict)}\n`);
  process.exit(status === "passed" ? 0 : 1);
}

/** Control-flow abort: the failure was already recorded, unwind to finally. */
class VerifyAbort extends Error {}

/** Records nothing — call recordStep first, then unwind to the cleanup. */
function abort(): never {
  throw new VerifyAbort();
}

// ---------------------------------------------------------------------------
// Preconditions (fail closed — never touch the demo sheet by accident)
// ---------------------------------------------------------------------------

const spreadsheetUrl = (process.env.QA_SYNC_SPREADSHEET_URL ?? "").trim();
const saJson = process.env.QA_SA_JSON ?? "";
if (spreadsheetUrl === "" || saJson === "") {
  const missing = [
    ...(spreadsheetUrl === "" ? ["QA_SYNC_SPREADSHEET_URL"] : []),
    ...(saJson === "" ? ["QA_SA_JSON"] : []),
  ];
  recordStep("preconditions", "failed", `missing ${missing.join(" and ")}`);
  emit("misconfigured", "none", null);
}
const runId = (process.env.QA_VERIFY_RUN_ID ?? `manual-${Date.now()}`).replace(/[^A-Za-z0-9_-]/g, "-");
const canaryId = `qa-nightly-${runId}`;

// ---------------------------------------------------------------------------
// Shared run state (written by the phases, consumed by the guaranteed
// cleanup below — every field stays undefined/empty until its phase lands)
// ---------------------------------------------------------------------------

let client: SheetsDirect | undefined;
let tab = "";
let headers: string[] = [];
let appended = false;
let runtime: Awaited<ReturnType<typeof createTypedSheets>> | undefined;

/**
 * Guaranteed canary cleanup: removes the dedicated row from SQLite (the
 * canonical path, whose projected sheet delete also lands) AND from the
 * sheet directly (located by an id-column scan — covers a canary the
 * projection never picked up), then closes the runtime and unlinks the
 * key file. Independent guarded steps: one failure never prevents the
 * others, and any cleanup failure fails the verdict — residue is loud.
 * Never throws.
 */
async function cleanupCanary(): Promise<void> {
  let ok = true;
  let detail: string | undefined;
  const fail = (reason: string): void => {
    ok = false;
    detail ??= reason;
  };
  // SQLite first (canonical): a later sheet scan then only removes what
  // the projection did not already delete.
  if (runtime !== undefined) {
    try {
      const em = runtime.em.fork();
      const entity = await em.findOne(QARecord, { id: canaryId });
      if (entity !== null) {
        em.remove(entity);
        await em.flush();
      }
    } catch {
      fail("cleanup-delete-failed");
    }
  }
  // Sheet row by id-column scan (only when the append landed and the
  // header layout is known — otherwise there is nothing locatable).
  if (appended && client !== undefined && tab !== "" && headers.includes("id")) {
    // Narrowed once: closures below must not re-read the mutable binding.
    const direct: SheetsDirect = client;
    try {
      const column = columnToLetter(headers.indexOf("id") + 1);
      const grid = await counted(() =>
        direct.readRange(tab, `${column}1:${column}${SHEET_SCAN_MAX_ROWS}`));
      let rowNumber = -1;
      for (let index = 1; index < grid.length; index += 1) {
        if (String(grid[index]?.[0] ?? "") === canaryId) {
          rowNumber = index + 1;
          break;
        }
      }
      if (rowNumber > 0) {
        await counted(() => direct.deleteRows(tab, rowNumber, rowNumber + 1));
      }
    } catch {
      fail("cleanup-delete-failed");
    }
  }
  if (runtime !== undefined) {
    try {
      await runtime.close();
    } catch {
      fail("cleanup-close-failed");
    }
  }
  try {
    unlinkSync(SA_KEY_FILE);
  } catch {
    // Ephemeral container path; a missing file is the common case.
  }
  recordStep("cleanup", ok ? "ok" : "failed", detail);
}

// ---------------------------------------------------------------------------
// Phases (every failure records its step, then unwinds to the cleanup)
// ---------------------------------------------------------------------------

try {
  try {
    client = await createSheetsDirect({ saJson, spreadsheetUrl });
    recordStep("auth", "ok");

    // Discover the QA entity's human-input tab (never assume the title).
    const tabs = await counted(() => (client as SheetsDirect).listTabs());
    tab = tabs.includes("QARecord_Input")
      ? "QARecord_Input"
      : (tabs.find((title) => title.endsWith("_Input")) ?? "");
    if (tab === "") {
      recordStep("discover-tab", "failed", "sheet-not-provisioned");
      abort();
    }
    recordStep("discover-tab", "ok", tab);
    if (expired()) {
      recordStep("read-headers", "failed", "deadline-exceeded");
      abort();
    }

    // Read the header row so the canary follows the sheet's column order.
    const headerGrid = await counted(() => (client as SheetsDirect).readRange(tab, "1:1"));
    headers = (headerGrid[0] ?? []).map((cell) => String(cell ?? ""));
    const missingFields = CANARY_FIELDS.filter((field) => !headers.includes(field));
    if (missingFields.length > 0) {
      recordStep("read-headers", "failed", `missing-columns:${missingFields.join(",")}`);
      abort();
    }
    recordStep("read-headers", "ok", `${headers.length} columns`);
    if (expired()) {
      recordStep("append-canary", "failed", "deadline-exceeded");
      abort();
    }

    // Human-typing append of the dedicated canary row (USER_ENTERED inside).
    const canary: Record<string, unknown> = {
      id: canaryId,
      name: `nightly ${runId}`,
      amount: 1.5,
      processed: false,
    };
    try {
      await counted(() =>
        (client as SheetsDirect).appendRow(tab, headers.map((header) => canary[header] ?? "")));
    } catch (error) {
      recordStep("append-canary", "failed", isThrottle(error) ? "sheets-throttled" : "append-rejected");
      abort();
    }
    appended = true;
    recordStep("append-canary", "ok", `${headers.length} cells`);
  } catch (error) {
    if (error instanceof VerifyAbort) throw error;
    // Auth/discovery/read/append throws land here. Only the error class
    // is recorded — never the message (it may carry sheet content).
    recordStep("human-write", "failed", errorClass(error));
    abort();
  }

  try {
    writeFileSync(SA_KEY_FILE, saJson, { mode: 0o600 });
    process.env.HIKOUTEI_SYNC_SPREADSHEET_URL = spreadsheetUrl;
    process.env.GOOGLE_APPLICATION_CREDENTIALS = SA_KEY_FILE;
    runtime = await createTypedSheets({ dbName: "/tmp/human-lane-verify.sqlite", entities: [QARecord] });
    recordStep("sync-boot", "ok");

    const ingestDeadline = Math.min(Date.now() + INGEST_TIMEOUT_MS, deadlineAt);
    let ingested = false;
    while (!ingested && Date.now() < ingestDeadline) {
      const em = (runtime as NonNullable<typeof runtime>).em.fork();
      ingested = (await em.findOne(QARecord, { id: canaryId })) !== null;
      if (!ingested) await new Promise((resolve) => setTimeout(resolve, INGEST_POLL_MS));
    }
    if (!ingested) {
      recordStep("ingest-poll", "failed", expired() ? "deadline-exceeded" : "ingest-timeout");
      abort();
    }
    const found = await (runtime as NonNullable<typeof runtime>).em.fork()
      .findOne(QARecord, { id: canaryId });
    if (found === null || found.name !== `nightly ${runId}`) {
      recordStep("ingest-poll", "failed", found === null ? "row-missing" : "value-drift");
      abort();
    }
    recordStep("ingest-poll", "ok");
  } catch (error) {
    if (error instanceof VerifyAbort) throw error;
    recordStep("ingest-poll", "failed", errorClass(error));
    abort();
  }

  // Deferred boundary (deliberate skip with a ceiling): writeCell-into-
  // conflict needs human-write/server-write race choreography plus a
  // verdict on the recorded conflict. Skipped until this nightly is
  // green; add when the append/ingest path proves stable for a week.
  recordStep("write-cell-conflict", "skipped", "write-cell-conflict-skipped");
} catch (error) {
  if (!(error instanceof VerifyAbort)) {
    // Defensive: only VerifyAbort should escape the phases (a bug would
    // surface here instead of silently passing).
    recordStep("verify", "failed", errorClass(error));
  }
} finally {
  await cleanupCanary();
}

if (steps.every((step) => step.status !== "failed")) {
  emit("passed", runId, tab === "" ? null : tab);
} else {
  emit("failed", runId, tab === "" ? null : tab);
}
