/**
 * Redacted finale/close helpers: the final summary builder and the
 * final-retry runtime close. Depends only on errors/redact/performance
 * plus the scenario record sanitizer (no scenario internals).
 */
import { performance } from "node:perf_hooks";
import { describeError } from "./errors.mjs";
import { sanitizeErrorClass, sanitizeReason, sanitizeStableCode } from "./redact.mjs";
import { sanitizeScenarioRecord } from "./scenarios/scenarioVocabulary.mjs";

/** Builds the redacted final summary object. */
function buildSummary({
  state,
  stopReason,
  startedClock,
  live,
  closeError,
  replacementCloseError,
  finalizationFailures = [],
  // Redacted per-scenario failure detail from collectScenarioFailures()
  // (already-sanitized cycle records only — never raw plans or values).
  // Always an array (possibly empty) so workflow parsing stays stable.
  scenarioFailures = [],
}) {
  const status =
    stopReason === "max-consecutive-failures" ||
    stopReason === "reopen-failed" ||
    stopReason === "simulated-interruption" ||
    replacementCloseError !== undefined ||
    finalizationFailures.length > 0 ||
    state.cumulative.failures > 0 ||
    (state.cumulative.scenarioFailures ?? 0) > 0
      ? "failed"
      : "passed";
  const described = closeError === undefined ? undefined : describeError(closeError);
  const replacementDescribed =
    replacementCloseError === undefined ? undefined : describeError(replacementCloseError);
  const finalizationDescribed =
    finalizationFailures.length === 0 ? undefined : describeError(finalizationFailures[0].error);
  return {
    scenario: "local-multitable-soak",
    scenarioVersion: 1,
    status,
    mode: live.mode,
    stopReason,
    seed: state.seed,
    startedAt: new Date(state.startedAtMs).toISOString(),
    finishedAt: new Date().toISOString(),
    elapsedMs: Math.round(performance.now() - startedClock),
    durationBudgetMs: state.params.durationMs,
    cyclesCompleted: state.lastCompletedCycle,
    operations: {
      total: state.cumulative.operations,
      ok: state.cumulative.operations - state.cumulative.expectedErrors - state.cumulative.failures,
      expectedErrors: state.cumulative.expectedErrors,
      failures: state.cumulative.failures,
      retries: state.cumulative.retries,
    },
    probes: state.cumulative.probes,
    convergence: {
      checks: state.cumulative.convergenceChecks,
      failed: state.cumulative.convergenceFailed,
    },
    // Dedicated scenario totals, separate from the standard operation
    // counters: a scenario failure fails the run without perturbing the
    // baseline workload totals.
    scenarios: {
      expectedErrors: state.cumulative.scenarioExpectedErrors ?? 0,
      failures: state.cumulative.scenarioFailures ?? 0,
    },
    tableRows: state.tableRows,
    // Dedicated failing-scenario detail: one entry per failed scenario
    // record (cycle/id/phase plus the allowlisted reason diagnostics),
    // so a scenario-only failure stays attributable from the summary
    // alone — the per-cycle JSONL is not always reachable (e.g. a
    // remote-only run directory). Never carries ids, values, or URLs.
    scenarioFailures,
    // Recovery section: a resume reconciled an interrupted run. The reason
    // is a fixed vocabulary value and the cycle a number — never an id,
    // path, or message. Present only when the state records a recovery.
    ...(state.recovery === undefined ? {} : {
      recovery: {
        status: "recovered",
        cycle: state.recovery.cycle,
        reason: sanitizeReason(state.recovery.reason),
      },
    }),
    // Stable cleanup-failure section: a runtime close failure after the
    // loop ended makes the run failed with a fixed reason and the
    // allowlisted class/code — never the raw message.
    ...(described === undefined ? {} : {
      cleanup: {
        status: "failed",
        reason: "runtime-close-failed",
        errorClass: sanitizeErrorClass(described.errorClass),
        ...(described.code === undefined ? {} : { code: sanitizeStableCode(described.code) }),
      },
    }),
    // A replacement runtime that could not be closed after a failed
    // reopen handoff: the run is already failed (reopen-failed) and the
    // close failure is recorded here with a stable redacted reason — an
    // unclosable opened replacement is never reported silently.
    ...(replacementDescribed === undefined ? {} : {
      replacementCleanup: {
        status: "failed",
        reason: "replacement-close-failed",
        errorClass: sanitizeErrorClass(replacementDescribed.errorClass),
        ...(replacementDescribed.code === undefined ? {} : { code: sanitizeStableCode(replacementDescribed.code) }),
      },
    }),
    // A final artifact write/collection failure: the run is failed with
    // the stable failing step label and redacted error — never a silent
    // passed summary when finalization did not fully land.
    ...(finalizationDescribed === undefined ? {} : {
      finalization: {
        status: "failed",
        reason: "artifact-write-failed",
        step: finalizationFailures[0].label,
        errorClass: sanitizeErrorClass(finalizationDescribed.errorClass),
        ...(finalizationDescribed.code === undefined ? {} : { code: sanitizeStableCode(finalizationDescribed.code) }),
      },
    }),
  };
}

/**
 * Collects the redacted failing-scenario entries for the final summary.
 *
 * Reads the in-memory recorded cycle records (`scenarios` arrays written
 * by cycleRecord) and returns one entry per scenario record with
 * `failures > 0` or `status === "failed"`, ordered by (cycle, order) and
 * bounded to `limit` entries. Every entry passes through
 * `sanitizeScenarioRecord`, so only fixed-vocabulary strings and
 * non-negative counters survive — a malformed or forged record can never
 * inject text into the summary (unknown values collapse to `unknown`).
 *
 * @param {Map<number, object> | Record<string, object>} cycleRecords
 *   recorded cycle records by cycle number.
 * @param {number} [limit] maximum entries (default 30).
 * @returns {Array<object>} redacted failing-scenario entries.
 */
function collectScenarioFailures(cycleRecords, limit = 30) {
  const entries = [];
  const records = cycleRecords instanceof Map
    ? [...cycleRecords.entries()]
    : Object.entries(cycleRecords ?? {}).map(([cycle, record]) => [Number(cycle), record]);
  records.sort((a, b) => a[0] - b[0]);
  for (const [cycle, record] of records) {
    if (!Number.isInteger(cycle)) continue;
    const scenarios = record !== null && typeof record === "object" && !Array.isArray(record)
      ? record.scenarios
      : undefined;
    if (!Array.isArray(scenarios)) continue;
    const sorted = [...scenarios].sort((a, b) => (a?.order ?? 0) - (b?.order ?? 0));
    for (const entry of sorted) {
      const clean = sanitizeScenarioRecord(entry);
      if (clean === undefined) continue;
      if (!((Number.isInteger(clean.failures) && clean.failures > 0) || clean.status === "failed")) continue;
      entries.push({
        cycle,
        id: clean.id,
        phase: clean.phase,
        order: clean.order,
        status: clean.status,
        failures: clean.failures,
        ...(clean.cleanupFailures > 0 ? { cleanupFailures: clean.cleanupFailures } : {}),
        ...(clean.expectedErrors > 0 ? { expectedErrors: clean.expectedErrors } : {}),
        ...(clean.reason !== undefined ? { reason: clean.reason } : {}),
        ...(clean.reasonTag !== undefined ? { reasonTag: clean.reasonTag } : {}),
        ...(clean.failureKinds !== undefined ? { failureKinds: [...clean.failureKinds] } : {}),
        ...(clean.targetTable !== undefined ? { targetTable: clean.targetTable } : {}),
      });
      if (entries.length >= limit) return entries;
    }
  }
  return entries;
}

/**
 * Closes one runtime with a final second attempt on failure.
 *
 * A runtime that fails to close is never silently discarded: the first
 * failure triggers one final close attempt. Because Hikoutei close() is
 * retryable (a failed close leaves the runtime open), the retry genuinely
 * re-runs the provider cleanup instead of no-oping — a real first-attempt
 * close failure can therefore recover, and only a persistent failure is
 * returned so the caller records a stable cleanup failure and forces the
 * summary to failed.
 *
 * Failure tracking uses a BOOLEAN flag, never `error !== undefined`: a
 * close that rejects with a non-Error value (a hook or provider that
 * throws `undefined`) is still a FAILED close and is reported as such —
 * it must never masquerade as a successful close. When the thrown value
 * is not an Error, a stable synthetic Error is returned so every caller
 * can branch on `error !== undefined` without losing the failure.
 *
 * Test injection (`__test*` options): with `failClose`, the FIRST attempt
 * fails before the real close runs (a simulated provider cleanup failure)
 * and the final retry genuinely invokes the runtime close, so a run can
 * recover. With `failClosePersistent`, the first attempt fails before the
 * real close AND the retry — which genuinely ran the provider cleanup —
 * still reports failure, so a persistent close failure keeps failing the
 * run. `failClose` mirrors `__testCloseFail`; `failClosePersistent` mirrors
 * `__testCloseFailPersistent` and `__testFailReplacementClose`.
 *
 * @param {{ close(): Promise<unknown> }} runtime
 * @param {{ failClose?: boolean, failClosePersistent?: boolean }} [options]
 * @returns {Promise<Error | undefined>} the close error when both
 *   attempts failed, or `undefined` when a close succeeded.
 */
export async function closeRuntimeWithFinalRetry(runtime, options = {}) {
  const persistent = options.failClosePersistent === true;
  let failed = false;
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      if (persistent) {
        // Persistent injection: the FIRST attempt fails before the real
        // close (simulating a provider cleanup failure). The retry below
        // genuinely runs the real close and then reports the injected
        // failure, so a persistent close failure still fails the run while
        // the provider cleanup really was re-invoked (never a masked pass,
        // never a leaked runtime).
        if (attempt === 0) {
          throw new Error("soak-test-injected-close-failure");
        }
      } else if (options.failClose === true && attempt === 0) {
        // First-attempt injection: fail before the real close, leaving the
        // runtime open so the final retry genuinely re-invokes the runtime
        // close (provider cleanup) and can recover.
        throw new Error("soak-test-injected-close-failure");
      }
      await runtime.close();
      if (persistent) {
        // The retry genuinely ran the provider cleanup (the real close
        // succeeded) but the injected failure persists: the run must still
        // report a stable cleanup failure, never a masked pass.
        throw new Error("soak-test-injected-close-failure");
      }
      return undefined;
    } catch (error) {
      failed = true;
      lastError = error;
    }
  }
  if (!failed) return undefined;
  // A thrown non-Error value (including `undefined`) is still a failure;
  // normalize it so callers can branch on a defined error.
  return lastError instanceof Error
    ? lastError
    : new Error("runtime close failed with a non-Error rejection");
}

// Cross-module helpers split out of the monolithic runner.
// Final redacted summary builder consumed by runner.mjs.
export {
  buildSummary,
  collectScenarioFailures,
};
