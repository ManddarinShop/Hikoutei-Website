---
title: Sync pipeline 3-layer contract
description: The worker→Sheets pipeline is three layers — durable kernel, planning host, wire adapter. Each boundary, its symbols, and its guardians.
---

# Sync pipeline: the 3-layer contract

One page, three layers. If you are new, this page is designed so you can
read **Layer 2 only** and work correctly without opening Layers 1 or 3.

The pipeline is one-directional. Nothing flows back up: effects are planned,
handed down, and executed; failures are classified, not retried upward.

```text
Layer 1 (kernel)  ikisaki — durable effect ledger, no Sheets knowledge
        ▼  SyncEffectWorkerProvider (contract)
Layer 2 (host)    sync-engine — planning, pacing, cadence, reconciliation
        ▼  CoordinatedSheetsProvider / provider contracts (contracts pkg)
Layer 3 (adapter) sheets — concrete Google Sheets writes
```

## Layer 1 — ikisaki kernel: "what already ran / what's next"

Owns the **durable ledger**: `sheet_effect_outbox` DDL, lease/fencing
semantics, and the worker error vocabulary.

| Boundary symbol | Home | Meaning |
|---|---|---|
| `WORKER_ERROR_CODES` | `ikisaki/src/worker/constants.ts` | The only error vocabulary the ledger persists |
| `DispatchTransportError` / `DispatchTransportOutcome` | `ikisaki/worker/errors.ts` | Redacted transport outcome crossing the ledger |
| effect lifecycle statuses | ikisaki `EFFECT_STATUSES` | `pending → applied / failed / superseded` … |

**Allowed to know:** commit/lease bookkeeping, retry deadlines.
**Forbidden forever:** anything Sheets-shaped — tab names, cell values,
HTTP statuses, retry pacing.

## Layer 2 — sync-engine host: "what to send, when, where"

The only layer a pipeline reader should need. Owns:

| Concern | Owner | Where |
|---|---|---|
| Effect dispatch + batch windows | `SheetsEffectDispatcher` | `sync/outbound/SheetsEffectDispatcher.ts` |
| Retry/lane pacing policy | `dispatcherSupport.ts` | `sync/outbound/` (extracted by #401) |
| Cadence: poll/reconcile intervals | `cadence.ts` | `sync/service/cadence.ts` |
| Supervisors (effects, polling) | `effectSupervisor.ts`, `pollingSupervisor.ts` | `sync/service/` |
| Drift repair + cleanup | `ReconciliationScanner`, `CleanupScanner` | `sync/outbound/reconciliation/` |
| Startup classification | `syncAutoStart.ts` | `sync/service/` |

**Allowed:** importing Layer 1 (kernel) and `@hikoutei/contracts`;
planning effect payloads; deciding WHEN to dispatch.
**Forbidden:** importing adapters (`@hikoutei/sheets`, `@hikoutei/composition`,
`@hikoutei/cli`) — enforced by dependency-cruiser rule
`engine-not-into-upper-trees` (CI-blocking; concrete wiring arrives via
`sync/service/compositionPorts.ts`).

## Layer 3 — adapters: "how it actually hits the wire"

`packages/library/cloud/sheets` (and friends) satisfy contract interfaces
only: `SyncSheetsProvider` / `SyncEffectWorkerProvider`
(`contracts/sheets/syncSheets.ts`), plus the coordinated mutation surface
(`contracts/sheets/mutationCoordinator/CoordinatedSheetsProvider.ts`).
They know Google's API; they never plan.

**Forbidden:** reaching back into Layer 1 or 2 internals; owning any policy.

## Boundary symbols (the shared vocabulary)

- `TransportOutcome` + `classifyTransportOutcome` (`ikisaki/transport/transportOutcome.ts`,
  re-exported through contracts' mutationCoordinator) — redacted
  success/explicit-failure/delivery-uncertain classification
- `SyncEffectWorkerProvider`, `SyncSheetsProvider` — the Layer 2↔3 port
- `SyncConflictProjection*` — the Sync_Conflicts audit projection contract
  (`contracts/sheets/model/conflictProjection.ts`)
- `SyncProviderTiming` + `SYNC_TIMING_OPERATION_KINDS` — timing vocabulary
  (canonical in contracts `sheets/timing.ts`; kernel re-exports)

## Guardians (each boundary claim above is checkable)

| Claim | Enforcer |
|---|---|
| Ledger DDL/error codes never leak Sheets shapes | `test/outbox-contract-drift.test.ts` |
| Kernel/contract import boundaries | dependency-cruiser rules (`.dependency-cruiser.cjs`, CI-blocking via `audit:deps` — 0 errors since P8-D, #526) |
| Adapter wiring stays out of the engine | `engine-not-into-upper-trees` rule + `sync/service/compositionPorts.ts` |
| Protocol import surface stays minimal | `test/protocol-import-boundary.test.ts` |
| Log events stay a closed registry | `test/log-event-registry-contract.test.ts` |

## Reading path for a new contributor

1. This page (Layer 2 only) — you can work on the dispatcher/supervisors
   without opening Layers 1 or 3.
2. When a test fails in `outbox-contract-drift.test.ts`: you touched the
   ledger contract; Layer 1 owns it, Layer 2 consumes it.
3. When dependency-cruiser fails: you crossed a layer backwards; the rule
   name names the layer.