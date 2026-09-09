/**
 * Shared QA entity and model shape.
 *
 * Both the harness loop (server.ts) and the minimum-op units (minops.ts)
 * import from here so the entity token has one home and no import cycle.
 */

import { defineTypedSheetsEntity } from "hikoutei";

export const QARecord = defineTypedSheetsEntity({
  name: "QARecord",
  tableName: "qa_records",
  properties: {
    id: { type: "string", primary: true },
    name: { type: "string" },
    amount: { type: "number" },
    processed: { type: "boolean" },
  },
});

export interface ExpectedRow {
  readonly name: string;
  readonly amount: number;
  readonly processed: boolean;
}

/** The model mirror: every row the runtime must hold, by id. */
export type ModelMirror = Map<string, ExpectedRow>;
