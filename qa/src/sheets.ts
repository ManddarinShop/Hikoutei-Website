/**
 * Direct Sheets access for the human lane (no library involved).
 *
 * The server lane goes through the EntityManager; the human lane must touch
 * the Sheet exactly like a person typing: raw cell reads/writes through the
 * Sheets REST API with `USER_ENTERED` input (formulas/dates parse the way a
 * human edit parses). Authentication is a service-account JWT; the key
 * arrives as `QA_SA_JSON` (same shape as the demo's `DEMO_SA_JSON`) and is
 * never logged — only byte counts and tab names leave this module.
 *
 * Dormant until `QA_SYNC_SPREADSHEET_URL` + `QA_SA_JSON` are set (a QA-only
 * sheet — never the demo sheet). Exists now so scenario composition has a
 * stable seam to target.
 */

import { JWT } from "google-auth-library";

const SHEETS_API = "https://sheets.googleapis.com/v4/spreadsheets";

/** Extracts the spreadsheet id from a `/d/<id>/` URL (query ignored). */
export function parseSpreadsheetId(url: string): string {
  const match = url.match(/\/d\/([A-Za-z0-9_-]+)/);
  if (match === null || match[1] === undefined) {
    throw new Error("QA_SYNC_SPREADSHEET_URL is not a /d/<id>/ URL");
  }
  return match[1];
}

/** Column index (1-based) to A1 letters: 1 -> A, 27 -> AA. */
export function columnToLetter(column: number): string {
  if (!Number.isInteger(column) || column < 1) {
    throw new Error(`invalid column: ${column}`);
  }
  let letters = "";
  let rest = column;
  while (rest > 0) {
    const remainder = (rest - 1) % 26;
    letters = String.fromCharCode(65 + remainder) + letters;
    rest = Math.floor((rest - 1) / 26);
  }
  return letters;
}

export interface SheetsDirect {
  readonly spreadsheetId: string;
  /** Tab titles in tab order (metadata only — no cell values). */
  listTabs(): Promise<readonly string[]>;
  /** Raw cell grid for an A1 range (rows of values, may be ragged). */
  readRange(tab: string, a1Range: string): Promise<readonly (readonly unknown[])[]>;
  /** Human-typing write of one cell (1-based row/column). */
  writeCell(tab: string, row: number, column: number, value: unknown): Promise<void>;
  /** Human-typing append of one row at the table bottom. */
  appendRow(tab: string, values: readonly unknown[]): Promise<void>;
  /** Physical row deletion, [startRow, endRowExclusive), 1-based. */
  deleteRows(tab: string, startRow: number, endRowExclusive: number): Promise<void>;
}

/**
 * Builds an authenticated Sheets client. No network happens here; the first
 * call mints the token (the google-auth client caches and refreshes it).
 */
export async function createSheetsDirect(args: {
  readonly saJson: string;
  readonly spreadsheetUrl: string;
}): Promise<SheetsDirect> {
  const credentials = JSON.parse(args.saJson) as { client_email?: unknown; private_key?: unknown };
  if (typeof credentials.client_email !== "string" || typeof credentials.private_key !== "string") {
    throw new Error("QA_SA_JSON is not a service-account key (client_email/private_key)");
  }
  const spreadsheetId = parseSpreadsheetId(args.spreadsheetUrl);
  const client = new JWT({
    email: credentials.client_email,
    key: credentials.private_key,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });

  async function authed(path: string, init?: RequestInit): Promise<unknown> {
    const { token } = await client.getAccessToken();
    if (token === null || token === undefined || token === "") {
      throw new Error("Sheets auth produced no token");
    }
    const response = await fetch(`${SHEETS_API}/${spreadsheetId}${path}`, {
      ...init,
      headers: { ...init?.headers, Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
      throw new Error(`Sheets API ${response.status} on ${path}`);
    }
    return (await response.json()) as unknown;
  }

  return {
    spreadsheetId,
    async listTabs(): Promise<readonly string[]> {
      const meta = (await authed(`?fields=sheets.properties.title`)) as {
        sheets?: readonly { properties?: { title?: string } }[];
      };
      return (meta.sheets ?? []).map((sheet) => sheet.properties?.title ?? "");
    },
    async readRange(tab, a1Range): Promise<readonly (readonly unknown[])[]> {
      const body = (await authed(
        `/values/${encodeURIComponent(tab)}!${encodeURIComponent(a1Range)}`,
      )) as { values?: readonly (readonly unknown[])[] };
      return body.values ?? [];
    },
    async writeCell(tab, row, column, value): Promise<void> {
      const cell = `${columnToLetter(column)}${row}`;
      await authed(`/values/${encodeURIComponent(tab)}!${cell}?valueInputOption=USER_ENTERED`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ values: [[value]] }),
      });
    },
    async appendRow(tab, values): Promise<void> {
      await authed(`/values/${encodeURIComponent(tab)}:append?valueInputOption=USER_ENTERED`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ values: [values] }),
      });
    },
    async deleteRows(tab, startRow, endRowExclusive): Promise<void> {
      const meta = (await authed(`?fields=sheets.properties`)) as {
        sheets?: readonly { properties?: { title?: string; sheetId?: number } }[];
      };
      const sheetId = meta.sheets
        ?.find((sheet) => sheet.properties?.title === tab)?.properties?.sheetId;
      if (sheetId === undefined) throw new Error(`tab not found: ${tab}`);
      await authed(`:batchUpdate`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          requests: [{
            deleteDimension: {
              range: { sheetId, dimension: "ROWS", startIndex: startRow - 1, endIndex: endRowExclusive - 1 },
            },
          }],
        }),
      });
    },
  };

}
