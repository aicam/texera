/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * Tool results are read by a language model, so they are formatted as compact
 * text rather than raw JSON: fewer tokens, and the meaning is not buried in
 * punctuation. Anything genuinely structural (a workflow's content, a schema)
 * still goes out as JSON.
 */

/** Truncates in the middle, which keeps both the head and the tail readable. */
export function truncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const keep = Math.max(1, Math.floor((maxChars - 80) / 2));
  const omitted = text.length - keep * 2;
  return `${text.slice(0, keep)}\n\n… [${omitted} characters omitted to fit the result limit] …\n\n${text.slice(-keep)}`;
}

export function formatBytes(bytes: number | undefined): string {
  if (bytes === undefined || bytes === null || Number.isNaN(bytes)) return "unknown size";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unitIndex]}`;
}

/** Timestamps arrive as epoch millis; ISO is unambiguous across locales. */
export function formatTimestamp(value: number | undefined | null): string {
  if (value === undefined || value === null) return "unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "unknown" : date.toISOString().replace(".000Z", "Z");
}

/** Renders rows as an aligned text table. Empty input yields a marker, not an empty string. */
export function formatTable(headers: string[], rows: (string | number | undefined)[][]): string {
  if (rows.length === 0) return "(none)";
  const cells = rows.map(row => row.map(cell => (cell === undefined || cell === null ? "" : String(cell))));
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...cells.map(row => (row[index] ?? "").length))
  );
  const line = (row: string[]) =>
    row
      .map((cell, index) => cell.padEnd(widths[index]))
      .join("  ")
      .trimEnd();
  return [line(headers), line(widths.map(width => "-".repeat(width))), ...cells.map(line)].join("\n");
}

/**
 * Renders result records as a table, capping both rows and characters. Result
 * sets can be enormous; a model needs shape and a sample, not everything.
 */
export function formatRecords(
  records: Record<string, unknown>[],
  options: { maxRows?: number; maxChars?: number } = {}
): string {
  if (records.length === 0) return "(no rows)";
  const maxRows = options.maxRows ?? 20;
  // The engine adds a synthetic row index that carries no information for a reader.
  const headers = Object.keys(records[0]).filter(key => key !== "__row_index__");
  const shown = records.slice(0, maxRows);
  const rows = shown.map(record => headers.map(header => stringifyCell(record[header])));
  let table = formatTable(headers, rows);
  if (records.length > shown.length) {
    table += `\n… ${records.length - shown.length} more row(s) not shown`;
  }
  return options.maxChars ? truncate(table, options.maxChars) : table;
}

function stringifyCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  const text = String(value);
  return text.length > 120 ? `${text.slice(0, 117)}…` : text;
}

/** Joins non-empty sections with blank lines. */
export function joinSections(...sections: (string | undefined | false)[]): string {
  return sections.filter((section): section is string => Boolean(section && section.trim())).join("\n\n");
}
