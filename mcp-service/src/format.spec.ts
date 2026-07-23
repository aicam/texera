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

import { describe, expect, test } from "bun:test";
import { formatBytes, formatRecords, formatTable, formatTimestamp, joinSections, truncate } from "./format";

describe("truncate", () => {
  test("leaves text within the limit untouched", () => {
    expect(truncate("hello", 100)).toBe("hello");
    expect(truncate("hello", 5)).toBe("hello");
  });

  test("keeps the head and the tail, and says how much went missing", () => {
    const result = truncate(`START${"x".repeat(2000)}END`, 400);
    expect(result).toStartWith("START");
    expect(result).toEndWith("END");
    expect(result).toContain("characters omitted");
  });

  test("survives a limit smaller than the marker itself", () => {
    expect(() => truncate("x".repeat(500), 10)).not.toThrow();
  });
});

describe("formatBytes", () => {
  test("scales through the units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MB");
    expect(formatBytes(3 * 1024 * 1024 * 1024)).toBe("3.0 GB");
  });

  test("drops the decimal once the number is large enough to not need it", () => {
    expect(formatBytes(20 * 1024)).toBe("20 KB");
  });

  test("says so rather than printing NaN for missing sizes", () => {
    expect(formatBytes(undefined)).toBe("unknown size");
    expect(formatBytes(Number.NaN)).toBe("unknown size");
  });
});

describe("formatTimestamp", () => {
  test("renders epoch millis as ISO", () => {
    expect(formatTimestamp(1_700_000_000_000)).toBe("2023-11-14T22:13:20Z");
  });

  test("does not invent a date for missing or invalid input", () => {
    expect(formatTimestamp(undefined)).toBe("unknown");
    expect(formatTimestamp(null)).toBe("unknown");
    expect(formatTimestamp(Number.NaN)).toBe("unknown");
  });
});

describe("formatTable", () => {
  test("aligns columns to the widest cell", () => {
    const table = formatTable(
      ["id", "name"],
      [
        [1, "short"],
        [200, "much longer name"],
      ]
    );
    const [header, , first] = table.split("\n");
    expect(header).toStartWith("id ");
    expect(first).toStartWith("1  ");
  });

  test("renders a marker instead of an empty table", () => {
    expect(formatTable(["id"], [])).toBe("(none)");
  });

  test("renders missing cells as blanks rather than 'undefined'", () => {
    expect(formatTable(["a", "b"], [["x", undefined]])).not.toContain("undefined");
  });
});

describe("formatRecords", () => {
  const rows = Array.from({ length: 50 }, (_, index) => ({ __row_index__: index, n: index, label: `row-${index}` }));

  test("hides the synthetic row index", () => {
    expect(formatRecords(rows.slice(0, 2))).not.toContain("__row_index__");
  });

  test("caps the number of rows and says how many were dropped", () => {
    const result = formatRecords(rows, { maxRows: 5 });
    expect(result).toContain("row-4");
    expect(result).not.toContain("row-6");
    expect(result).toContain("45 more row(s) not shown");
  });

  test("renders nested values as JSON rather than [object Object]", () => {
    expect(formatRecords([{ payload: { a: 1 } }])).toContain('{"a":1}');
    expect(formatRecords([{ payload: { a: 1 } }])).not.toContain("[object Object]");
  });

  test("shortens an over-long cell", () => {
    const result = formatRecords([{ text: "y".repeat(500) }]);
    expect(result).toContain("…");
    expect(result.length).toBeLessThan(300);
  });

  test("says there are no rows rather than returning nothing", () => {
    expect(formatRecords([])).toBe("(no rows)");
  });

  test("renders null and undefined cells as blanks", () => {
    const result = formatRecords([{ a: null, b: undefined, c: 1 }]);
    expect(result).not.toContain("null");
    expect(result).not.toContain("undefined");
  });
});

describe("joinSections", () => {
  test("drops empty, blank and falsy sections", () => {
    expect(joinSections("a", undefined, "", "   ", false, "b")).toBe("a\n\nb");
  });

  test("returns an empty string when everything is dropped", () => {
    expect(joinSections(undefined, "")).toBe("");
  });
});
