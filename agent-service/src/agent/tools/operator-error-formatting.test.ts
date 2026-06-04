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
import {
  distillError,
  formatConsoleLogs,
  formatErrorAndConsole,
  headTailTruncate,
} from "./operator-error-formatting";

// A long Python traceback: the real cause (KeyError) is at the very end, after many internal frames.
const TRACEBACK = [
  "Traceback (most recent call last):",
  '  File "/usr/local/lib/python3.9/site-packages/pyamber/operator.py", line 312, in run',
  "    next(self.process(table, port))",
  '  File "/usr/local/lib/python3.9/site-packages/pytexera/udf/udf_operator.py", line 88, in wrapper',
  "    yield from fn(table, port)",
  '  File "<udf>", line 8, in process_table',
  '    df["x"] = df["nonexistent"] + 1',
  '  File "/usr/local/lib/python3.9/site-packages/pandas/core/frame.py", line 3805, in __getitem__',
  "    indexer = self.columns.get_loc(key)",
  '  File "/usr/local/lib/python3.9/site-packages/pandas/core/indexes/base.py", line 3805, in get_loc',
  "    raise KeyError(key) from err",
  "KeyError: 'nonexistent'",
].join("\n");

describe("distillError", () => {
  test("returns the error unchanged when within budget", () => {
    expect(distillError("boom", 100)).toBe("boom");
  });

  test("keeps the real exception (tail) and user frame, drops framework frames", () => {
    const out = distillError(TRACEBACK, 300); // raw is > 300 chars, so it must distill
    expect(out).toContain("KeyError: 'nonexistent'"); // the actual cause, originally at the very end
    expect(out).toContain("process_table"); // the user-code frame is kept
    expect(out).toContain('df["nonexistent"]'); // the offending user line is kept
    expect(out).not.toContain("pyamber/operator.py"); // deep framework frame dropped
    expect(out).not.toContain("pandas/core/indexes"); // deep framework frame dropped
  });

  test("head-truncation alone would have lost the cause (regression guard)", () => {
    // Plain slice(0, n) drops the KeyError; distillError must NOT.
    const headOnly = TRACEBACK.slice(0, 300);
    expect(headOnly).not.toContain("KeyError");
    expect(distillError(TRACEBACK, 300)).toContain("KeyError");
  });

  test("non-traceback long error keeps both head and tail", () => {
    const text = "START " + "x".repeat(500) + " END_CAUSE";
    const out = distillError(text, 60);
    expect(out.length).toBeLessThanOrEqual(60);
    expect(out).toContain("START");
    expect(out).toContain("END_CAUSE");
    expect(out).toContain("truncated");
  });
});

describe("formatConsoleLogs", () => {
  test("returns empty string when there is no console output", () => {
    expect(formatConsoleLogs(undefined, 1000)).toBe("");
    expect(formatConsoleLogs([], 1000)).toBe("");
  });

  test("surfaces error/stderr lines first, then other lines", () => {
    const out = formatConsoleLogs(
      [
        { msgType: "PRINT", message: "loaded 100 rows" },
        { msgType: "ERROR", message: "KeyError: nonexistent" },
      ],
      1000
    );
    expect(out.startsWith("Console output:\n")).toBe(true);
    expect(out.indexOf("[ERROR] KeyError: nonexistent")).toBeLessThan(out.indexOf("[PRINT] loaded 100 rows"));
  });
});

describe("formatErrorAndConsole", () => {
  test("error with no console output is just the prefixed error (back-compat)", () => {
    expect(formatErrorAndConsole({ state: "Failed", inputTuples: 0, outputTuples: 0, resultMode: "table", error: "boom" }, 2000)).toBe(
      "[ERROR] boom"
    );
  });

  test("includes both the error and the console output when present", () => {
    const out = formatErrorAndConsole(
      {
        state: "Failed",
        inputTuples: 0,
        outputTuples: 0,
        resultMode: "table",
        error: "KeyError: 'nonexistent'",
        consoleLogs: [{ msgType: "PRINT", message: "debug: about to index" }],
      },
      2000
    );
    expect(out).toContain("[ERROR] KeyError: 'nonexistent'");
    expect(out).toContain("Console output:");
    expect(out).toContain("[PRINT] debug: about to index");
  });
});

describe("headTailTruncate", () => {
  test("preserves both ends", () => {
    const out = headTailTruncate("HEAD" + "m".repeat(200) + "TAIL", 40);
    expect(out.startsWith("HEAD")).toBe(true);
    expect(out.endsWith("TAIL")).toBe(true);
  });
});
