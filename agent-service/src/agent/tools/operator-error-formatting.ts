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

import type { ConsoleMessage, OperatorInfo } from "../../types/execution";

/**
 * Turns an operator's error and console output into the most useful text for the model within a
 * character budget. Two problems this addresses:
 *  - Plain head truncation drops the END of a Python traceback, which is exactly where the real
 *    exception is — so we distill the traceback (final exception + user-code frames) and fall back
 *    to head+tail truncation, never tail-only loss.
 *  - Console messages (print/stderr) were not reaching the model at all; they often carry the
 *    actual failure detail, so we now include them.
 */

const ELLIPSIS = "\n…[truncated]…\n";
const ERROR_PREFIX = "[ERROR] ";

const FRAME_RE = /^\s*File ".*", line \d+/;
// Frames inside the framework/runtime that the user cannot act on.
const INTERNAL_FRAME_RE =
  /site-packages|dist-packages|pyamber|pytexera|core\/amber|core\/storage|overrides[/.]|runpy|importlib|threading\.py|asyncio|concurrent[/.]futures/;
const ERROR_LIKE_MSG_TYPE = /error|exception|stderr|warn|fail/i;

/** Keep both ends of an over-long text so neither the summary nor the final cause is lost. */
export function headTailTruncate(text: string, maxChars: number): string {
  if (maxChars <= 0) return "";
  if (text.length <= maxChars) return text;
  if (maxChars <= ELLIPSIS.length) return text.slice(text.length - maxChars); // keep the tail (the cause)
  const budget = maxChars - ELLIPSIS.length;
  const headLen = Math.floor(budget * 0.3);
  const tailLen = budget - headLen;
  return `${text.slice(0, headLen)}${ELLIPSIS}${text.slice(text.length - tailLen)}`;
}

/**
 * Distill an error to fit `maxChars`. For a Python traceback, keep the header, the user-code
 * frames (dropping deep framework frames), and the final exception. Otherwise keep head+tail.
 */
export function distillError(error: string, maxChars: number): string {
  const text = (error ?? "").trimEnd();
  if (text.length <= maxChars) return text;

  if (/Traceback \(most recent call last\)/.test(text)) {
    const lines = text.split("\n");
    const header = lines.find(l => l.includes("Traceback (most recent call last)")) ?? "Traceback (most recent call last):";

    const userFrames: string[] = [];
    let lastFrameIdx = -1;
    for (let i = 0; i < lines.length; i++) {
      if (!FRAME_RE.test(lines[i])) continue;
      lastFrameIdx = i;
      if (INTERNAL_FRAME_RE.test(lines[i])) continue;
      userFrames.push(`  ${lines[i].trim()}`);
      const next = lines[i + 1];
      if (next && !FRAME_RE.test(next) && next.trim()) userFrames.push(`    ${next.trim()}`);
    }

    // The exception message is whatever follows the last stack frame.
    const exceptionLines = (lastFrameIdx >= 0 ? lines.slice(lastFrameIdx + 1) : []).filter(l => l.trim());

    if (lastFrameIdx >= 0 && exceptionLines.length > 0) {
      const parts = [header];
      if (userFrames.length) parts.push(...userFrames);
      parts.push("  …", ...exceptionLines);
      const distilled = parts.join("\n");
      return distilled.length <= maxChars ? distilled : headTailTruncate(distilled, maxChars);
    }
  }

  return headTailTruncate(text, maxChars);
}

/**
 * Format an operator's console output for the model: error/stderr lines first (most actionable),
 * then the most recent other lines, within `maxChars`. Returns "" when there is nothing to show.
 */
export function formatConsoleLogs(consoleLogs: ConsoleMessage[] | undefined, maxChars: number): string {
  if (!consoleLogs?.length || maxChars <= 0) return "";
  const errorLike = consoleLogs.filter(m => ERROR_LIKE_MSG_TYPE.test(m.msgType));
  const rest = consoleLogs.filter(m => !ERROR_LIKE_MSG_TYPE.test(m.msgType));
  const ordered = [...errorLike, ...rest.slice(-15)];
  const body = ordered
    .map(m => `[${m.msgType}] ${m.message}`)
    .join("\n")
    .trimEnd();
  if (!body) return "";
  return `Console output:\n${headTailTruncate(body, maxChars)}`;
}

/**
 * Combined error + console block for a failed operator within `maxChars`. Console is given a
 * slice of the budget only when present, so an error with no console output is unchanged.
 */
export function formatErrorAndConsole(opInfo: OperatorInfo, maxChars: number): string {
  const limit = isFiniteLimit(maxChars) ? maxChars : Number.MAX_SAFE_INTEGER;
  const hasConsole = !!opInfo.consoleLogs?.length;
  const consoleBudget = hasConsole ? Math.min(800, Math.floor(limit * 0.35)) : 0;
  const errorBudget = Math.max(0, limit - consoleBudget - ERROR_PREFIX.length);

  const blocks = [`${ERROR_PREFIX}${distillError(opInfo.error ?? "", errorBudget)}`];
  const consoleBlock = formatConsoleLogs(opInfo.consoleLogs, consoleBudget);
  if (consoleBlock) blocks.push(consoleBlock);
  return blocks.join("\n\n");
}

/** Console budget for the success path: a small reserved slice, only when console output exists. */
export function successConsoleBudget(maxChars: number | undefined): number {
  if (!isFiniteLimit(maxChars)) return Number.MAX_SAFE_INTEGER;
  return Math.min(600, Math.floor(maxChars * 0.3));
}

function isFiniteLimit(maxChars: number | undefined): maxChars is number {
  return typeof maxChars === "number" && Number.isFinite(maxChars) && maxChars > 0;
}
