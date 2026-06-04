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
import { appendSystemNotice, detectRepeatedToolCalls, windowEvents } from "./react-loop-guards";
import type { ReActStep } from "../types/agent";

function step(id: string, partial: Partial<ReActStep>): ReActStep {
  return { id, messageId: "m", stepId: 0, timestamp: 0, role: "agent", content: "", isBegin: false, isEnd: false, ...partial };
}
function userStep(id: string, contentLen = 4): ReActStep {
  return step(id, { role: "user", content: "u".repeat(contentLen) });
}
// content length controls the estimated token cost (~chars/4 + small overhead).
function agentStep(id: string, contentLen = 4): ReActStep {
  return step(id, { role: "agent", content: "a".repeat(contentLen) });
}
function toolStep(id: string, toolName: string, input: unknown): ReActStep {
  return step(id, { role: "agent", toolCalls: [{ toolName, toolCallId: `${id}-tc`, input }] });
}

describe("windowEvents", () => {
  test("empty input yields nothing omitted", () => {
    expect(windowEvents([], 1000)).toEqual({ kept: [], omitted: 0 });
  });

  test("keeps everything when it fits the budget", () => {
    const steps = [userStep("u"), agentStep("a1"), agentStep("a2")];
    const { kept, omitted } = windowEvents(steps, 100000);
    expect(kept.map(s => s.id)).toEqual(["u", "a1", "a2"]);
    expect(omitted).toBe(0);
  });

  test("drops the oldest events but keeps the latest user request and the most recent events", () => {
    // user ~25 tokens; each agent (~400 chars) ~124 tokens. Budget 300 fits user + 2 recent agents.
    const steps = [userStep("u"), agentStep("a1", 400), agentStep("a2", 400), agentStep("a3", 400), agentStep("a4", 400)];
    const { kept, omitted } = windowEvents(steps, 300);
    expect(kept.map(s => s.id)).toEqual(["u", "a3", "a4"]); // chronological order, with a gap
    expect(omitted).toBe(2);
  });

  test("always keeps the latest user request even when the budget is tiny", () => {
    const steps = [userStep("u", 8), agentStep("a1", 400), agentStep("a2", 400)];
    const { kept } = windowEvents(steps, 1);
    expect(kept.map(s => s.id)).toContain("u");
  });

  test("keeps at least one event when there is no user step", () => {
    const steps = [agentStep("a1", 400), agentStep("a2", 400)];
    const { kept } = windowEvents(steps, 1);
    expect(kept.length).toBeGreaterThanOrEqual(1);
    expect(kept[kept.length - 1].id).toBe("a2"); // the most recent
  });
});

describe("detectRepeatedToolCalls", () => {
  test("returns null below the threshold", () => {
    expect(detectRepeatedToolCalls([toolStep("a", "addOperator", { id: 1 }), toolStep("b", "addOperator", { id: 1 })], 3)).toBeNull();
  });

  test("warns when the latest call repeats at/over the threshold", () => {
    const steps = [toolStep("a", "csvScan", { p: "x" }), toolStep("b", "csvScan", { p: "x" }), toolStep("c", "csvScan", { p: "x" })];
    const warning = detectRepeatedToolCalls(steps, 3);
    expect(warning).toContain("csvScan");
    expect(warning).toContain("3 times");
  });

  test("ignores parameter key order", () => {
    const steps = [toolStep("a", "t", { a: 1, b: 2 }), toolStep("b", "t", { b: 2, a: 1 }), toolStep("c", "t", { a: 1, b: 2 })];
    expect(detectRepeatedToolCalls(steps, 3)).not.toBeNull();
  });

  test("clears once the latest call changes, even if an earlier one repeated", () => {
    const steps = [toolStep("a", "t", { a: 1 }), toolStep("b", "t", { a: 1 }), toolStep("c", "t", { a: 1 }), toolStep("d", "t", { a: 2 })];
    expect(detectRepeatedToolCalls(steps, 3)).toBeNull();
  });
});

describe("appendSystemNotice", () => {
  test("adds a notice to the last message", () => {
    const out = appendSystemNotice([{ role: "user", content: "ctx" }], "stop looping");
    expect(out[0].content).toContain("ctx");
    expect(out[0].content).toContain("# System Notice");
    expect(out[0].content).toContain("stop looping");
  });
});
