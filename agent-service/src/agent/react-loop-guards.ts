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

import type { ModelMessage } from "ai";
import type { ReActStep } from "../types/agent";

/**
 * Guards that keep the agent's ReAct loop stable: a repeated-tool-call detector that nudges the
 * model out of loops, and a rolling event window that bounds the context size. Both are pure
 * functions (no LLM calls, no mutation), so they are deterministic and easy to unit test. The
 * live "# Current Workflow" section always carries the workflow's full current state, so dropping
 * older conversational events never loses the thing the agent is actually working on.
 */

/** Deterministic stringify with recursively sorted keys, so equal inputs hash identically. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`).join(",")}}`;
}

function toolCallSignature(toolName: string, input: unknown): string {
  return `${toolName}::${stableStringify(input)}`;
}

function lengthOf(value: unknown): number {
  if (typeof value === "string") return value.length;
  try {
    return JSON.stringify(value)?.length ?? 0;
  } catch {
    return 0;
  }
}

/** Rough token estimate (~4 chars/token) for one event as it will appear in the context. */
function estimateStepTokens(step: ReActStep): number {
  let chars = (step.content ?? "").length;
  for (const call of step.toolCalls ?? []) chars += call.toolName.length + lengthOf(call.input);
  for (const result of step.toolResults ?? []) chars += lengthOf(result.output);
  return Math.ceil(chars / 4) + 24; // small per-event overhead for the event header/labels
}

export interface EventWindow {
  /** The events to send to the model, in chronological order. */
  kept: ReActStep[];
  /** How many events were dropped to fit the budget. */
  omitted: number;
}

/**
 * Bound the event log by keeping only the most recent events that fit a token budget (newest
 * first), always retaining the latest user request so the task is never lost. Older events are
 * dropped — the live "# Current Workflow" section still carries the workflow's full current state.
 * Always keeps at least one event. Deterministic and side-effect free.
 */
export function windowEvents(steps: ReActStep[], tokenBudget: number): EventWindow {
  if (steps.length === 0) return { kept: [], omitted: 0 };

  let latestUserIdx = -1;
  for (let i = steps.length - 1; i >= 0; i--) {
    if (steps[i].role === "user") {
      latestUserIdx = i;
      break;
    }
  }

  const keep = new Set<number>();
  let used = 0;
  if (latestUserIdx >= 0) {
    keep.add(latestUserIdx);
    used += estimateStepTokens(steps[latestUserIdx]);
  }

  for (let i = steps.length - 1; i >= 0; i--) {
    if (keep.has(i)) continue;
    const cost = estimateStepTokens(steps[i]);
    if (keep.size > 0 && used + cost > tokenBudget) break; // keep at least one event
    keep.add(i);
    used += cost;
  }

  const kept = steps.filter((_, i) => keep.has(i));
  return { kept, omitted: steps.length - kept.length };
}

/**
 * Returns a warning when the most recent tool call repeats a (tool, parameters) signature that
 * has now occurred at least `threshold` times — i.e. the agent is looping. Returns null when the
 * latest action is novel, so the nudge appears exactly while looping and clears once it changes.
 */
export function detectRepeatedToolCalls(steps: ReActStep[], threshold: number): string | null {
  const counts = new Map<string, number>();
  let lastCall: { toolName: string; input: unknown; signature: string } | null = null;

  for (const step of steps) {
    if (step.role !== "agent" || !step.toolCalls) continue;
    for (const call of step.toolCalls) {
      const signature = toolCallSignature(call.toolName, call.input);
      counts.set(signature, (counts.get(signature) ?? 0) + 1);
      lastCall = { toolName: call.toolName, input: call.input, signature };
    }
  }

  if (!lastCall) return null;
  const count = counts.get(lastCall.signature) ?? 0;
  if (count < threshold) return null;

  const params = stableStringify(lastCall.input);
  const shownParams = params.length > 300 ? `${params.slice(0, 300)}…` : params;
  return (
    `You have already called the tool \`${lastCall.toolName}\` with the same parameters ${count} times ` +
    `(parameters: ${shownParams}). Repeating the identical call is not making progress. Stop and change ` +
    `direction: fix the underlying cause, try a different tool or different parameters, or ask the user ` +
    `for clarification — do not call it again with the same parameters.`
  );
}

/** Appends a "# System Notice" block to the (single) prepared user message. */
export function appendSystemNotice(messages: ModelMessage[], notice: string): ModelMessage[] {
  if (messages.length === 0) {
    return [{ role: "user", content: `# System Notice\n${notice}` }];
  }
  const last = messages[messages.length - 1];
  const content = typeof last.content === "string" ? last.content : "";
  const updated = { ...last, content: `${content}\n\n# System Notice\n${notice}` } as ModelMessage;
  return [...messages.slice(0, -1), updated];
}
