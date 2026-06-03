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

// Output uses plain markdown rather than XML-like tags to reduce format
// mimicry, where the model echoes the context shape into its output instead
// of calling tools via the native protocol.

import type { ModelMessage } from "ai";
import type { WorkflowState } from "../workflow-state";
import type { OperatorPredicate, OperatorPortSchemaMap, PortSchema } from "../../types/workflow";
import type { ReActStep } from "../../types/agent";
import type { WorkflowCompilationResponse, WorkflowFatalError } from "../../api/compile-api";
import { extractOperatorInputPortSchemaMap } from "./workflow-utils";
import { createLogger } from "../../logger";
import { limitResolvedText } from "../tools/tools-utility";

const log = createLogger("ContextAssembler");

export interface AssembleContextOptions {
  useRedact?: boolean;
  compilationResult?: WorkflowCompilationResponse | null;
  includeWorkflowContext?: boolean;
  maxResolvedCharLimit?: number;
  /** Whether a computing unit is connected; surfaced so the model can guide the user to connect one. */
  computingUnitConnected?: boolean;
}

export function assembleContext(
  visibleSteps: ReActStep[],
  workflowState: WorkflowState,
  operatorExecutionResults: Map<string, string>,
  options: AssembleContextOptions = {}
): ModelMessage[] {
  const {
    useRedact = false,
    compilationResult,
    includeWorkflowContext = false,
    maxResolvedCharLimit,
    computingUnitConnected = false,
  } = options;
  const sections: string[] = [];
  sections.push(serializeEvents(visibleSteps, maxResolvedCharLimit));

  // When the user is in a workflow workspace the section is always present, so the model can
  // tell "empty workflow" apart from "no workflow context"; an empty DAG renders as "(empty)".
  if (includeWorkflowContext) {
    const dagSection = serializeDag(
      workflowState,
      operatorExecutionResults,
      useRedact,
      compilationResult,
      maxResolvedCharLimit
    );
    sections.push("");
    sections.push("# Current Workflow");
    sections.push(
      computingUnitConnected
        ? "Computing unit: connected — operators can be executed."
        : "Computing unit: not connected — to execute the workflow, the user must connect a computing unit from the top menu bar."
    );
    sections.push(dagSection ?? "(empty — no operators have been added to the workflow yet)");
  }

  const content = sections.join("\n");

  log.debug(
    {
      events: visibleSteps.length,
      includeWorkflowContext,
      operatorResults: operatorExecutionResults.size,
      useRedact,
    },
    "built context"
  );

  return [{ role: "user", content }];
}

function serializeEvents(steps: ReActStep[], maxResolvedCharLimit?: number): string {
  const lines: string[] = [];
  lines.push("# Event Context");

  if (steps.length === 0) {
    lines.push("");
    lines.push("(no prior events)");
    return lines.join("\n");
  }

  for (let i = 0; i < steps.length; i++) {
    lines.push("");
    lines.push(serializeEvent(steps[i], i + 1, maxResolvedCharLimit));
  }

  return lines.join("\n").trimEnd();
}

function serializeEvent(step: ReActStep, eventNumber: number, maxResolvedCharLimit?: number): string {
  const eventType = getEventType(step);
  const lines: string[] = [];
  lines.push(`## Event ${eventNumber}: ${eventType}`);

  if (step.role === "user") {
    lines.push("Content:");
    appendBlock(lines, step.content || "(empty)");
    return lines.join("\n");
  }

  lines.push("Thought:");
  appendBlock(lines, step.content || "(empty)");

  const toolCalls = step.toolCalls ?? [];
  const toolResults = step.toolResults ?? [];
  if (toolCalls.length === 0) {
    lines.push("Actions: (none)");
  } else {
    const resultsByCallId = new Map(toolResults.map(result => [result.toolCallId, result]));
    for (let i = 0; i < toolCalls.length; i++) {
      const toolCall = toolCalls[i];
      const toolResult = resultsByCallId.get(toolCall.toolCallId) ?? toolResults[i];
      lines.push("");
      lines.push(`### Tool Call ${i + 1}`);
      lines.push(`Action: ${toolCall.toolName}`);
      lines.push("Parameters:");
      appendBlock(lines, serializeValue(toolCall.input));
      if (toolResult) {
        lines.push(`Result Status: ${toolResult.isError ? "failed" : "succeeded"}`);
        lines.push("Result:");
        appendBlock(lines, serializeToolResult(toolResult.output, maxResolvedCharLimit));
      } else {
        lines.push("Result Status: missing");
        lines.push("Result:");
        appendBlock(lines, "(missing)");
      }
    }
  }

  const matchedToolCallIds = new Set(toolCalls.map(call => call.toolCallId));
  const unmatchedResults = toolResults.filter(result => !matchedToolCallIds.has(result.toolCallId));
  for (const result of unmatchedResults) {
    lines.push("");
    lines.push("### Tool Result Without Matching Call");
    lines.push(`Result Status: ${result.isError ? "failed" : "succeeded"}`);
    lines.push("Result:");
    appendBlock(lines, serializeToolResult(result.output, maxResolvedCharLimit));
  }

  return lines.join("\n");
}

function getEventType(step: ReActStep): "user_task" | "user_event" | "agent_event" {
  if (step.role === "agent") {
    return "agent_event";
  }
  return step.messageSource === "feedback" ? "user_event" : "user_task";
}

function appendBlock(lines: string[], content: string): void {
  const value = content.length > 0 ? content : "(empty)";
  for (const line of value.split("\n")) {
    lines.push(`  ${line}`);
  }
}

function serializeToolResult(output: unknown, maxResolvedCharLimit?: number): string {
  return limitResolvedText(serializeValue(output), maxResolvedCharLimit);
}

function serializeValue(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  try {
    const serialized = JSON.stringify(value, null, 2);
    if (serialized !== undefined) {
      return serialized;
    }
  } catch {}
  return String(value);
}

function serializeDag(
  workflowState: WorkflowState,
  operatorExecutionResults: Map<string, string>,
  useRedact: boolean,
  compilationResult?: WorkflowCompilationResponse | null,
  maxResolvedCharLimit?: number
): string | null {
  const allOperators = workflowState.getAllOperators();
  if (allOperators.length === 0) return null;

  const lines: string[] = [];

  const allLinks = workflowState.getAllLinks();
  const opIds = new Set(allOperators.map(op => op.operatorID));
  const inDegree = new Map<string, number>();
  const children = new Map<string, string[]>();
  for (const id of opIds) {
    inDegree.set(id, 0);
    children.set(id, []);
  }
  for (const link of allLinks) {
    children.get(link.source.operatorID)?.push(link.target.operatorID);
    inDegree.set(link.target.operatorID, (inDegree.get(link.target.operatorID) ?? 0) + 1);
  }
  const queue: string[] = [...opIds].filter(id => (inDegree.get(id) ?? 0) === 0);
  const topoOrder = new Map<string, number>();
  let rank = 0;
  while (queue.length > 0) {
    const node = queue.shift()!;
    topoOrder.set(node, rank++);
    for (const child of children.get(node) ?? []) {
      const newDeg = (inDegree.get(child) ?? 1) - 1;
      inDegree.set(child, newDeg);
      if (newDeg === 0) queue.push(child);
    }
  }

  const sortedOps = [...allOperators].sort(
    (a, b) => (topoOrder.get(a.operatorID) ?? 0) - (topoOrder.get(b.operatorID) ?? 0)
  );

  const outputSchemas = compilationResult?.operatorOutputSchemas ?? {};
  const compilationErrors = compilationResult?.operatorErrors ?? {};

  lines.push("## Operators");
  lines.push("");

  for (const op of sortedOps) {
    const inputSchemaMap = extractOperatorInputPortSchemaMap(op.operatorID, op, outputSchemas, allLinks);
    const outputSchemaMap = outputSchemas[op.operatorID];
    const compilationError = compilationErrors[op.operatorID];
    lines.push(
      serializeOperator(
        op,
        operatorExecutionResults.get(op.operatorID),
        useRedact,
        inputSchemaMap,
        outputSchemaMap,
        compilationError,
        maxResolvedCharLimit
      )
    );
    lines.push("");
  }

  if (allLinks.length > 0) {
    const sortedLinks = [...allLinks].sort((a, b) => {
      const srcA = topoOrder.get(a.source.operatorID) ?? 0;
      const srcB = topoOrder.get(b.source.operatorID) ?? 0;
      if (srcA !== srcB) return srcA - srcB;
      return (topoOrder.get(a.target.operatorID) ?? 0) - (topoOrder.get(b.target.operatorID) ?? 0);
    });

    lines.push("## Links");
    for (const link of sortedLinks) {
      lines.push(`- ${link.source.operatorID} → ${link.target.operatorID}`);
    }
  }

  return lines.join("\n").trimEnd();
}

function serializeOperator(
  op: OperatorPredicate,
  execResult: string | undefined,
  useRedact: boolean,
  inputSchemaMap?: OperatorPortSchemaMap,
  outputSchemaMap?: OperatorPortSchemaMap,
  compilationError?: WorkflowFatalError,
  maxResolvedCharLimit?: number
): string {
  const hasError = execResult !== undefined && execResult.includes("[ERROR]");
  const status = execResult ? (hasError ? "failed" : "executed") : "not-executed";

  const summary = op.customDisplayName || op.operatorID;
  const showProperties = !useRedact || hasError;

  const lines: string[] = [];
  lines.push(`### Operator \`${op.operatorID}\` (${op.operatorType}, ${status})`);
  lines.push(`Summary: ${summary}`);

  if (inputSchemaMap) {
    for (const [portId, schema] of Object.entries(inputSchemaMap)) {
      if (schema) {
        lines.push(`Input Table Schema (port ${parsePortIndex(portId)}): ${formatSchema(schema)}`);
      }
    }
  }

  if (showProperties) {
    const props = op.operatorProperties;
    if (props && Object.keys(props).length > 0) {
      lines.push("Properties:");
      for (const [key, value] of Object.entries(props)) {
        if (value !== undefined && value !== null && value !== "") {
          const valueStr = typeof value === "string" ? value : JSON.stringify(value);
          lines.push(`  ${key}: ${valueStr}`);
        }
      }
    }
  }

  if (outputSchemaMap) {
    const firstSchema = Object.values(outputSchemaMap).find(s => s !== undefined);
    if (firstSchema) {
      lines.push(`Output Table Schema: ${formatSchema(firstSchema)}`);
    }
  }

  if (compilationError) {
    lines.push(`Compilation Error: ${compilationError.message}`);
  }

  if (execResult) {
    lines.push("Result:");
    const indented = limitResolvedText(execResult, maxResolvedCharLimit)
      .split("\n")
      .map(l => "  " + l)
      .join("\n");
    lines.push(indented);
  }

  return lines.join("\n");
}

function formatSchema(schema: PortSchema): string {
  const attrs = schema.map(a => `${a.attributeName}: ${a.attributeType}`);
  return `[${attrs.join(", ")}]`;
}

function parsePortIndex(portId: string): string {
  const idx = portId.indexOf("_");
  return idx >= 0 ? portId.substring(0, idx) : portId;
}
