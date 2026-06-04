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
import { assembleContext } from "./context-utils";
import { WorkflowState } from "../workflow-state";
import type { ReActStep } from "../../types/agent";
import type { OperatorPredicate } from "../../types/workflow";

function makeUserStep(overrides: Partial<ReActStep> = {}): ReActStep {
  return {
    id: "step-user",
    messageId: "msg-1",
    stepId: 0,
    timestamp: Date.UTC(2026, 0, 1, 0, 0, 0),
    role: "user",
    content: "List my datasets",
    isBegin: true,
    isEnd: true,
    messageSource: "chat",
    ...overrides,
  };
}

function makeAgentStep(overrides: Partial<ReActStep> = {}): ReActStep {
  return {
    id: "step-agent",
    parentId: "step-user",
    messageId: "msg-1",
    stepId: 1,
    timestamp: Date.UTC(2026, 0, 1, 0, 0, 1),
    role: "agent",
    content: "I need to inspect accessible datasets.",
    isBegin: true,
    isEnd: true,
    toolCalls: [
      {
        toolName: "listDatasets",
        toolCallId: "call-1",
        input: { visibility: "all", ownership: "all" },
      },
    ],
    toolResults: [
      {
        toolCallId: "call-1",
        output: "dataset-a\nwith two files",
        isError: false,
      },
    ],
    ...overrides,
  };
}

function makeOperator(id: string, overrides: Partial<OperatorPredicate> = {}): OperatorPredicate {
  return {
    operatorID: id,
    operatorType: "CSVFileScan",
    operatorVersion: "1.0",
    operatorProperties: { fileName: "data.csv" },
    inputPorts: [],
    outputPorts: [{ portID: "output-0", displayName: "Output 0" }],
    showAdvanced: false,
    ...overrides,
  };
}

function getContextContent(
  steps: ReActStep[],
  workflowState: WorkflowState = new WorkflowState(),
  operatorResults: Map<string, string> = new Map(),
  options: Parameters<typeof assembleContext>[3] = {}
): string {
  const messages = assembleContext(steps, workflowState, operatorResults, options);
  expect(messages).toHaveLength(1);
  expect(messages[0].role).toBe("user");
  return messages[0].content as string;
}

describe("assembleContext event serialization", () => {
  test("serializes user and agent ReAct steps without storage metadata", () => {
    const content = getContextContent([makeUserStep(), makeAgentStep()]);

    expect(content).toContain("# Event Context");
    expect(content).not.toContain("# Completed Tasks");
    expect(content).not.toContain("# Ongoing Task");

    expect(content).toContain("## Event 1: user_task");
    expect(content).toContain("Content:");
    expect(content).toContain("List my datasets");

    expect(content).toContain("## Event 2: agent_event");
    expect(content).toContain("Thought:");
    expect(content).toContain("I need to inspect accessible datasets.");
    expect(content).toContain("Action: listDatasets");
    expect(content).toContain('"visibility": "all"');
    expect(content).toContain('"ownership": "all"');
    expect(content).toContain("Result Status: succeeded");
    expect(content).toContain("Result:");
    expect(content).toContain("dataset-a");
    expect(content).toContain("with two files");

    expect(content).not.toContain("Message ID:");
    expect(content).not.toContain("ReAct Step ID:");
    expect(content).not.toContain("Step ID:");
    expect(content).not.toContain("Timestamp:");
    expect(content).not.toContain("Role:");
    expect(content).not.toContain("Begin:");
    expect(content).not.toContain("End:");
    expect(content).not.toContain("Source:");
    expect(content).not.toContain("Tool Call ID:");
    expect(content).not.toContain("Usage:");
  });

  test("serializes user feedback as a user_event", () => {
    const content = getContextContent([
      makeUserStep({
        messageSource: "feedback",
        content: "That answer missed the private datasets.",
      }),
    ]);

    expect(content).toContain("## Event 1: user_event");
    expect(content).toContain("That answer missed the private datasets.");
    expect(content).not.toContain("Source:");
  });

  test("renders the rolling-window omission note when earlier events were dropped", () => {
    const content = getContextContent([makeUserStep()], new WorkflowState(), new Map(), {
      omittedEventCount: 3,
    });
    expect(content).toContain("3 earlier event(s) omitted to fit the context window");
  });

  test("omits the rolling-window note when no events were dropped", () => {
    const content = getContextContent([makeUserStep()]);
    expect(content).not.toContain("omitted to fit the context window");
  });

  test("limits serialized tool results with maxResolvedCharLimit", () => {
    const content = getContextContent(
      [
        makeUserStep(),
        makeAgentStep({
          toolResults: [
            {
              toolCallId: "call-1",
              output: "abcdefghijklmnopqrstuvwxyz",
            },
          ],
        }),
      ],
      new WorkflowState(),
      new Map(),
      { maxResolvedCharLimit: 24 }
    );

    expect(content).toContain("...[truncated]");
    expect(content).not.toContain("abcdefghijklmnopqrstuvwxyz");
  });
});

describe("assembleContext workflow section", () => {
  test("omits current workflow when includeWorkflowContext is false", () => {
    const workflowState = new WorkflowState();
    workflowState.addOperator(makeOperator("scan-1"));

    const content = getContextContent([makeUserStep()], workflowState, new Map(), {
      includeWorkflowContext: false,
    });

    expect(content).not.toContain("# Current Workflow");
    expect(content).not.toContain("### Operator `scan-1`");
  });

  test("appends current workflow when includeWorkflowContext is true", () => {
    const workflowState = new WorkflowState();
    workflowState.addOperator(makeOperator("scan-1"));

    const content = getContextContent([makeUserStep()], workflowState, new Map(), {
      includeWorkflowContext: true,
    });

    expect(content).toContain("# Current Workflow");
    expect(content).toContain("### Operator `scan-1` (CSVFileScan, not-executed)");
    expect(content).toContain("Properties:");
    expect(content).toContain("fileName: data.csv");
  });

  test("appends an empty current workflow section when includeWorkflowContext is true but there are no operators", () => {
    const content = getContextContent([makeUserStep()], new WorkflowState(), new Map(), {
      includeWorkflowContext: true,
    });

    expect(content).toContain("# Current Workflow");
    expect(content).toContain("(empty");
  });

  test("flags when no computing unit is connected and points to the top menu bar", () => {
    const workflowState = new WorkflowState();
    workflowState.addOperator(makeOperator("scan-1"));

    const content = getContextContent([makeUserStep()], workflowState, new Map(), {
      includeWorkflowContext: true,
      computingUnitConnected: false,
    });

    expect(content).toContain("Computing unit: not connected");
    expect(content).toContain("top menu bar");
  });

  test("flags when a computing unit is connected", () => {
    const workflowState = new WorkflowState();
    workflowState.addOperator(makeOperator("scan-1"));

    const content = getContextContent([makeUserStep()], workflowState, new Map(), {
      includeWorkflowContext: true,
      computingUnitConnected: true,
    });

    expect(content).toContain("Computing unit: connected");
  });
});
