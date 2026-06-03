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

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import type { WorkflowContent } from "../types/workflow";

const workflowContent: WorkflowContent = {
  operators: [
    {
      operatorID: "scan-1",
      operatorType: "CSVFileScan",
      operatorVersion: "1.0",
      operatorProperties: { fileName: "data.csv" },
      inputPorts: [],
      outputPorts: [{ portID: "output-0", displayName: "Output 0" }],
      showAdvanced: false,
    },
  ],
  operatorPositions: { "scan-1": { x: 0, y: 0 } },
  links: [],
  commentBoxes: [],
  settings: { dataTransferBatchSize: 400 },
};

const liveWorkflowContent: WorkflowContent = {
  ...workflowContent,
  operators: [
    {
      ...workflowContent.operators[0],
      operatorID: "live-scan",
      operatorProperties: { fileName: "live.csv" },
    },
  ],
  operatorPositions: { "live-scan": { x: 0, y: 0 } },
};

let preparedContent = "";
const originalFetch = globalThis.fetch;
const fetchMock = mock(async () => {
  return new Response(JSON.stringify({ operatorOutputSchemas: {}, operatorErrors: {} }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
});

const generateTextMock = mock(async (params: any) => {
  const prepared = await params.prepareStep({ stepNumber: 0, messages: params.messages });
  preparedContent = prepared.messages[0]?.content ?? "";
  await params.onStepFinish({
    text: "Done",
    toolCalls: [],
    toolResults: [],
    usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
  });

  return {
    text: "Done",
    response: { messages: prepared.messages },
    totalUsage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
  };
});

const retrieveWorkflowMock = mock(async () => ({
  name: "Loaded Workflow",
  content: workflowContent,
}));
const persistWorkflowMock = mock(async () => undefined);

mock.module("ai", () => ({
  generateText: generateTextMock,
  jsonSchema: (schema: any) => schema,
  stepCountIs: () => () => false,
  tool: (definition: any) => definition,
}));

mock.module("../api/workflow-api", () => ({
  retrieveWorkflow: retrieveWorkflowMock,
  persistWorkflow: persistWorkflowMock,
}));

const { TexeraAgent } = await import("./texera-agent");

function makeAgent(): InstanceType<typeof TexeraAgent> {
  return new TexeraAgent({
    model: {} as any,
    modelType: "test-model",
    agentId: "agent-test",
    systemPrompt: "Test prompt",
  });
}

beforeEach(() => {
  preparedContent = "";
  generateTextMock.mockClear();
  retrieveWorkflowMock.mockClear();
  persistWorkflowMock.mockClear();
  fetchMock.mockClear();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("TexeraAgent workflow context", () => {
  test("includes the current workflow when workflow id is present without a computing unit", async () => {
    const agent = makeAgent();

    await agent.sendMessage("What is in this workflow?", {
      userToken: "user-token",
      workflowId: 123,
    });

    expect(retrieveWorkflowMock).toHaveBeenCalledWith("user-token", 123);
    expect(preparedContent).toContain("# Current Workflow");
    expect(preparedContent).toContain("### Operator `scan-1` (CSVFileScan, not-executed)");
  });

  test("omits the current workflow when workflow id is absent", async () => {
    const agent = makeAgent();

    await agent.sendMessage("What is in this workflow?", {
      userToken: "user-token",
    });

    expect(retrieveWorkflowMock).not.toHaveBeenCalled();
    expect(preparedContent).not.toContain("# Current Workflow");
  });

  test("uses live workflow content from the request instead of persisted workflow content", async () => {
    const agent = makeAgent();

    await agent.sendMessage("What is in this workflow?", {
      userToken: "user-token",
      workflowId: 123,
      workflowName: "Live Workflow",
      workflowContent: liveWorkflowContent,
    });

    expect(retrieveWorkflowMock).not.toHaveBeenCalled();
    expect(preparedContent).toContain("# Current Workflow");
    expect(preparedContent).toContain("### Operator `live-scan` (CSVFileScan, not-executed)");
    expect(preparedContent).toContain("fileName: live.csv");
    expect(preparedContent).not.toContain("fileName: data.csv");
  });
});
