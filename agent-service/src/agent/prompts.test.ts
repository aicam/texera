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
import { buildSystemPrompt } from "./prompts";
import { WorkflowSystemMetadata } from "./util/workflow-system-metadata";

describe("buildSystemPrompt", () => {
  test("frames the assistant around DKNet-AI and includes the platform overview", () => {
    const prompt = buildSystemPrompt(new WorkflowSystemMetadata());
    const normalizedPrompt = prompt.toLowerCase();

    expect(prompt).toContain("You are DKNetAgent, the DKNet-AI assistant for dknet-ai.org");
    expect(prompt).toContain("Use DKNet-AI as the primary platform name");
    expect(prompt).toContain("Apache Texera is the underlying workflow/dataflow engine");
    expect(normalizedPrompt).toContain("on-demand computing resources");
    expect(normalizedPrompt).toContain("single-cell rna sequencing analysis");
    expect(prompt).toContain("CloudBioMapper");
    expect(prompt).toContain("## Platform Concepts and Data Analysis Workflow");
    expect(prompt).toContain("Click the Datasets tab");
    expect(prompt).toContain("Click Create Workflow");
    expect(prompt).toContain("operator menu");
    expect(normalizedPrompt).toContain("computing units");
    expect(normalizedPrompt).toContain("runtime environments");
    expect(prompt).toContain("READ or WRITE access");
    expect(prompt).not.toContain("You are a Texera Copilot");
  });

  test("instructs the agent to discover operator schemas with tools instead of embedding every schema", () => {
    const store = new WorkflowSystemMetadata();
    store.loadFromMetadata({
      operators: [
        {
          operatorType: "CSVFileScan",
          operatorVersion: "1",
          jsonSchema: {
            properties: { fileName: { type: "string" } },
            required: ["fileName"],
            definitions: {},
          },
          additionalMetadata: {
            userFriendlyName: "CSV File Scan",
            operatorGroupName: "Source",
            operatorDescription: "Read a CSV file",
            inputPorts: [],
            outputPorts: [{}],
          },
        },
      ],
      groups: [],
    });

    const prompt = buildSystemPrompt(store);

    expect(prompt).toContain("list_operator_types");
    expect(prompt).toContain("only the available operator type names");
    expect(prompt).toContain("get_operator_definition");
    expect(prompt).toContain("Use one of those exact operator type names");
    expect(prompt).not.toContain("## CSVFileScan");
    expect(prompt).not.toContain('"fileName"');
  });
});
