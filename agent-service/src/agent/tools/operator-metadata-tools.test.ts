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
import { WorkflowSystemMetadata } from "../util/workflow-system-metadata";
import { createGetOperatorDefinitionTool, createListOperatorTypesTool } from "./operator-metadata-tools";

function metadataStore(): WorkflowSystemMetadata {
  const store = new WorkflowSystemMetadata();
  store.loadFromMetadata({
    operators: [
      {
        operatorType: "CSVFileScan",
        operatorVersion: "1",
        jsonSchema: {
          properties: {
            fileName: {
              type: "string",
              description: "CSV path",
              propertyOrder: 1,
            },
            dummyPropertyList: { type: "array" },
          },
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
      {
        operatorType: "Filter",
        operatorVersion: "1",
        jsonSchema: {
          properties: {
            predicates: { type: "array" },
          },
          required: ["predicates"],
          definitions: {},
        },
        additionalMetadata: {
          userFriendlyName: "Filter",
          operatorGroupName: "Core",
          operatorDescription: "Keep matching rows",
          inputPorts: [{}],
          outputPorts: [{}],
        },
      },
    ],
    groups: [],
  });
  return store;
}

describe("operator metadata tools", () => {
  test("list_operator_types returns all metadata-backed operator types", async () => {
    const result = await (createListOperatorTypesTool(metadataStore()) as any).execute({});
    const parsed = JSON.parse(result);

    expect(parsed).toEqual({ operatorTypes: ["CSVFileScan", "Filter"] });
    expect(result).not.toContain("Read a CSV file");
    expect(result).not.toContain("Source");
  });

  test("get_operator_definition returns the trimmed compact schema for one operator", async () => {
    const result = await (createGetOperatorDefinitionTool(metadataStore()) as any).execute({
      operatorType: "CSVFileScan",
    });
    const parsed = JSON.parse(result);

    expect(parsed.operatorType).toBe("CSVFileScan");
    expect(parsed.schema).toEqual({
      properties: {
        fileName: {
          type: "string",
          description: "CSV path",
        },
      },
      required: ["fileName"],
    });
    expect(JSON.stringify(parsed.schema)).not.toContain("dummyPropertyList");
    expect(JSON.stringify(parsed.schema)).not.toContain("propertyOrder");
  });

  test("get_operator_definition reports unknown operator types", async () => {
    const result = await (createGetOperatorDefinitionTool(metadataStore()) as any).execute({
      operatorType: "Missing",
    });

    expect(result).toContain("[ERROR] Unknown operator type");
    expect(result).toContain("CSVFileScan");
    expect(result).toContain("Filter");
  });
});
