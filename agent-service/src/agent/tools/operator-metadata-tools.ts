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

import { tool } from "ai";
import { z } from "zod";
import { createErrorResult, createToolResult } from "./tools-utility";
import type { WorkflowSystemMetadata } from "../util/workflow-system-metadata";

export const TOOL_NAME_LIST_OPERATOR_TYPES = "list_operator_types";
export const TOOL_NAME_GET_OPERATOR_DEFINITION = "get_operator_definition";

function availableTypes(metadataStore: WorkflowSystemMetadata): string {
  return Object.keys(metadataStore.getAllOperatorTypes()).join(", ");
}

export function createListOperatorTypesTool(metadataStore: WorkflowSystemMetadata) {
  return tool({
    description:
      "List the Texera operator type names available in the current backend metadata store. " +
      "Use a returned operator type with get_operator_definition before setting operator properties.",
    inputSchema: z.object({}),
    execute: async () => {
      return createToolResult(JSON.stringify({ operatorTypes: Object.keys(metadataStore.getAllOperatorTypes()) }));
    },
  });
}

export function createGetOperatorDefinitionTool(metadataStore: WorkflowSystemMetadata) {
  return tool({
    description:
      "Return the definition of one Texera operator type as defined by the system: its configuration property " +
      "schema and metadata (required fields, property details, and ports). This is the operator's static " +
      "definition from the backend metadata store — it is NOT an operator instance in the current workflow, and " +
      "NOT the input/output table (data) schema of an operator's results. Call this before addOperator or " +
      "modifyOperator whenever you need to set operator properties.",
    inputSchema: z.object({
      operatorType: z
        .string()
        .describe("Exact operator type name returned by list_operator_types, for example CSVFileScan."),
    }),
    execute: async ({ operatorType }: { operatorType: string }) => {
      const schema = metadataStore.getCompactSchema(operatorType);
      if (!schema) {
        return createErrorResult(
          `Unknown operator type: "${operatorType}". Available types: ${availableTypes(metadataStore)}`
        );
      }

      const additional = metadataStore.getAdditionalMetadata(operatorType) || {};
      return createToolResult(
        JSON.stringify(
          {
            operatorType,
            name: additional.userFriendlyName || operatorType,
            group: additional.operatorGroupName || "",
            description: metadataStore.getDescription(operatorType),
            schema,
          },
          null,
          2
        )
      );
    },
  });
}
