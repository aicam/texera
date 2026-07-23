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

import type { TexeraClient } from "../client";
import type { LogicalPlan, OperatorPortSchemaMap } from "../types/workflow";
import { createSdkLogger } from "../logger";

const log = createSdkLogger("CompileAPI");

export interface WorkflowFatalError {
  type: string;
  message: string;
  operatorId?: string;
}

export interface WorkflowCompilationResponse {
  physicalPlan?: any;
  operatorOutputSchemas: Record<string, OperatorPortSchemaMap>;
  operatorErrors: Record<string, WorkflowFatalError>;
}

/**
 * Type-checks a logical plan without running it (`POST /api/compile`), yielding
 * per-port output schemas and per-operator errors.
 *
 * Returns `null` rather than throwing when the compiling service is unreachable
 * or errors: compilation is an *enrichment* step for callers (better attribute
 * suggestions, earlier error messages), and losing it must not fail the
 * surrounding edit.
 */
export async function compileWorkflow(
  client: TexeraClient,
  logicalPlan: LogicalPlan
): Promise<WorkflowCompilationResponse | null> {
  try {
    return await client.request<WorkflowCompilationResponse>("compile", "/api/compile", {
      method: "POST",
      json: {
        operators: logicalPlan.operators,
        links: logicalPlan.links,
        opsToReuseResult: [],
        opsToViewResult: [],
      },
    });
  } catch (error) {
    log.warn({ err: error }, "compile workflow API error");
    return null;
  }
}

/** @deprecated Use {@link compileWorkflow}. */
export const compileWorkflowAsync = compileWorkflow;
