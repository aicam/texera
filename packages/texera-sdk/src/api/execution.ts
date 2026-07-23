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
import type { LogicalPlan } from "../types/workflow";
import type { SyncExecutionResult } from "../types/execution";

/**
 * Caps enforced server-side by `SyncExecutionResource` regardless of what the
 * request asks for. Mirrored here so callers can size their own requests and
 * explain the truncation instead of being surprised by it.
 */
export const MAX_OPERATOR_RESULT_CHARS = 100_000;
export const MAX_OPERATOR_RESULT_CELL_CHARS = 20_000;

export interface SyncExecutionRequest {
  executionName: string;
  logicalPlan: LogicalPlan;
  /**
   * "Execute to" semantics: with exactly one id, only that operator's upstream
   * sub-DAG runs. Empty means run everything.
   */
  targetOperatorIds?: string[];
  timeoutSeconds: number;
  maxOperatorResultCharLimit: number;
  maxOperatorResultCellCharLimit: number;
  workflowSettings?: { dataTransferBatchSize: number };
}

export interface RunWorkflowOptions {
  workflowId: number;
  computingUnitId: number;
  plan: LogicalPlan;
  executionName?: string;
  targetOperatorIds?: string[];
  timeoutSeconds?: number;
  maxOperatorResultCharLimit?: number;
  maxOperatorResultCellCharLimit?: number;
  signal?: AbortSignal;
}

/**
 * Runs a logical plan to completion and returns per-operator results, console
 * output and errors in one response (`POST /api/execution/{wid}/{cuid}/run`).
 *
 * The HTTP timeout is set past `timeoutSeconds` so the server's own timeout
 * wins and we get a structured result instead of an opaque client abort.
 */
export async function runWorkflowSync(client: TexeraClient, options: RunWorkflowOptions): Promise<SyncExecutionResult> {
  const timeoutSeconds = options.timeoutSeconds ?? 60;
  const request: SyncExecutionRequest = {
    executionName: options.executionName ?? "mcp-execution",
    logicalPlan: options.plan,
    targetOperatorIds: options.targetOperatorIds ?? [],
    timeoutSeconds,
    maxOperatorResultCharLimit: Math.min(
      options.maxOperatorResultCharLimit ?? MAX_OPERATOR_RESULT_CHARS,
      MAX_OPERATOR_RESULT_CHARS
    ),
    maxOperatorResultCellCharLimit: Math.min(
      options.maxOperatorResultCellCharLimit ?? MAX_OPERATOR_RESULT_CELL_CHARS,
      MAX_OPERATOR_RESULT_CELL_CHARS
    ),
  };

  return client.request<SyncExecutionResult>(
    "execution",
    `/api/execution/${options.workflowId}/${options.computingUnitId}/run`,
    {
      method: "POST",
      json: request,
      originOverride: client.executionEndpointFor(options.computingUnitId),
      timeoutMs: (timeoutSeconds + 30) * 1000,
      signal: options.signal,
    }
  );
}
