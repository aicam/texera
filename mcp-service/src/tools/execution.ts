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

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  createComputingUnit,
  getComputingUnitLimitOptions,
  getComputingUnitTypes,
  isComputingUnitReady,
  listComputingUnits,
  renameComputingUnit,
  runWorkflowSync,
  terminateComputingUnit,
  type DashboardWorkflowComputingUnit,
  type OperatorInfo,
  type SyncExecutionResult,
} from "@texera/sdk";
import type { McpContext } from "../context";
import { ToolError } from "../errors";
import { formatRecords, formatTable, formatTimestamp, joinSections } from "../format";
import { registerTool } from "../register";

/** Picks a running unit when the caller did not name one. */
async function resolveComputingUnit(
  context: McpContext,
  requested: number | undefined
): Promise<DashboardWorkflowComputingUnit> {
  const units = await listComputingUnits(context.client);

  if (requested !== undefined) {
    const match = units.find(unit => unit.computingUnit.cuid === requested);
    if (!match) {
      throw new ToolError(
        `No computing unit ${requested} is available to this account. ` +
          `computing_unit_list shows the ones you can use.`
      );
    }
    if (!isComputingUnitReady(match)) {
      throw new ToolError(
        `Computing unit ${requested} is "${match.status}", not Running. Wait for it to start, or pick another.`
      );
    }
    return match;
  }

  const ready = units.filter(isComputingUnitReady);
  if (ready.length === 0) {
    throw new ToolError(
      units.length === 0
        ? "You have no computing units. A workflow needs one to run — create it with computing_unit_create."
        : `None of your ${units.length} computing unit(s) is Running (${units.map(unit => `${unit.computingUnit.cuid}: ${unit.status}`).join(", ")}). ` +
            `Wait for one to start, or create another with computing_unit_create.`
    );
  }
  return ready[0];
}

function formatOperatorOutcome(operatorId: string, info: OperatorInfo, maxChars: number): string {
  const header = `${operatorId} — ${info.state}, ${info.outputTuples ?? 0} output row(s)`;

  if (info.error) {
    return joinSections(header, `ERROR: ${info.error}`);
  }

  const sections: string[] = [header];
  if (Array.isArray(info.result) && info.result.length > 0) {
    const total = info.totalRowCount ?? info.result.length;
    sections.push(
      `Result (showing ${Math.min(info.result.length, 20)} of ${total} row(s)):\n` +
        formatRecords(info.result, { maxRows: 20, maxChars })
    );
  }
  if (info.warnings && info.warnings.length > 0) {
    sections.push(`Warnings:\n${info.warnings.map(warning => `- ${warning}`).join("\n")}`);
  }
  const consoleLogs = (info.consoleLogs ?? []).filter(entry => entry.message?.trim());
  if (consoleLogs.length > 0) {
    sections.push(
      `Console output:\n${consoleLogs
        .slice(-10)
        .map(entry => `[${entry.msgType}] ${entry.message}`)
        .join("\n")}`
    );
  }
  return joinSections(...sections);
}

function formatRunResult(result: SyncExecutionResult, targets: string[], maxChars: number): string {
  const compilationErrors = Object.entries(result.compilationErrors ?? {});
  if (compilationErrors.length > 0) {
    return joinSections(
      `Execution did not start — the workflow failed to compile (state ${result.state}).`,
      compilationErrors.map(([operatorId, message]) => `- ${operatorId}: ${message}`).join("\n"),
      "Fix the operators above, then run again. workflow_validate catches most of these without an execution."
    );
  }

  const operatorEntries = Object.entries(result.operators ?? {});
  const failing = operatorEntries.filter(([, info]) => info.error);

  if (result.state === "Killed") {
    return joinSections(
      "Execution was killed — it exceeded the timeout.",
      "Raise timeout_seconds, narrow the run with target_operator_id, or reduce the data volume."
    );
  }

  if (!result.success && failing.length === 0 && (result.errors ?? []).length > 0) {
    return joinSections(
      `Execution failed (state ${result.state}):`,
      (result.errors ?? []).map(error => `- ${error}`).join("\n")
    );
  }

  // Show the requested operators, or everything when nothing specific was asked for.
  const shown = targets.length > 0 ? operatorEntries.filter(([id]) => targets.includes(id)) : operatorEntries;
  const perOperator = shown.map(([id, info]) =>
    formatOperatorOutcome(id, info, Math.floor(maxChars / Math.max(1, shown.length)))
  );

  return joinSections(
    `Execution ${result.success ? "succeeded" : "finished with errors"} (state ${result.state}).`,
    ...perOperator,
    result.errors && result.errors.length > 0
      ? `Other errors:\n${result.errors.map(error => `- ${error}`).join("\n")}`
      : undefined
  );
}

export function registerExecutionTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "computing_unit_list",
    title: "List computing units",
    description:
      "List the computing units this account can run workflows on, with status and resource usage. " +
      "A workflow needs a Running unit to execute.",
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (_args, ctx) => {
      const units = await listComputingUnits(ctx.client);
      if (units.length === 0) {
        return "No computing units. Create one with computing_unit_create before running a workflow.";
      }
      return joinSections(
        `${units.length} computing unit(s):`,
        formatTable(
          ["cuid", "name", "status", "type", "owner", "cpu", "memory", "created"],
          units.map(unit => [
            unit.computingUnit.cuid,
            unit.computingUnit.name,
            unit.status,
            unit.computingUnit.type ?? "",
            unit.isOwner ? "you" : (unit.ownerName ?? unit.accessPrivilege),
            unit.metrics?.cpuUsage ?? "",
            unit.metrics?.memoryUsage ?? "",
            formatTimestamp(unit.computingUnit.creationTime),
          ])
        )
      );
    },
  });

  registerTool(server, context, {
    name: "computing_unit_create",
    title: "Start a computing unit",
    description:
      "Start a computing unit to run workflows on. Resource values must come from the deployment's allowed " +
      "list — call this without cpu/memory to see the options. On Kubernetes the unit is a pod and may take " +
      "a minute to become Running. On a single-node/local deployment the engine already runs, so pass uri " +
      "to point the unit at it.",
    inputSchema: {
      name: z.string().min(1).describe("Name for the unit"),
      cpu: z.string().optional().describe('CPU limit from the allowed list, e.g. "1"'),
      memory: z.string().optional().describe('Memory limit from the allowed list, e.g. "2Gi"'),
      gpu: z.string().optional().describe('GPU limit from the allowed list, e.g. "0"'),
      unit_type: z
        .string()
        .optional()
        .describe('Unit type, e.g. "kubernetes" or "local". Defaults to the first supported type.'),
      uri: z
        .string()
        .optional()
        .describe('Required for "local" units: URL of the already-running engine, e.g. "http://localhost:8085".'),
    },
    handler: async (
      args: { name: string; cpu?: string; memory?: string; gpu?: string; unit_type?: string; uri?: string },
      ctx
    ) => {
      const [limits, types] = await Promise.all([
        getComputingUnitLimitOptions(ctx.client),
        getComputingUnitTypes(ctx.client),
      ]);

      const unitType = args.unit_type ?? types.typeOptions[0];
      if (!unitType) {
        throw new ToolError("This deployment reports no supported computing-unit types.");
      }
      if (!types.typeOptions.includes(unitType)) {
        throw new ToolError(`Unit type "${unitType}" is not supported here. Options: ${types.typeOptions.join(", ")}.`);
      }

      // A "local" unit attaches to an engine that is already running rather than
      // spawning a pod, so the backend requires a URL to reach it.
      if (unitType === "local" && (args.uri === undefined || args.uri.trim() === "")) {
        throw new ToolError(
          'A "local" computing unit needs uri set to the running engine, e.g. "http://localhost:8085". ' +
            "Kubernetes units spawn a pod and need no uri."
        );
      }

      const cpu = args.cpu ?? limits.cpuLimitOptions[0];
      const memory = args.memory ?? limits.memoryLimitOptions[0];
      const gpu = args.gpu ?? limits.gpuLimitOptions[0];

      for (const [label, value, allowed] of [
        ["cpu", cpu, limits.cpuLimitOptions],
        ["memory", memory, limits.memoryLimitOptions],
        ["gpu", gpu, limits.gpuLimitOptions],
      ] as const) {
        if (!allowed.includes(value)) {
          throw new ToolError(`${label} "${value}" is not allowed here. Options: ${allowed.join(", ")}.`);
        }
      }

      const created = await createComputingUnit(ctx.client, {
        name: args.name,
        unitType,
        cpuLimit: cpu,
        memoryLimit: memory,
        gpuLimit: gpu,
        // Give the JVM most of the container, leaving headroom for off-heap use.
        jvmMemorySize: memory,
        shmSize: "64Mi",
        ...(args.uri !== undefined ? { uri: args.uri } : {}),
      });

      return (
        `Started computing unit ${created.computingUnit.cuid} "${created.computingUnit.name}" ` +
        `(${unitType}, cpu ${cpu}, memory ${memory}) — status ${created.status}.\n` +
        `Check computing_unit_list until it reads Running, then use it with workflow_run.`
      );
    },
  });

  registerTool(server, context, {
    name: "computing_unit_terminate",
    title: "Terminate a computing unit",
    description:
      "Shut down a computing unit and release its resources. Any execution running on it is stopped. " +
      "Requires confirm_name to match the unit's name.",
    inputSchema: {
      cuid: z.number().int().describe("Computing unit id"),
      confirm_name: z.string().describe("The unit's exact current name, as a confirmation"),
    },
    annotations: { destructiveHint: true },
    handler: async (args: { cuid: number; confirm_name: string }, ctx) => {
      const units = await listComputingUnits(ctx.client);
      const unit = units.find(candidate => candidate.computingUnit.cuid === args.cuid);
      if (!unit) {
        throw new ToolError(`No computing unit ${args.cuid} is available to this account.`);
      }
      if (args.confirm_name !== unit.computingUnit.name) {
        throw new ToolError(
          `Refusing to terminate unit ${args.cuid}: confirm_name must match its name exactly. ` +
            `Expected "${unit.computingUnit.name}", got "${args.confirm_name}".`
        );
      }
      await terminateComputingUnit(ctx.client, args.cuid);
      return `Terminated computing unit ${args.cuid} "${unit.computingUnit.name}".`;
    },
  });

  registerTool(server, context, {
    name: "computing_unit_rename",
    title: "Rename a computing unit",
    description:
      "Change a computing unit's display name. Cosmetic only — the unit keeps running and its id is unchanged.",
    inputSchema: {
      cuid: z.number().int().describe("Computing unit id"),
      name: z.string().min(1).describe("New name"),
    },
    handler: async (args: { cuid: number; name: string }, ctx) => {
      await renameComputingUnit(ctx.client, args.cuid, args.name);
      return `Renamed computing unit ${args.cuid} to "${args.name}".`;
    },
  });

  registerTool(server, context, {
    name: "workflow_run",
    title: "Run the open workflow and return results",
    description:
      "Run a workflow to completion on a computing unit and return each operator's results, row counts, " +
      "console output and errors. Runs the in-memory graph of the open editing session, so unsaved edits " +
      "are executed as-is — you do not have to save first. " +
      "Pass target_operator_id to run only that operator's upstream sub-graph, which is much faster when " +
      "iterating on one step. Run workflow_validate first: it catches most failures without spending an execution.",
    inputSchema: {
      wid: z
        .number()
        .int()
        .optional()
        .describe("Workflow id. Defaults to the workflow most recently opened in this session."),
      computing_unit_id: z
        .number()
        .int()
        .optional()
        .describe("Computing unit to run on. Defaults to any Running unit this account can use."),
      target_operator_id: z
        .string()
        .optional()
        .describe("Run only this operator and everything upstream of it, and show its result."),
      timeout_seconds: z.number().int().positive().optional().describe("Wall-clock budget for the run"),
    },
    handler: async (
      args: { wid?: number; computing_unit_id?: number; target_operator_id?: string; timeout_seconds?: number },
      ctx
    ) => {
      const session = ctx.sessions.require(args.wid);
      const operators = session.state.getAllEnabledOperators();
      if (operators.length === 0) {
        throw new ToolError(`Workflow ${session.wid} is empty — add operators before running it.`);
      }

      if (args.target_operator_id && !session.state.getOperator(args.target_operator_id)) {
        throw new ToolError(
          `Workflow ${session.wid} has no operator "${args.target_operator_id}". ` +
            `Its operators are: ${operators.map(operator => operator.operatorID).join(", ")}.`
        );
      }

      const unit = await resolveComputingUnit(ctx, args.computing_unit_id);
      const targets = args.target_operator_id ? [args.target_operator_id] : [];
      const plan = session.state.toLogicalPlan(args.target_operator_id);

      const result = await runWorkflowSync(ctx.client, {
        workflowId: session.wid,
        computingUnitId: unit.computingUnit.cuid,
        plan,
        executionName: `mcp-${new Date().toISOString().slice(0, 19)}`,
        targetOperatorIds: targets,
        timeoutSeconds: args.timeout_seconds ?? ctx.config.defaultRunTimeoutSeconds,
      });

      return joinSections(
        `Ran workflow ${session.wid} "${session.name}" on computing unit ${unit.computingUnit.cuid}` +
          `${args.target_operator_id ? ` (up to ${args.target_operator_id})` : ""}${session.dirty ? ", including unsaved edits" : ""}.`,
        formatRunResult(result, targets, ctx.config.maxResultChars)
      );
    },
  });
}
