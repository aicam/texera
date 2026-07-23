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
  autoLayoutWorkflow,
  compileWorkflow,
  formatValidationErrors,
  parseWorkflowContent,
  persistWorkflow,
  retrieveWorkflowWithPrivilege,
  WorkflowUtilService,
  type OperatorLink,
  type OperatorPredicate,
  type WorkflowSystemMetadata,
} from "@texera/sdk";
import type { McpContext } from "../context";
import { ToolError } from "../errors";
import { formatTable, joinSections } from "../format";
import { registerTool } from "../register";
import type { EditSession } from "../session";
import { suggestOperatorTypes } from "./operator";

const widArg = z
  .number()
  .int()
  .optional()
  .describe("Workflow id. Defaults to the workflow most recently opened in this session.");

/** Ports are addressed by ordinal in the tools and by id in the stored graph. */
function portIdAt(operator: OperatorPredicate, kind: "input" | "output", ordinal: number): string {
  const ports = kind === "input" ? operator.inputPorts : operator.outputPorts;
  if (ordinal < 0 || ordinal >= ports.length) {
    throw new ToolError(
      `Operator "${operator.operatorID}" (${operator.operatorType}) has ${ports.length} ${kind} port(s), ` +
        `so ${kind} port ${ordinal} does not exist.` +
        (ports.length === 0 && kind === "input"
          ? " This is a source operator — it reads data rather than receiving it."
          : "")
    );
  }
  return ports[ordinal].portID;
}

function portOrdinal(operator: OperatorPredicate | undefined, kind: "input" | "output", portId: string): number {
  if (!operator) return 0;
  const ports = kind === "input" ? operator.inputPorts : operator.outputPorts;
  const index = ports.findIndex(port => port.portID === portId);
  return index >= 0 ? index : 0;
}

function requireOperator(session: EditSession, operatorId: string): OperatorPredicate {
  const operator = session.state.getOperator(operatorId);
  if (!operator) {
    const existing = session.state.getAllOperators().map(op => op.operatorID);
    throw new ToolError(
      `Workflow ${session.wid} has no operator "${operatorId}". ` +
        (existing.length > 0 ? `It has: ${existing.join(", ")}.` : "It has no operators yet.")
    );
  }
  return operator;
}

/** Renders the graph as text: node list plus edge list, which is what a model reasons over. */
export function describeWorkflow(session: EditSession): string {
  const operators = session.state.getAllOperators();
  const links = session.state.getAllLinks();

  const header =
    `Workflow ${session.wid} "${session.name}"` +
    `${session.readonly ? " (read-only)" : ""}` +
    `${session.dirty ? " — UNSAVED CHANGES" : ""}`;

  if (operators.length === 0) {
    return joinSections(header, "The workflow is empty. Add a source operator first (one with no input ports).");
  }

  const operatorTable = formatTable(
    ["id", "type", "label", "in/out ports", "properties"],
    operators.map(operator => [
      operator.operatorID,
      operator.operatorType,
      operator.customDisplayName ?? "",
      `${operator.inputPorts.length}/${operator.outputPorts.length}`,
      summarizeProperties(operator.operatorProperties),
    ])
  );

  const linkTable =
    links.length === 0
      ? "(no links — the operators are not connected)"
      : formatTable(
          ["from", "to"],
          links.map(link => {
            const source = session.state.getOperator(link.source.operatorID);
            const target = session.state.getOperator(link.target.operatorID);
            return [
              `${link.source.operatorID}:out${portOrdinal(source, "output", link.source.portID)}`,
              `${link.target.operatorID}:in${portOrdinal(target, "input", link.target.portID)}`,
            ];
          })
        );

  return joinSections(header, `Operators (${operators.length}):`, operatorTable, `Links (${links.length}):`, linkTable);
}

function summarizeProperties(properties: Record<string, unknown>): string {
  const entries = Object.entries(properties).filter(
    ([, value]) => value !== undefined && value !== null && value !== ""
  );
  if (entries.length === 0) return "(none)";
  const rendered = entries
    .slice(0, 4)
    .map(([key, value]) => `${key}=${typeof value === "object" ? JSON.stringify(value) : String(value)}`)
    .join(", ");
  const text = entries.length > 4 ? `${rendered}, …` : rendered;
  return text.length > 110 ? `${text.slice(0, 107)}…` : text;
}

/**
 * Validates properties against the operator's JSON Schema before mutating, so
 * the model gets a precise, fixable message instead of a failure several steps
 * later at compile or run time.
 */
function assertPropertiesValid(
  metadata: WorkflowSystemMetadata,
  operatorType: string,
  properties: Record<string, unknown>
): void {
  const validation = metadata.validateOperatorProperties(operatorType, properties);
  if (validation.isValid) return;
  const compact = metadata.getCompactSchema(operatorType);
  throw new ToolError(
    `Invalid properties for ${operatorType}: ${formatValidationErrors(validation)}.` +
      (compact
        ? ` Required: [${compact.required.join(", ")}]. Call operator_get_schema("${operatorType}") for the full schema.`
        : "")
  );
}

/** Connects `sourceOperatorIds` into `target`'s input ports, replacing existing incoming links. */
function relinkInputs(
  session: EditSession,
  target: OperatorPredicate,
  inputs: Record<string, string[]>
): { created: string[]; removed: string[] } {
  const removed: string[] = [];
  for (const link of session.state.getAllLinks()) {
    if (link.target.operatorID === target.operatorID) {
      session.state.deleteLink(link.linkID);
      removed.push(`${link.source.operatorID} -> ${target.operatorID}`);
    }
  }

  const created: string[] = [];
  for (const [ordinalText, sourceIds] of Object.entries(inputs)) {
    const ordinal = Number(ordinalText);
    if (!Number.isInteger(ordinal) || ordinal < 0) {
      throw new ToolError(`Input port key "${ordinalText}" must be a non-negative integer port ordinal, e.g. "0".`);
    }
    const targetPortId = portIdAt(target, "input", ordinal);
    for (const sourceId of sourceIds) {
      const source = requireOperator(session, sourceId);
      if (source.outputPorts.length === 0) {
        throw new ToolError(
          `Operator "${sourceId}" (${source.operatorType}) has no output ports, so nothing can read from it.`
        );
      }
      const link: OperatorLink = {
        linkID: session.state.generateLinkId(),
        source: { operatorID: sourceId, portID: source.outputPorts[0].portID },
        target: { operatorID: target.operatorID, portID: targetPortId },
      };
      session.state.addLink(link);
      created.push(`${sourceId} -> ${target.operatorID}:in${ordinal}`);
    }
  }
  return { created, removed };
}

const inputsArg = z
  .record(z.array(z.string()))
  .optional()
  .describe(
    'Incoming connections, keyed by input port ordinal: {"0": ["op1"], "1": ["op2"]}. ' +
      "Replaces all existing incoming links on this operator. Source operators (file scans) take none."
  );

export function registerWorkflowEditTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "workflow_open",
    title: "Open a workflow for editing",
    description:
      "Load a workflow's operator graph into this session and show it. All the editing tools act on the " +
      "open workflow and keep changes in memory until workflow_save writes them back. " +
      "Opening also records the workflow's last-modified time so a later save can detect concurrent edits.",
    inputSchema: { wid: z.number().int().describe("Workflow id, from workflow_list") },
    annotations: { readOnlyHint: true },
    handler: async (args: { wid: number }, ctx) => {
      const fetched = await retrieveWorkflowWithPrivilege(ctx.client, args.wid);
      const session = ctx.sessions.open(
        {
          wid: fetched.wid,
          name: fetched.name,
          description: fetched.description,
          content: parseWorkflowContent(fetched.content),
          lastModifiedTime: fetched.lastModifiedTime,
          isPublic: fetched.isPublished,
        },
        fetched.readonly
      );
      return joinSections(
        describeWorkflow(session),
        fetched.readonly
          ? "You have read-only access. Edits will be rejected; use workflow_duplicate for an editable copy."
          : undefined
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_describe",
    title: "Show the open workflow's graph",
    description:
      "Show the operators, their properties and the links of the workflow currently open for editing, " +
      "including any unsaved changes. Use this to re-orient before or after a series of edits.",
    inputSchema: { wid: widArg },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { wid?: number }, ctx) => describeWorkflow(ctx.sessions.require(args.wid)),
  });

  registerTool(server, context, {
    name: "workflow_add_operator",
    title: "Add an operator to the open workflow",
    description:
      "Add one operator and optionally connect its inputs. Call operator_get_schema for the type first — " +
      "properties are validated against its JSON Schema and a mismatch is rejected here rather than at run time. " +
      "The change stays in memory until workflow_save.",
    inputSchema: {
      operator_type: z.string().min(1).describe('Operator type, e.g. "CSVFileScan". See operator_list_types.'),
      operator_id: z.string().optional().describe("Id for the new operator. Generated from the type when omitted."),
      properties: z
        .record(z.any())
        .optional()
        .describe("Property values, matching operator_get_schema. Schema defaults fill in the rest."),
      inputs: inputsArg,
      label: z.string().optional().describe("Short display label shown on the canvas"),
      wid: widArg,
    },
    handler: async (
      args: {
        operator_type: string;
        operator_id?: string;
        properties?: Record<string, unknown>;
        inputs?: Record<string, string[]>;
        label?: string;
        wid?: number;
      },
      ctx
    ) => {
      const session = ctx.sessions.requireWritable(args.wid);
      const metadata = await ctx.operatorMetadata();

      if (!metadata.operatorTypeExists(args.operator_type)) {
        const suggestions = suggestOperatorTypes(args.operator_type, Object.keys(metadata.getAllOperatorTypes()));
        throw new ToolError(
          `No operator type "${args.operator_type}" on this deployment.` +
            (suggestions.length > 0 ? ` Did you mean: ${suggestions.join(", ")}?` : "") +
            ` Use operator_list_types to browse.`
        );
      }
      if (args.operator_id && session.state.getOperator(args.operator_id)) {
        throw new ToolError(
          `Workflow ${session.wid} already has an operator "${args.operator_id}". ` +
            `Use workflow_modify_operator to change it, or pick a different id.`
        );
      }

      const util = new WorkflowUtilService(metadata, session.state);
      const base = util.getNewOperatorPredicate(args.operator_type, args.label);
      // Schema defaults come from getNewOperatorPredicate; caller values win.
      const properties = { ...base.operatorProperties, ...(args.properties ?? {}) };
      assertPropertiesValid(metadata, args.operator_type, properties);

      const operator: OperatorPredicate = {
        ...base,
        operatorID: args.operator_id ?? base.operatorID,
        operatorProperties: properties,
      };
      session.state.addOperator(operator);

      let linkSummary = "";
      if (args.inputs && Object.keys(args.inputs).length > 0) {
        const { created } = relinkInputs(session, operator, args.inputs);
        linkSummary = created.length > 0 ? `\nConnected: ${created.join(", ")}` : "";
      }

      autoLayoutWorkflow(session.state);
      session.dirty = true;

      return (
        `Added ${operator.operatorID} (${operator.operatorType}) with ` +
        `${operator.inputPorts.length} input and ${operator.outputPorts.length} output port(s).${linkSummary}\n` +
        `Unsaved — call workflow_save to persist.`
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_modify_operator",
    title: "Change an operator's properties or connections",
    description:
      "Update an existing operator's properties, its display label, and/or its incoming links. Properties " +
      "are merged with the existing ones and validated against the operator's schema. Passing `inputs` " +
      "replaces every existing incoming link on that operator.",
    inputSchema: {
      operator_id: z.string().min(1).describe("Id of the operator to change"),
      properties: z.record(z.any()).optional().describe("Properties to merge into the existing ones"),
      inputs: inputsArg,
      label: z.string().optional().describe("New display label"),
      wid: widArg,
    },
    handler: async (
      args: {
        operator_id: string;
        properties?: Record<string, unknown>;
        inputs?: Record<string, string[]>;
        label?: string;
        wid?: number;
      },
      ctx
    ) => {
      const session = ctx.sessions.requireWritable(args.wid);
      const operator = requireOperator(session, args.operator_id);
      const changes: string[] = [];

      if (args.properties) {
        const metadata = await ctx.operatorMetadata();
        const merged = { ...operator.operatorProperties, ...args.properties };
        assertPropertiesValid(metadata, operator.operatorType, merged);
        session.state.updateOperatorProperties(args.operator_id, args.properties);
        changes.push(`properties updated (${Object.keys(args.properties).join(", ")})`);
      }

      if (args.label !== undefined) {
        session.state.updateOperatorDisplayName(args.operator_id, args.label);
        changes.push(`label -> "${args.label}"`);
      }

      if (args.inputs) {
        const { created, removed } = relinkInputs(session, operator, args.inputs);
        if (removed.length > 0) changes.push(`removed links: ${removed.join(", ")}`);
        if (created.length > 0) changes.push(`added links: ${created.join(", ")}`);
        autoLayoutWorkflow(session.state);
      }

      if (changes.length === 0) {
        throw new ToolError("Nothing to change — pass at least one of properties, inputs, label.");
      }

      session.dirty = true;
      return `${args.operator_id}: ${changes.join("; ")}.\nUnsaved — call workflow_save to persist.`;
    },
  });

  registerTool(server, context, {
    name: "workflow_delete_operator",
    title: "Delete an operator from the open workflow",
    description:
      "Remove an operator and every link attached to it. The change stays in memory until workflow_save, " +
      "so it can be abandoned with workflow_discard.",
    inputSchema: {
      operator_id: z.string().min(1).describe("Id of the operator to delete"),
      wid: widArg,
    },
    annotations: { destructiveHint: true },
    handler: async (args: { operator_id: string; wid?: number }, ctx) => {
      const session = ctx.sessions.requireWritable(args.wid);
      requireOperator(session, args.operator_id);
      const attached = session.state.getLinksConnectedToOperator(args.operator_id).length;
      session.state.deleteOperator(args.operator_id);
      session.dirty = true;
      return (
        `Deleted ${args.operator_id} and ${attached} attached link(s).\n` +
        `Unsaved — call workflow_save to persist, or workflow_discard to abandon.`
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_add_link",
    title: "Connect two operators",
    description:
      "Connect one operator's output port to another's input port. Ports are addressed by ordinal " +
      "(0-based); operator_get_schema shows how many each type has.",
    inputSchema: {
      from_operator_id: z.string().min(1).describe("Source operator id"),
      to_operator_id: z.string().min(1).describe("Target operator id"),
      from_port: z.number().int().min(0).optional().describe("Source output port ordinal. Defaults to 0."),
      to_port: z.number().int().min(0).optional().describe("Target input port ordinal. Defaults to 0."),
      wid: widArg,
    },
    handler: async (
      args: { from_operator_id: string; to_operator_id: string; from_port?: number; to_port?: number; wid?: number },
      ctx
    ) => {
      const session = ctx.sessions.requireWritable(args.wid);
      const source = requireOperator(session, args.from_operator_id);
      const target = requireOperator(session, args.to_operator_id);
      const fromPortId = portIdAt(source, "output", args.from_port ?? 0);
      const toPortId = portIdAt(target, "input", args.to_port ?? 0);

      const duplicate = session.state
        .getAllLinks()
        .find(
          link =>
            link.source.operatorID === source.operatorID &&
            link.source.portID === fromPortId &&
            link.target.operatorID === target.operatorID &&
            link.target.portID === toPortId
        );
      if (duplicate) {
        return `${args.from_operator_id} is already connected to ${args.to_operator_id} on those ports; nothing to do.`;
      }

      session.state.addLink({
        linkID: session.state.generateLinkId(),
        source: { operatorID: source.operatorID, portID: fromPortId },
        target: { operatorID: target.operatorID, portID: toPortId },
      });
      autoLayoutWorkflow(session.state);
      session.dirty = true;

      return (
        `Connected ${args.from_operator_id}:out${args.from_port ?? 0} -> ${args.to_operator_id}:in${args.to_port ?? 0}.\n` +
        `Unsaved — call workflow_save to persist.`
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_delete_link",
    title: "Disconnect two operators",
    description: "Remove the link between two operators. Ports default to 0, matching workflow_add_link.",
    inputSchema: {
      from_operator_id: z.string().min(1).describe("Source operator id"),
      to_operator_id: z.string().min(1).describe("Target operator id"),
      from_port: z.number().int().min(0).optional().describe("Source output port ordinal. Defaults to 0."),
      to_port: z.number().int().min(0).optional().describe("Target input port ordinal. Defaults to 0."),
      wid: widArg,
    },
    annotations: { destructiveHint: true },
    handler: async (
      args: { from_operator_id: string; to_operator_id: string; from_port?: number; to_port?: number; wid?: number },
      ctx
    ) => {
      const session = ctx.sessions.requireWritable(args.wid);
      const source = requireOperator(session, args.from_operator_id);
      const target = requireOperator(session, args.to_operator_id);
      const fromPortId = portIdAt(source, "output", args.from_port ?? 0);
      const toPortId = portIdAt(target, "input", args.to_port ?? 0);

      const link = session.state
        .getAllLinks()
        .find(
          candidate =>
            candidate.source.operatorID === source.operatorID &&
            candidate.source.portID === fromPortId &&
            candidate.target.operatorID === target.operatorID &&
            candidate.target.portID === toPortId
        );
      if (!link) {
        throw new ToolError(
          `No link from ${args.from_operator_id}:out${args.from_port ?? 0} to ${args.to_operator_id}:in${args.to_port ?? 0}. ` +
            `Call workflow_describe to see the current links.`
        );
      }

      session.state.deleteLink(link.linkID);
      session.dirty = true;
      return `Disconnected ${args.from_operator_id} from ${args.to_operator_id}.\nUnsaved — call workflow_save to persist.`;
    },
  });

  registerTool(server, context, {
    name: "workflow_auto_layout",
    title: "Tidy the workflow's canvas layout",
    description:
      "Re-position operators into a clean left-to-right layout. Cosmetic only — it does not change the " +
      "graph. The editing tools do this automatically, so it is rarely needed on its own.",
    inputSchema: { wid: widArg },
    handler: async (args: { wid?: number }, ctx) => {
      const session = ctx.sessions.requireWritable(args.wid);
      autoLayoutWorkflow(session.state);
      session.dirty = true;
      return `Re-laid out ${session.state.getAllOperators().length} operator(s). Unsaved — call workflow_save to persist.`;
    },
  });

  registerTool(server, context, {
    name: "workflow_validate",
    title: "Check the open workflow for errors",
    description:
      "Type-check the workflow without running it: verifies operator properties, checks that required " +
      "input ports are connected, and compiles the graph on the deployment to surface schema mismatches " +
      "and per-operator errors. Run this before workflow_run — it is much cheaper than a failed execution.",
    inputSchema: { wid: widArg },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { wid?: number }, ctx) => {
      const session = ctx.sessions.require(args.wid);
      const metadata = await ctx.operatorMetadata();
      const operators = session.state.getAllEnabledOperators();

      if (operators.length === 0) {
        return `Workflow ${session.wid} is empty — nothing to validate.`;
      }

      const problems: string[] = [];

      for (const operator of operators) {
        const validation = metadata.validateOperatorProperties(operator.operatorType, operator.operatorProperties);
        if (!validation.isValid) {
          problems.push(`${operator.operatorID} (${operator.operatorType}): ${formatValidationErrors(validation)}`);
        }

        // Every declared input port must actually be fed, or the operator will
        // stall at run time rather than fail fast.
        const incomingByPort = new Map<string, number>();
        for (const link of session.state.getAllLinks()) {
          if (link.target.operatorID === operator.operatorID) {
            incomingByPort.set(link.target.portID, (incomingByPort.get(link.target.portID) ?? 0) + 1);
          }
        }
        for (const port of operator.inputPorts) {
          const count = incomingByPort.get(port.portID) ?? 0;
          if (count === 0) {
            problems.push(
              `${operator.operatorID} (${operator.operatorType}): input port "${port.displayName || port.portID}" has no incoming link`
            );
          } else if (port.disallowMultiInputs && count > 1) {
            problems.push(
              `${operator.operatorID}: input port "${port.displayName || port.portID}" accepts one link but has ${count}`
            );
          }
        }
      }

      const compilation = await compileWorkflow(ctx.client, session.state.toLogicalPlan());
      if (compilation) {
        for (const [operatorId, error] of Object.entries(compilation.operatorErrors ?? {})) {
          problems.push(`${operatorId}: ${error.message}`);
        }
      }

      const schemaSection = compilation
        ? summarizeOutputSchemas(compilation.operatorOutputSchemas ?? {})
        : "The compiling service could not be reached, so attribute schemas were not checked.";

      if (problems.length === 0) {
        return joinSections(`Workflow ${session.wid} validates cleanly.`, schemaSection);
      }
      return joinSections(
        `Workflow ${session.wid} has ${problems.length} problem(s):`,
        problems.map(problem => `- ${problem}`).join("\n"),
        schemaSection
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_save",
    title: "Save the open workflow",
    description:
      "Write the in-memory edits back to the deployment, creating a version snapshot. " +
      "Refuses if the workflow changed on the server since it was opened — that means someone else, or " +
      "the user's own open browser tab, has saved in the meantime and a blind write would discard their " +
      "work. Re-open and redo the edits, or pass force to overwrite deliberately.",
    inputSchema: {
      wid: widArg,
      force: z
        .boolean()
        .optional()
        .describe("Overwrite even if the workflow changed on the server since it was opened. Discards those changes."),
    },
    handler: async (args: { wid?: number; force?: boolean }, ctx) => {
      const session = ctx.sessions.requireWritable(args.wid);

      if (!session.dirty && !args.force) {
        return `Workflow ${session.wid} has no unsaved changes.`;
      }

      const current = await retrieveWorkflowWithPrivilege(ctx.client, session.wid);
      const drifted =
        session.openedLastModifiedTime !== undefined &&
        current.lastModifiedTime !== undefined &&
        current.lastModifiedTime !== session.openedLastModifiedTime;

      if (drifted && !args.force) {
        throw new ToolError(
          `Workflow ${session.wid} was modified on the server after you opened it ` +
            `(server copy last modified ${new Date(current.lastModifiedTime).toISOString()}). ` +
            `Saving now would discard that change. Someone else may be editing it, or the user may have it ` +
            `open in a browser tab — Texera's editor saves from the browser. ` +
            `Ask the user to close the tab, then workflow_open(${session.wid}) again and redo the edits; ` +
            `or call workflow_save with force=true to overwrite deliberately.`
        );
      }

      const saved = await persistWorkflow(ctx.client, {
        wid: session.wid,
        name: session.name,
        description: session.description,
        content: session.state.getWorkflowContent(),
        isPublic: session.isPublic,
      });

      ctx.sessions.markSaved(session, saved.lastModifiedTime);

      return (
        `Saved workflow ${session.wid} "${session.name}" — ` +
        `${session.state.getAllOperators().length} operator(s), ${session.state.getAllLinks().length} link(s).` +
        (drifted ? "\nNote: this overwrote a newer server-side version, as requested." : "")
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_discard",
    title: "Discard unsaved workflow edits",
    description:
      "Throw away the in-memory edits and re-load the workflow from the deployment. " +
      "Use this after a wrong turn, instead of trying to undo edits one by one.",
    inputSchema: { wid: widArg },
    annotations: { destructiveHint: true },
    handler: async (args: { wid?: number }, ctx) => {
      const session = ctx.sessions.require(args.wid);
      const fetched = await retrieveWorkflowWithPrivilege(ctx.client, session.wid);
      const reopened = ctx.sessions.open(
        {
          wid: fetched.wid,
          name: fetched.name,
          description: fetched.description,
          content: parseWorkflowContent(fetched.content),
          lastModifiedTime: fetched.lastModifiedTime,
          isPublic: fetched.isPublished,
        },
        fetched.readonly
      );
      return joinSections(
        `Discarded unsaved edits to workflow ${session.wid}; reloaded from the server.`,
        describeWorkflow(reopened)
      );
    },
  });
}

/** Condenses compiled per-port schemas into one line per operator. */
function summarizeOutputSchemas(schemas: Record<string, Record<string, unknown>>): string {
  const lines: string[] = [];
  for (const [operatorId, portMap] of Object.entries(schemas)) {
    for (const [portId, schema] of Object.entries(portMap ?? {})) {
      if (!Array.isArray(schema)) continue;
      const attributes = schema
        .map((attribute: any) => `${attribute.attributeName}:${attribute.attributeType}`)
        .join(", ");
      lines.push(`${operatorId} port ${portId} -> ${attributes || "(no attributes)"}`);
    }
  }
  return lines.length === 0
    ? "No output schemas were resolved."
    : joinSections("Resolved output schemas:", lines.join("\n"));
}
