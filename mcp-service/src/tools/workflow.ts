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
  createWorkflow,
  deleteWorkflows,
  duplicateWorkflows,
  listWorkflowVersions,
  listWorkflows,
  retrieveWorkflowWithPrivilege,
  setWorkflowPublic,
  updateWorkflowDescription,
  updateWorkflowName,
} from "@texera/sdk";
import type { McpContext } from "../context";
import { ToolError } from "../errors";
import { formatTable, formatTimestamp, joinSections } from "../format";
import { registerTool } from "../register";

export function registerWorkflowTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "workflow_list",
    title: "List workflows",
    description:
      "List every workflow the account can open, with id, owner, access level and last-modified time. " +
      "Use the returned `wid` with workflow_open to start editing one.",
    inputSchema: {
      search: z.string().optional().describe("Case-insensitive filter on name and description"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { search?: string }, ctx) => {
      const workflows = await listWorkflows(ctx.client);
      const needle = args.search?.trim().toLowerCase();
      const filtered = needle
        ? workflows.filter(entry =>
            `${entry.workflow.name} ${entry.workflow.description ?? ""}`.toLowerCase().includes(needle)
          )
        : workflows;

      if (filtered.length === 0) {
        return workflows.length === 0
          ? "No workflows. Create one with workflow_create."
          : `No workflow matches "${args.search}" (${workflows.length} total).`;
      }

      const sorted = [...filtered].sort(
        (a, b) => (b.workflow.lastModifiedTime ?? 0) - (a.workflow.lastModifiedTime ?? 0)
      );

      return joinSections(
        `${sorted.length} workflow(s), most recently modified first:`,
        formatTable(
          ["wid", "name", "owner", "access", "modified"],
          sorted.map(entry => [
            entry.workflow.wid,
            entry.workflow.name,
            entry.ownerName,
            entry.isOwner ? "owner" : entry.accessLevel,
            formatTimestamp(entry.workflow.lastModifiedTime),
          ])
        )
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_create",
    title: "Create an empty workflow",
    description:
      "Create a new, empty workflow owned by this account and open it for editing. " +
      "Follow with workflow_add_operator to build the graph, then workflow_save.",
    inputSchema: {
      name: z.string().min(1).describe("Workflow name"),
      description: z.string().optional().describe("Human-readable description"),
    },
    handler: async (args: { name: string; description?: string }, ctx) => {
      const created = await createWorkflow(ctx.client, { name: args.name, description: args.description });
      const wid = created.workflow.wid;

      // Open it immediately: creating a workflow is only ever a prelude to
      // editing it, and this removes a guaranteed extra round-trip.
      const fetched = await retrieveWorkflowWithPrivilege(ctx.client, wid);
      ctx.sessions.open(
        {
          wid,
          name: fetched.name,
          description: fetched.description,
          content: {
            operators: [],
            operatorPositions: {},
            links: [],
            commentBoxes: [],
            settings: { dataTransferBatchSize: 400 },
          },
          lastModifiedTime: fetched.lastModifiedTime,
          isPublic: fetched.isPublished,
        },
        false
      );

      return (
        `Created workflow ${wid} "${created.workflow.name}" and opened it for editing.\n` +
        `Add operators with workflow_add_operator, then call workflow_save.`
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_update",
    title: "Update workflow metadata",
    description:
      "Rename a workflow, change its description, or publish/unpublish it. This touches metadata only — " +
      "the operator graph is edited with the workflow_* editing tools and written by workflow_save.",
    inputSchema: {
      wid: z.number().int().describe("Workflow id"),
      name: z.string().min(1).optional().describe("New name"),
      description: z.string().optional().describe("New description"),
      is_public: z.boolean().optional().describe("Publish (true) or unpublish (false)"),
    },
    handler: async (args: { wid: number; name?: string; description?: string; is_public?: boolean }, ctx) => {
      const changes: string[] = [];
      if (args.name !== undefined) {
        await updateWorkflowName(ctx.client, args.wid, args.name);
        changes.push(`name -> "${args.name}"`);
        const session = ctx.sessions.get(args.wid);
        if (session) session.name = args.name;
      }
      if (args.description !== undefined) {
        await updateWorkflowDescription(ctx.client, args.wid, args.description);
        changes.push("description updated");
        const session = ctx.sessions.get(args.wid);
        if (session) session.description = args.description;
      }
      if (args.is_public !== undefined) {
        await setWorkflowPublic(ctx.client, args.wid, args.is_public);
        changes.push(args.is_public ? "published" : "unpublished");
        const session = ctx.sessions.get(args.wid);
        if (session) session.isPublic = args.is_public;
      }
      if (changes.length === 0) {
        throw new ToolError("Nothing to update — pass at least one of name, description, is_public.");
      }
      return `Workflow ${args.wid}: ${changes.join("; ")}.`;
    },
  });

  registerTool(server, context, {
    name: "workflow_duplicate",
    title: "Duplicate a workflow",
    description:
      "Copy a workflow into a new one owned by this account, named with a `_copy` suffix. " +
      "Use this to get an editable copy of a workflow shared with you read-only, or to experiment " +
      "without touching the original.",
    inputSchema: { wid: z.number().int().describe("Workflow id to copy") },
    handler: async (args: { wid: number }, ctx) => {
      const copies = await duplicateWorkflows(ctx.client, [args.wid]);
      if (copies.length === 0) {
        throw new ToolError(`The deployment did not return a copy of workflow ${args.wid}. Check your access to it.`);
      }
      const copy = copies[0];
      return `Copied workflow ${args.wid} to ${copy.workflow.wid} "${copy.workflow.name}". Open it with workflow_open(${copy.workflow.wid}).`;
    },
  });

  registerTool(server, context, {
    name: "workflow_delete",
    title: "Delete a workflow",
    description:
      "Permanently delete a workflow, its version history and its execution history. This cannot be undone. " +
      "Requires confirm_name to exactly match the workflow's current name — show the user what will be " +
      "deleted and get their agreement before calling this.",
    inputSchema: {
      wid: z.number().int().describe("Workflow id"),
      confirm_name: z.string().describe("The workflow's exact current name, as a confirmation"),
    },
    annotations: { destructiveHint: true },
    handler: async (args: { wid: number; confirm_name: string }, ctx) => {
      const workflow = await retrieveWorkflowWithPrivilege(ctx.client, args.wid);
      if (args.confirm_name !== workflow.name) {
        throw new ToolError(
          `Refusing to delete workflow ${args.wid}: confirm_name must exactly match its current name. ` +
            `Expected "${workflow.name}", got "${args.confirm_name}".`
        );
      }
      await deleteWorkflows(ctx.client, [args.wid]);
      ctx.sessions.close(args.wid);
      return `Deleted workflow ${args.wid} "${workflow.name}".`;
    },
  });

  registerTool(server, context, {
    name: "workflow_list_versions",
    title: "List a workflow's version history",
    description:
      "List saved versions of a workflow, newest first. Texera snapshots a version on every save, so this " +
      "is the recovery path if an edit went wrong.",
    inputSchema: { wid: z.number().int().describe("Workflow id") },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { wid: number }, ctx) => {
      const versions = await listWorkflowVersions(ctx.client, args.wid);
      if (versions.length === 0) {
        return `Workflow ${args.wid} has no saved versions yet.`;
      }
      return joinSections(
        `${versions.length} version(s) of workflow ${args.wid}, newest first:`,
        formatTable(
          ["vid", "created", "milestone"],
          versions
            .slice(0, 50)
            .map(version => [version.vid, formatTimestamp(version.creationTime), version.importance ? "yes" : ""])
        ),
        versions.length > 50 ? `… ${versions.length - 50} older version(s) not shown` : undefined
      );
    },
  });
}
