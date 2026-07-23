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
  getDatasetOwner,
  getWorkflowOwner,
  grantDatasetAccess,
  grantWorkflowAccess,
  listDatasetAccess,
  listWorkflowAccess,
  revokeDatasetAccess,
  revokeWorkflowAccess,
  type Privilege,
} from "@texera/sdk";
import type { McpContext } from "../context";
import { formatTable, joinSections } from "../format";
import { registerTool } from "../register";

const privilegeArg = z.enum(["READ", "WRITE"]).describe("READ lets them view and run; WRITE lets them edit");

export function registerSharingTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "workflow_list_access",
    title: "Show who a workflow is shared with",
    description: "List the accounts a workflow has been shared with and their access level, plus its owner.",
    inputSchema: { wid: z.number().int().describe("Workflow id") },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { wid: number }, ctx) => {
      const [owner, entries] = await Promise.all([
        getWorkflowOwner(ctx.client, args.wid).catch(() => "unknown"),
        listWorkflowAccess(ctx.client, args.wid),
      ]);
      return joinSections(
        `Workflow ${args.wid} — owner: ${owner}`,
        entries.length === 0
          ? "Not shared with anyone else."
          : formatTable(
              ["email", "name", "access"],
              entries.map(entry => [entry.email, entry.name, entry.privilege])
            )
      );
    },
  });

  registerTool(server, context, {
    name: "workflow_share",
    title: "Share a workflow with someone",
    description:
      "Grant another account access to a workflow by email address. This gives a real person access to " +
      "the user's work — confirm the exact address and access level with the user first, and never infer " +
      "an address you were not given. The account must already exist on this deployment.",
    inputSchema: {
      wid: z.number().int().describe("Workflow id"),
      email: z.string().min(3).describe("Exact email address of the recipient's Texera account"),
      privilege: privilegeArg,
    },
    annotations: { destructiveHint: true },
    handler: async (args: { wid: number; email: string; privilege: Privilege }, ctx) => {
      await grantWorkflowAccess(ctx.client, args.wid, args.email, args.privilege);
      return `Granted ${args.privilege} access to workflow ${args.wid} for ${args.email}.`;
    },
  });

  registerTool(server, context, {
    name: "workflow_unshare",
    title: "Revoke someone's access to a workflow",
    description: "Remove an account's access to a workflow. The owner's access cannot be revoked.",
    inputSchema: {
      wid: z.number().int().describe("Workflow id"),
      email: z.string().min(3).describe("Email address whose access is removed"),
    },
    annotations: { destructiveHint: true },
    handler: async (args: { wid: number; email: string }, ctx) => {
      await revokeWorkflowAccess(ctx.client, args.wid, args.email);
      return `Revoked ${args.email}'s access to workflow ${args.wid}.`;
    },
  });

  registerTool(server, context, {
    name: "dataset_list_access",
    title: "Show who a dataset is shared with",
    description: "List the accounts a dataset has been shared with and their access level, plus its owner.",
    inputSchema: { did: z.number().int().describe("Dataset id") },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { did: number }, ctx) => {
      const [owner, entries] = await Promise.all([
        getDatasetOwner(ctx.client, args.did).catch(() => "unknown"),
        listDatasetAccess(ctx.client, args.did),
      ]);
      return joinSections(
        `Dataset ${args.did} — owner: ${owner}`,
        entries.length === 0
          ? "Not shared with anyone else."
          : formatTable(
              ["email", "name", "access"],
              entries.map(entry => [entry.email, entry.name, entry.privilege])
            )
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_share",
    title: "Share a dataset with someone",
    description:
      "Grant another account access to a dataset by email address. This exposes the user's data to a real " +
      "person — confirm the exact address and access level with the user first, and never infer an address " +
      "you were not given.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      email: z.string().min(3).describe("Exact email address of the recipient's Texera account"),
      privilege: privilegeArg,
    },
    annotations: { destructiveHint: true },
    handler: async (args: { did: number; email: string; privilege: Privilege }, ctx) => {
      await grantDatasetAccess(ctx.client, args.did, args.email, args.privilege);
      return `Granted ${args.privilege} access to dataset ${args.did} for ${args.email}.`;
    },
  });

  registerTool(server, context, {
    name: "dataset_unshare",
    title: "Revoke someone's access to a dataset",
    description: "Remove an account's access to a dataset. The owner's access cannot be revoked.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      email: z.string().min(3).describe("Email address whose access is removed"),
    },
    annotations: { destructiveHint: true },
    handler: async (args: { did: number; email: string }, ctx) => {
      await revokeDatasetAccess(ctx.client, args.did, args.email);
      return `Revoked ${args.email}'s access to dataset ${args.did}.`;
    },
  });
}
