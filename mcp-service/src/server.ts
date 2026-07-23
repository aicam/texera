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

import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getDataset, listDatasetVersions, retrieveWorkflow } from "@texera/sdk";
import type { McpContext } from "./context";
import { registerDatasetTools } from "./tools/dataset";
import { registerExecutionTools } from "./tools/execution";
import { registerOperatorTools } from "./tools/operator";
import { registerSessionTools } from "./tools/session";
import { registerSharingTools } from "./tools/sharing";
import { registerWorkflowTools } from "./tools/workflow";
import { registerWorkflowEditTools } from "./tools/workflow-edit";

export const SERVER_NAME = "texera";
export const SERVER_VERSION = "0.1.0";

/**
 * Guidance shown to the model alongside the tool list. It encodes the two
 * ordering constraints that are invisible from the tool signatures and that
 * otherwise produce confidently broken results: uploads need a version commit,
 * and edits need an explicit save.
 */
const INSTRUCTIONS = `This server drives a user's account on an Apache Texera deployment — datasets, workflows and executions.

Two rules are not obvious from the tool names and cause silent failures if ignored:

1. Dataset uploads are staged. dataset_upload_file and dataset_delete_file change nothing a workflow
   can see until dataset_create_version commits them. Always finish an upload with a version.
2. Workflow edits are in memory. workflow_open loads a workflow; the workflow_* editing tools change a
   local copy; workflow_save writes it back. Nothing is persisted until you save. (workflow_run is the
   exception — it runs the in-memory graph, so you can test before saving.)

A typical build-from-data conversation:
  dataset_create -> dataset_upload_file -> dataset_create_version -> dataset_list_files (copy the workflow path)
  -> workflow_create -> operator_get_schema -> workflow_add_operator … -> workflow_validate
  -> workflow_run -> workflow_save

Operator types and their properties differ between deployments. Consult operator_list_types and
operator_get_schema rather than assuming a type exists or guessing its property names.

Deletion and sharing tools affect real data and real people. Show the user what will change and get
their agreement before calling them.`;

export function createServer(context: McpContext): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {}, resources: {}, prompts: {} }, instructions: INSTRUCTIONS }
  );

  registerSessionTools(server, context);
  registerDatasetTools(server, context);
  registerWorkflowTools(server, context);
  registerWorkflowEditTools(server, context);
  registerOperatorTools(server, context);
  registerExecutionTools(server, context);
  registerSharingTools(server, context);

  registerResources(server, context);
  registerPrompts(server);

  return server;
}

function registerResources(server: McpServer, context: McpContext): void {
  // The operator catalogue is large and static within a deployment — a resource
  // the client can pin, rather than something re-fetched into every turn.
  server.registerResource(
    "operator-catalogue",
    "texera://operator-metadata",
    {
      title: "Texera operator catalogue",
      description: "Every operator type this deployment offers, with its JSON Schema and port layout.",
      mimeType: "application/json",
    },
    async uri => {
      const metadata = await context.operatorMetadata();
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: metadata.getAllSchemasAsJson(),
          },
        ],
      };
    }
  );

  server.registerResource(
    "workflow",
    new ResourceTemplate("texera://workflow/{wid}", { list: undefined }),
    {
      title: "Texera workflow",
      description: "A workflow's stored operator graph as JSON.",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const workflow = await retrieveWorkflow(context.client, Number(variables.wid));
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify(
              {
                wid: workflow.wid,
                name: workflow.name,
                description: workflow.description,
                lastModifiedTime: workflow.lastModifiedTime,
                content: workflow.content,
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.registerResource(
    "dataset",
    new ResourceTemplate("texera://dataset/{did}", { list: undefined }),
    {
      title: "Texera dataset",
      description: "A dataset's metadata and version list as JSON.",
      mimeType: "application/json",
    },
    async (uri, variables) => {
      const did = Number(variables.did);
      const [dataset, versions] = await Promise.all([
        getDataset(context.client, did),
        listDatasetVersions(context.client, did).catch(() => []),
      ]);
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify({ ...dataset, versions }, null, 2),
          },
        ],
      };
    }
  );
}

function registerPrompts(server: McpServer): void {
  server.registerPrompt(
    "build_workflow_from_dataset",
    {
      title: "Build a Texera workflow over a dataset",
      description:
        "Walk through uploading data, committing a version, and building and running a workflow over it — " +
        "in the order Texera requires.",
      argsSchema: {
        goal: z.string().describe("What the workflow should do, in plain language"),
        dataset: z.string().optional().describe("Name or id of an existing dataset, if there is one"),
      },
    },
    ({ goal, dataset }) => ({
      messages: [
        {
          role: "user" as const,
          content: {
            type: "text" as const,
            text: [
              `Goal: ${goal}`,
              dataset ? `Use the existing dataset: ${dataset}.` : "There is no dataset yet; create one first.",
              "",
              "Work in this order and show me what you find at each step:",
              "1. texera_whoami, to confirm the connection.",
              dataset
                ? "2. dataset_list / dataset_get to locate it, then dataset_list_files to get each file's workflow path."
                : "2. dataset_create, dataset_upload_file for the data, then dataset_create_version to commit it, then dataset_list_files for the workflow paths.",
              "3. dataset_read_file on one file, so we agree on the column names before building anything.",
              "4. operator_list_types and operator_get_schema for the operators you plan to use.",
              "5. workflow_create, then workflow_add_operator for each step, wiring inputs as you go.",
              "6. workflow_validate, and fix whatever it reports.",
              "7. workflow_run with a target operator, and show me the result table.",
              "8. workflow_save once the result looks right.",
            ].join("\n"),
          },
        },
      ],
    })
  );
}
