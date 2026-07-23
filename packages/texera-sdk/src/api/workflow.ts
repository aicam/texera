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
import type { WorkflowContent } from "../types/workflow";

/**
 * The `workflow` table row as the backend serializes it. `content` is a JSON
 * **string** on the wire — a serialized {@link WorkflowContent} — not a nested
 * object. Every helper here parses/stringifies at the boundary so callers only
 * ever deal with {@link Workflow}.
 */
export interface WorkflowRecord {
  wid: number;
  name: string;
  description?: string;
  content: string;
  creationTime?: number;
  lastModifiedTime?: number;
  isPublic?: boolean;
}

export interface Workflow {
  wid: number;
  name: string;
  description?: string;
  content: WorkflowContent;
  creationTime?: number;
  lastModifiedTime?: number;
  isPublic?: boolean;
}

/** `GET /api/workflow/{wid}` — adds the caller's privilege to the row. */
export interface WorkflowWithPrivilege {
  name: string;
  description: string;
  wid: number;
  content: string;
  creationTime: number;
  lastModifiedTime: number;
  isPublished: boolean;
  /** True when the caller has read but not write access. */
  readonly: boolean;
}

/** `GET /api/workflow/list` entry. */
export interface DashboardWorkflow {
  isOwner: boolean;
  accessLevel: string;
  ownerName: string;
  workflow: WorkflowRecord;
  projectIDs: number[];
  ownerId: number;
  coverImage?: string | null;
}

export interface WorkflowVersionEntry {
  vid: number;
  creationTime: number;
  content?: string;
  importance?: boolean;
}

const EMPTY_CONTENT: WorkflowContent = {
  operators: [],
  operatorPositions: {},
  links: [],
  commentBoxes: [],
  settings: { dataTransferBatchSize: 400 },
};

/**
 * Parses the `content` JSON string, tolerating the empty/absent content the
 * backend stores for a freshly created workflow.
 */
export function parseWorkflowContent(content: string | undefined | null): WorkflowContent {
  if (!content) return EMPTY_CONTENT;
  const parsed = JSON.parse(content) as Partial<WorkflowContent>;
  return {
    operators: parsed.operators ?? [],
    operatorPositions: parsed.operatorPositions ?? {},
    links: parsed.links ?? [],
    commentBoxes: parsed.commentBoxes ?? [],
    settings: parsed.settings ?? EMPTY_CONTENT.settings,
  };
}

export async function retrieveWorkflow(client: TexeraClient, wid: number): Promise<Workflow> {
  const data = await client.request<WorkflowWithPrivilege>("dashboard", `/api/workflow/${wid}`);
  return {
    wid: data.wid,
    name: data.name,
    description: data.description,
    content: parseWorkflowContent(data.content),
    creationTime: data.creationTime,
    lastModifiedTime: data.lastModifiedTime,
    isPublic: data.isPublished,
  };
}

/** Same as {@link retrieveWorkflow} but keeps the raw privilege fields. */
export async function retrieveWorkflowWithPrivilege(client: TexeraClient, wid: number): Promise<WorkflowWithPrivilege> {
  return client.request<WorkflowWithPrivilege>("dashboard", `/api/workflow/${wid}`);
}

/**
 * Writes a workflow back (`POST /api/workflow/persist`). The backend also
 * snapshots a `workflow_version` row on every persist, so each save is
 * recoverable from the version history.
 */
export async function persistWorkflow(
  client: TexeraClient,
  workflow: {
    wid: number;
    name: string;
    content: WorkflowContent;
    description?: string;
    isPublic?: boolean;
  }
): Promise<Workflow> {
  const data = await client.request<WorkflowRecord>("dashboard", "/api/workflow/persist", {
    method: "POST",
    json: {
      wid: workflow.wid,
      name: workflow.name,
      description: workflow.description ?? "",
      content: JSON.stringify(workflow.content),
      isPublic: workflow.isPublic ?? false,
    },
  });
  return { ...data, content: parseWorkflowContent(data.content) };
}

export async function listWorkflows(client: TexeraClient): Promise<DashboardWorkflow[]> {
  return client.request<DashboardWorkflow[]>("dashboard", "/api/workflow/list");
}

export async function createWorkflow(
  client: TexeraClient,
  workflow: { name: string; description?: string; content?: WorkflowContent }
): Promise<DashboardWorkflow> {
  return client.request<DashboardWorkflow>("dashboard", "/api/workflow/create", {
    method: "POST",
    json: {
      // `wid` must stay absent: /create rejects a caller-supplied id.
      name: workflow.name,
      description: workflow.description ?? "",
      content: JSON.stringify(workflow.content ?? EMPTY_CONTENT),
      isPublic: false,
    },
  });
}

export async function deleteWorkflows(client: TexeraClient, wids: number[]): Promise<void> {
  await client.request<void>("dashboard", "/api/workflow/delete", {
    method: "POST",
    json: { wids, pid: null },
  });
}

export async function duplicateWorkflows(client: TexeraClient, wids: number[]): Promise<DashboardWorkflow[]> {
  return client.request<DashboardWorkflow[]>("dashboard", "/api/workflow/duplicate", {
    method: "POST",
    json: { wids, pid: null },
  });
}

export async function updateWorkflowName(client: TexeraClient, wid: number, name: string): Promise<void> {
  await client.request<void>("dashboard", "/api/workflow/update/name", {
    method: "POST",
    json: { wid, name },
  });
}

export async function updateWorkflowDescription(client: TexeraClient, wid: number, description: string): Promise<void> {
  await client.request<void>("dashboard", "/api/workflow/update/description", {
    method: "POST",
    json: { wid, description },
  });
}

export async function setWorkflowPublic(client: TexeraClient, wid: number, isPublic: boolean): Promise<void> {
  await client.request<void>("dashboard", `/api/workflow/${isPublic ? "public" : "private"}/${wid}`, {
    method: "PUT",
  });
}

export async function listWorkflowVersions(client: TexeraClient, wid: number): Promise<WorkflowVersionEntry[]> {
  return client.request<WorkflowVersionEntry[]>("dashboard", `/api/version/${wid}`);
}

export async function retrieveWorkflowVersion(client: TexeraClient, wid: number, vid: number): Promise<Workflow> {
  const data = await client.request<WorkflowRecord>("dashboard", `/api/version/${wid}/${vid}`);
  return { ...data, content: parseWorkflowContent(data.content) };
}
