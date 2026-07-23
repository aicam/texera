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

/** Sharing surfaces for workflows and datasets are identical apart from the path. */
export type Privilege = "READ" | "WRITE";

export interface AccessEntry {
  email: string;
  name: string;
  privilege: string;
}

export async function listWorkflowAccess(client: TexeraClient, wid: number): Promise<AccessEntry[]> {
  return client.request<AccessEntry[]>("dashboard", `/api/access/workflow/list/${wid}`);
}

export async function getWorkflowOwner(client: TexeraClient, wid: number): Promise<string> {
  return client.request<string>("dashboard", `/api/access/workflow/owner/${wid}`);
}

export async function grantWorkflowAccess(
  client: TexeraClient,
  wid: number,
  email: string,
  privilege: Privilege
): Promise<void> {
  await client.request<void>(
    "dashboard",
    `/api/access/workflow/grant/${wid}/${encodeURIComponent(email)}/${privilege}`,
    { method: "PUT" }
  );
}

export async function revokeWorkflowAccess(client: TexeraClient, wid: number, email: string): Promise<void> {
  await client.request<void>("dashboard", `/api/access/workflow/revoke/${wid}/${encodeURIComponent(email)}`, {
    method: "DELETE",
  });
}

export async function listDatasetAccess(client: TexeraClient, did: number): Promise<AccessEntry[]> {
  return client.request<AccessEntry[]>("file", `/api/access/dataset/list/${did}`);
}

export async function getDatasetOwner(client: TexeraClient, did: number): Promise<string> {
  return client.request<string>("file", `/api/access/dataset/owner/${did}`);
}

export async function grantDatasetAccess(
  client: TexeraClient,
  did: number,
  email: string,
  privilege: Privilege
): Promise<void> {
  await client.request<void>("file", `/api/access/dataset/grant/${did}/${encodeURIComponent(email)}/${privilege}`, {
    method: "PUT",
  });
}

export async function revokeDatasetAccess(client: TexeraClient, did: number, email: string): Promise<void> {
  await client.request<void>("file", `/api/access/dataset/revoke/${did}/${encodeURIComponent(email)}`, {
    method: "DELETE",
  });
}
