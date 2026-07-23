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

/**
 * Datasets are LakeFS repositories (`dataset-<did>`), which is what drives the
 * two-phase write model in this module:
 *
 *   upload / delete file  ->  uncommitted change on branch `main`
 *   createDatasetVersion  ->  commit  ->  an immutable, referenceable version
 *
 * Nothing a workflow reads can see an uncommitted change, so a caller that
 * uploads without committing has produced a dataset that silently does not work.
 */

export interface Dataset {
  did: number;
  name: string;
  description?: string;
  ownerUid: number;
  isPublic: boolean;
  isDownloadable: boolean;
  creationTime?: number;
  repositoryName?: string;
}

export interface DashboardDataset {
  dataset: Dataset;
  ownerEmail: string;
  /** `READ` | `WRITE` */
  accessPrivilege: string;
  isOwner: boolean;
  /** Total repository size in bytes. */
  size: number;
}

export interface DatasetVersion {
  dvid: number;
  did: number;
  creatorUid: number;
  name: string;
  versionHash: string;
  creationTime?: number;
}

/** Wire shape produced by `DatasetFileNodeSerializer`. */
export interface DatasetFileNode {
  name: string;
  /** `file` | `directory` */
  type: string;
  /** Absolute directory of this node, e.g. `/alice@x.com/covid/v1/raw`. */
  parentDir: string;
  ownerEmail: string;
  size?: number;
  children?: DatasetFileNode[];
}

export interface DatasetVersionRootFileNodesResponse {
  fileNodes: DatasetFileNode[];
  size: number;
}

export interface DashboardDatasetVersion {
  datasetVersion: DatasetVersion;
  fileNodes: DatasetFileNode[];
}

/** One uncommitted change on the dataset's `main` branch. */
export interface DatasetDiff {
  path: string;
  /** `object` | `common_prefix` */
  pathType: string;
  /** `added` | `removed` | `changed` | `conflict` */
  diffType: string;
  sizeBytes?: number;
}

/** A flattened file entry with the path string that workflow operators consume. */
export interface DatasetFileEntry {
  /** Path relative to the version root, e.g. `raw/cases.csv`. */
  relativePath: string;
  /**
   * The value to put in an operator's `fileName` property. `FileResolver`
   * parses it as `/ownerEmail/datasetName/versionName/relativePath`.
   */
  workflowPath: string;
  sizeBytes?: number;
}

export async function listDatasets(client: TexeraClient): Promise<DashboardDataset[]> {
  return client.request<DashboardDataset[]>("file", "/api/dataset/list");
}

export async function getDataset(client: TexeraClient, did: number): Promise<DashboardDataset> {
  return client.request<DashboardDataset>("file", `/api/dataset/${did}`);
}

export async function createDataset(
  client: TexeraClient,
  request: {
    datasetName: string;
    datasetDescription?: string;
    isDatasetPublic?: boolean;
    isDatasetDownloadable?: boolean;
  }
): Promise<DashboardDataset> {
  return client.request<DashboardDataset>("file", "/api/dataset/create", {
    method: "POST",
    json: {
      datasetName: request.datasetName,
      datasetDescription: request.datasetDescription ?? "",
      isDatasetPublic: request.isDatasetPublic ?? false,
      isDatasetDownloadable: request.isDatasetDownloadable ?? false,
    },
  });
}

/** Deletes the dataset, its LakeFS repository and its S3 objects. Irreversible. */
export async function deleteDataset(client: TexeraClient, did: number): Promise<void> {
  await client.request<void>("file", `/api/dataset/${did}`, { method: "DELETE" });
}

export async function updateDatasetName(client: TexeraClient, did: number, name: string): Promise<void> {
  await client.request<void>("file", "/api/dataset/update/name", { method: "POST", json: { did, name } });
}

export async function updateDatasetDescription(client: TexeraClient, did: number, description: string): Promise<void> {
  await client.request<void>("file", "/api/dataset/update/description", {
    method: "POST",
    json: { did, description },
  });
}

/**
 * **Toggles** publicity — the endpoint takes no desired value, it flips the
 * current one. Use {@link setDatasetPublic} unless you really want a flip.
 */
export async function toggleDatasetPublicity(client: TexeraClient, did: number): Promise<void> {
  await client.request<void>("file", `/api/dataset/${did}/update/publicity`, { method: "POST" });
}

/** **Toggles** downloadability. Owner-only. See {@link toggleDatasetPublicity}. */
export async function toggleDatasetDownloadable(client: TexeraClient, did: number): Promise<void> {
  await client.request<void>("file", `/api/dataset/${did}/update/downloadable`, { method: "POST" });
}

/**
 * Idempotent publicity setter: reads current state and toggles only on a
 * mismatch. Without this, "make it public" applied twice makes it private.
 */
export async function setDatasetPublic(client: TexeraClient, did: number, isPublic: boolean): Promise<boolean> {
  const current = await getDataset(client, did);
  if (current.dataset.isPublic === isPublic) return false;
  await toggleDatasetPublicity(client, did);
  return true;
}

/** Idempotent downloadability setter. See {@link setDatasetPublic}. */
export async function setDatasetDownloadable(
  client: TexeraClient,
  did: number,
  isDownloadable: boolean
): Promise<boolean> {
  const current = await getDataset(client, did);
  if (current.dataset.isDownloadable === isDownloadable) return false;
  await toggleDatasetDownloadable(client, did);
  return true;
}

export async function listDatasetVersions(client: TexeraClient, did: number): Promise<DatasetVersion[]> {
  return client.request<DatasetVersion[]>("file", `/api/dataset/${did}/version/list`);
}

export async function getLatestDatasetVersion(client: TexeraClient, did: number): Promise<DashboardDatasetVersion> {
  return client.request<DashboardDatasetVersion>("file", `/api/dataset/${did}/version/latest`);
}

/**
 * Commits the pending changes as a new version. The backend prefixes the name
 * with `v<n>` itself and **rejects the call with 400 when nothing is staged**,
 * which callers should surface as "nothing to commit" rather than an error.
 */
export async function createDatasetVersion(
  client: TexeraClient,
  did: number,
  versionName = ""
): Promise<DashboardDatasetVersion> {
  return client.request<DashboardDatasetVersion>("file", `/api/dataset/${did}/version/create`, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: versionName,
  });
}

export async function getDatasetVersionFileNodes(
  client: TexeraClient,
  did: number,
  dvid: number
): Promise<DatasetVersionRootFileNodesResponse> {
  return client.request<DatasetVersionRootFileNodesResponse>(
    "file",
    `/api/dataset/${did}/version/${dvid}/rootFileNodes`
  );
}

export async function getUncommittedChanges(client: TexeraClient, did: number): Promise<DatasetDiff[]> {
  return client.request<DatasetDiff[]>("file", `/api/dataset/${did}/diff`);
}

/**
 * Uploads one file in a single request (`POST /{did}/upload`). Suitable for
 * modest files; large ones should use the multipart flow so a failure does not
 * restart the whole transfer.
 *
 * The file lands as an uncommitted change — call {@link createDatasetVersion}
 * to make it visible to workflows.
 */
export async function uploadFile(
  client: TexeraClient,
  did: number,
  filePath: string,
  content: Uint8Array | ArrayBuffer | string,
  options: { message?: string; timeoutMs?: number } = {}
): Promise<void> {
  const body = typeof content === "string" ? new TextEncoder().encode(content) : content;
  await client.requestRaw("file", `/api/dataset/${did}/upload`, {
    method: "POST",
    // The backend URL-decodes filePath, so it must be encoded here. The client
    // sets it via URLSearchParams, which handles the encoding.
    query: { filePath, message: options.message ?? `Uploaded ${filePath}` },
    headers: { "Content-Type": "application/octet-stream" },
    body: body as BodyInit,
    timeoutMs: options.timeoutMs ?? 300_000,
  });
}

/** Removes a file from the dataset's working branch (uncommitted until a version is created). */
export async function deleteFile(client: TexeraClient, did: number, filePath: string): Promise<void> {
  await client.request<void>("file", `/api/dataset/${did}/file`, {
    method: "DELETE",
    query: { filePath },
  });
}

export interface PresignedUrlResponse {
  presignedUrl: string;
}

/**
 * Issues a short-lived (5 min) direct-download URL for one file in a committed
 * version. `filePath` is the path **within the repository**, and `commitHash`
 * is the version hash from {@link DatasetVersion}.
 */
export async function getPresignedDownloadUrl(
  client: TexeraClient,
  args: { filePath: string; repositoryName: string; commitHash: string }
): Promise<string> {
  const response = await client.request<PresignedUrlResponse>("file", "/api/dataset/presign-download", {
    query: args,
  });
  return response.presignedUrl;
}

/**
 * Flattens the file tree of a version into entries carrying the
 * `/ownerEmail/datasetName/versionName/…` string that operator `fileName`
 * properties expect (see `FileResolver`).
 */
export function flattenFileNodes(
  nodes: DatasetFileNode[],
  versionRootPath: string,
  accumulator: DatasetFileEntry[] = []
): DatasetFileEntry[] {
  for (const node of nodes) {
    if (node.type === "directory") {
      flattenFileNodes(node.children ?? [], versionRootPath, accumulator);
    } else {
      const fullPath = `${node.parentDir.replace(/\/+$/, "")}/${node.name}`;
      const relativePath = fullPath.startsWith(versionRootPath)
        ? fullPath.slice(versionRootPath.length).replace(/^\/+/, "")
        : fullPath.replace(/^\/+/, "");
      accumulator.push({ relativePath, workflowPath: fullPath, sizeBytes: node.size });
    }
  }
  return accumulator;
}

/** The `/ownerEmail/datasetName/versionName` prefix a version's files live under. */
export function versionRootPath(ownerEmail: string, datasetName: string, versionName: string): string {
  return `/${ownerEmail}/${datasetName}/${versionName}`;
}
