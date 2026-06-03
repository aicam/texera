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

import { createAuthHeaders } from "./auth-api";
import { getBackendConfig } from "./backend-api";

export interface Dataset {
  did?: number;
  ownerUid?: number;
  name: string;
  isPublic: boolean;
  isDownloadable: boolean;
  storagePath?: string;
  repositoryName?: string;
  description?: string;
  creationTime?: number;
  coverImage?: string;
}

export interface DashboardDataset {
  isOwner: boolean;
  ownerEmail: string;
  dataset: Dataset;
  accessPrivilege: "READ" | "WRITE" | "NONE" | string;
  size: number;
}

export interface DatasetVersion {
  dvid?: number;
  did: number;
  creatorUid: number;
  name: string;
  versionHash?: string;
  creationTime?: number;
}

export interface DatasetFileNode {
  name: string;
  type: "file" | "directory";
  parentDir: string;
  children?: DatasetFileNode[];
  ownerEmail?: string;
  size?: number;
}

export interface DashboardDatasetVersion {
  datasetVersion: DatasetVersion;
  fileNodes: DatasetFileNode[];
}

export interface DatasetVersionRootFileNodesResponse {
  fileNodes: DatasetFileNode[];
  size: number;
}

const DATASET_BASE_URL = "dataset";

export function buildDatasetApiUrl(fileServiceEndpoint: string, path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const normalizedEndpoint = fileServiceEndpoint.replace(/\/+$/, "").replace(/\/api$/, "");
  return `${normalizedEndpoint}/api/${DATASET_BASE_URL}${normalizedPath}`;
}

function datasetApiUrl(path: string): string {
  return buildDatasetApiUrl(getBackendConfig().fileServiceEndpoint, path);
}

async function requestDatasetJson<T>(
  token: string,
  path: string,
  failureMessage: string,
  options: { abortSignal?: AbortSignal } = {}
): Promise<T> {
  const response = await fetch(datasetApiUrl(path), {
    method: "GET",
    headers: createAuthHeaders(token),
    signal: options.abortSignal,
  });

  if (!response.ok) {
    const errorText = await response.text();
    const suffix = errorText ? ` - ${errorText}` : "";
    throw new Error(`${failureMessage}: ${response.status} ${response.statusText}${suffix}`);
  }

  return (await response.json()) as T;
}

export async function listAccessibleDatasets(
  token: string,
  options: { abortSignal?: AbortSignal } = {}
): Promise<DashboardDataset[]> {
  return requestDatasetJson<DashboardDataset[]>(token, "/list", "Failed to list accessible datasets", options);
}

export async function listDatasetVersions(
  token: string,
  did: number,
  options: { abortSignal?: AbortSignal } = {}
): Promise<DatasetVersion[]> {
  return requestDatasetJson<DatasetVersion[]>(
    token,
    `/${did}/version/list`,
    "Failed to list dataset versions",
    options
  );
}

export async function retrieveLatestDatasetVersion(
  token: string,
  did: number,
  options: { abortSignal?: AbortSignal } = {}
): Promise<DashboardDatasetVersion> {
  return requestDatasetJson<DashboardDatasetVersion>(
    token,
    `/${did}/version/latest`,
    "Failed to retrieve latest dataset version",
    options
  );
}

export async function retrieveDatasetVersionFileTree(
  token: string,
  did: number,
  dvid: number,
  options: { abortSignal?: AbortSignal } = {}
): Promise<DatasetVersionRootFileNodesResponse> {
  return requestDatasetJson<DatasetVersionRootFileNodesResponse>(
    token,
    `/${did}/version/${dvid}/rootFileNodes`,
    "Failed to retrieve dataset version file tree",
    options
  );
}

export function getFullPathFromDatasetFileNode(node: DatasetFileNode): string {
  const parentDir = node.parentDir.endsWith("/") ? node.parentDir.slice(0, -1) : node.parentDir;
  return parentDir ? `${parentDir}/${node.name}` : `/${node.name}`;
}
