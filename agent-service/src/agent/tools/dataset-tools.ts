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

import { tool } from "ai";
import { z } from "zod";
import {
  getFullPathFromDatasetFileNode,
  listAccessibleDatasets,
  listDatasetVersions,
  retrieveDatasetVersionFileTree,
  retrieveLatestDatasetVersion,
  type DashboardDataset,
  type DatasetFileNode,
  type DatasetVersion,
} from "../../api/dataset-api";
import { createErrorResult, createToolResult } from "./tools-utility";

export const TOOL_NAME_LIST_DATASETS = "listDatasets";
export const TOOL_NAME_LIST_DATASET_VERSIONS = "listDatasetVersions";
export const TOOL_NAME_LIST_DATASET_FILES = "listDatasetFiles";

export interface DatasetToolConfig {
  userToken: string;
}

type DatasetVisibilityFilter = "all" | "public" | "private";
type DatasetOwnershipFilter = "all" | "owned" | "shared";

export interface DatasetFilePath {
  path: string;
  size?: number;
}

interface DatasetVersionContext {
  did: number;
  dvid?: number;
  versionName?: string;
}

function sanitizeText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function formatSize(size: number | undefined): string {
  if (size === undefined || Number.isNaN(size)) return "unknown size";
  return size === 1 ? "1 byte" : `${size} bytes`;
}

function isPositiveInteger(value: number | undefined): value is number {
  return Number.isInteger(value) && value !== undefined && value > 0;
}

function filterDatasets(
  datasets: DashboardDataset[],
  visibility: DatasetVisibilityFilter,
  ownership: DatasetOwnershipFilter
): DashboardDataset[] {
  return datasets.filter(entry => {
    const visibilityMatches =
      visibility === "all" ||
      (visibility === "public" && entry.dataset.isPublic) ||
      (visibility === "private" && !entry.dataset.isPublic);
    const ownershipMatches =
      ownership === "all" || (ownership === "owned" && entry.isOwner) || (ownership === "shared" && !entry.isOwner);
    return visibilityMatches && ownershipMatches;
  });
}

export function formatAccessibleDatasets(datasets: DashboardDataset[]): string {
  if (datasets.length === 0) return "No accessible datasets found.";

  const lines = [`Accessible datasets (${datasets.length}):`];
  for (const entry of datasets) {
    const dataset = entry.dataset;
    const visibility = dataset.isPublic ? "public" : "private";
    const ownership = entry.isOwner ? "owned" : "shared";
    const did = dataset.did ?? "unknown";
    const downloadable = dataset.isDownloadable ? "yes" : "no";
    const description = dataset.description ? sanitizeText(dataset.description) : "";
    const descriptionText = description ? `, description=${description}` : "";
    lines.push(
      `- did=${did}, name=${dataset.name}, owner=${entry.ownerEmail}, visibility=${visibility}, ` +
        `access=${entry.accessPrivilege}, ownership=${ownership}, downloadable=${downloadable}${descriptionText}`
    );
  }
  return lines.join("\n");
}

export function formatDatasetVersions(did: number, versions: DatasetVersion[]): string {
  if (versions.length === 0) return `No versions found for dataset did=${did}.`;

  const lines = [`Dataset versions for did=${did} (${versions.length}):`];
  for (const version of versions) {
    const dvid = version.dvid ?? "unknown";
    const hash = version.versionHash ? `, versionHash=${version.versionHash}` : "";
    const created = version.creationTime !== undefined ? `, creationTime=${version.creationTime}` : "";
    lines.push(`- dvid=${dvid}, name=${version.name}${created}${hash}`);
  }
  return lines.join("\n");
}

export function collectDatasetFilePaths(nodes: DatasetFileNode[]): DatasetFilePath[] {
  const paths: DatasetFilePath[] = [];

  const visit = (node: DatasetFileNode) => {
    if (node.type === "file") {
      paths.push({ path: getFullPathFromDatasetFileNode(node), size: node.size });
      return;
    }
    for (const child of node.children ?? []) {
      visit(child);
    }
  };

  for (const node of nodes) {
    visit(node);
  }

  return paths;
}

export function formatDatasetFilePaths(context: DatasetVersionContext, paths: DatasetFilePath[]): string {
  const versionText = context.versionName ? `version=${context.versionName}` : "version=unknown";
  const dvidText = context.dvid !== undefined ? ` (dvid=${context.dvid})` : "";

  if (paths.length === 0) {
    return `No files found in dataset did=${context.did}, ${versionText}${dvidText}.`;
  }

  const lines = [`Files in dataset did=${context.did}, ${versionText}${dvidText}:`];
  for (const file of paths) {
    const sizeText = file.size !== undefined ? ` (${formatSize(file.size)})` : "";
    lines.push(`- ${file.path}${sizeText}`);
  }
  return lines.join("\n");
}

export function createListDatasetsTool(getConfig: () => DatasetToolConfig) {
  return tool({
    description:
      "List datasets the current user can access, including owned private datasets, shared datasets, and public datasets. The result includes dataset id, owner, visibility, and access privilege.",
    inputSchema: z.object({
      visibility: z
        .enum(["all", "public", "private"])
        .optional()
        .describe("Filter datasets by visibility. Defaults to all."),
      ownership: z
        .enum(["all", "owned", "shared"])
        .optional()
        .describe("Filter datasets by ownership. Defaults to all."),
    }),
    execute: async (
      args: { visibility?: DatasetVisibilityFilter; ownership?: DatasetOwnershipFilter } = {},
      options: { abortSignal?: AbortSignal } = {}
    ) => {
      try {
        const visibility = args.visibility ?? "all";
        const ownership = args.ownership ?? "all";
        const datasets = await listAccessibleDatasets(getConfig().userToken, { abortSignal: options.abortSignal });
        return createToolResult(formatAccessibleDatasets(filterDatasets(datasets, visibility, ownership)));
      } catch (error: any) {
        return createErrorResult(error.message || String(error));
      }
    },
  });
}

export function createListDatasetVersionsTool(getConfig: () => DatasetToolConfig) {
  return tool({
    description:
      "List committed versions of a dataset. Use listDatasets first to find the dataset id (did), then use this tool to choose a specific version id (dvid) when needed.",
    inputSchema: z.object({
      did: z.number().int().positive().describe("Dataset id."),
    }),
    execute: async (args: { did: number }, options: { abortSignal?: AbortSignal } = {}) => {
      try {
        if (!isPositiveInteger(args.did)) {
          return createErrorResult("did must be a positive integer.");
        }
        const versions = await listDatasetVersions(getConfig().userToken, args.did, {
          abortSignal: options.abortSignal,
        });
        return createToolResult(formatDatasetVersions(args.did, versions));
      } catch (error: any) {
        return createErrorResult(error.message || String(error));
      }
    },
  });
}

export function createListDatasetFilesTool(getConfig: () => DatasetToolConfig) {
  return tool({
    description:
      "List full file paths under a dataset version. The paths use DKNet-AI's dataset path format: /ownerEmail/datasetName/versionName/fileRelativePath. If dvid is omitted, the latest dataset version is used.",
    inputSchema: z.object({
      did: z.number().int().positive().describe("Dataset id."),
      dvid: z.number().int().positive().optional().describe("Dataset version id. Omit to use the latest version."),
    }),
    execute: async (args: { did: number; dvid?: number }, options: { abortSignal?: AbortSignal } = {}) => {
      try {
        if (!isPositiveInteger(args.did)) {
          return createErrorResult("did must be a positive integer.");
        }
        if (args.dvid !== undefined && !isPositiveInteger(args.dvid)) {
          return createErrorResult("dvid must be a positive integer when provided.");
        }

        if (args.dvid === undefined) {
          const latest = await retrieveLatestDatasetVersion(getConfig().userToken, args.did, {
            abortSignal: options.abortSignal,
          });
          return createToolResult(
            formatDatasetFilePaths(
              {
                did: args.did,
                dvid: latest.datasetVersion.dvid,
                versionName: latest.datasetVersion.name,
              },
              collectDatasetFilePaths(latest.fileNodes)
            )
          );
        }

        const [versions, tree] = await Promise.all([
          listDatasetVersions(getConfig().userToken, args.did, { abortSignal: options.abortSignal }),
          retrieveDatasetVersionFileTree(getConfig().userToken, args.did, args.dvid, {
            abortSignal: options.abortSignal,
          }),
        ]);
        const version = versions.find(candidate => candidate.dvid === args.dvid);
        return createToolResult(
          formatDatasetFilePaths(
            { did: args.did, dvid: args.dvid, versionName: version?.name },
            collectDatasetFilePaths(tree.fileNodes)
          )
        );
      } catch (error: any) {
        return createErrorResult(error.message || String(error));
      }
    },
  });
}
