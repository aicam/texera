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
  TexeraApiError,
  createDataset,
  createDatasetVersion,
  deleteDataset,
  deleteFile,
  flattenFileNodes,
  getDataset,
  getDatasetVersionFileNodes,
  getPresignedDownloadUrl,
  getUncommittedChanges,
  listDatasetVersions,
  listDatasets,
  setDatasetDownloadable,
  setDatasetPublic,
  updateDatasetDescription,
  updateDatasetName,
  uploadFile,
  versionRootPath,
  type DatasetVersion,
} from "@texera/sdk";
import type { McpContext } from "../context";
import { ToolError } from "../errors";
import { formatBytes, formatTable, formatTimestamp, joinSections, truncate } from "../format";
import { registerTool } from "../register";

/**
 * The uncommitted-changes rule stated once, and repeated into every tool
 * description that stages a change. A model that does not know this produces
 * datasets that look fine and cannot be read by any workflow.
 */
const COMMIT_NOTE = "Changes are staged, not visible to workflows, until dataset_create_version commits them.";

/** Resolves a version by id, by name, or (default) the newest one. */
async function resolveVersion(
  context: McpContext,
  did: number,
  version: number | string | undefined
): Promise<DatasetVersion> {
  const versions = await listDatasetVersions(context.client, did);
  if (versions.length === 0) {
    throw new ToolError(
      `Dataset ${did} has no versions yet. Upload files with dataset_upload_file, then commit them ` +
        `with dataset_create_version.`
    );
  }
  if (version === undefined) {
    // listDatasetVersions returns newest-first.
    return versions[0];
  }
  const match =
    typeof version === "number"
      ? versions.find(candidate => candidate.dvid === version)
      : versions.find(candidate => candidate.name === version || String(candidate.dvid) === version);
  if (!match) {
    throw new ToolError(
      `Dataset ${did} has no version "${version}". Available: ${versions.map(v => `${v.name} (dvid ${v.dvid})`).join(", ")}`
    );
  }
  return match;
}

function requireExactName(actual: string, confirmName: string | undefined, kind: string, id: number): void {
  if (confirmName !== actual) {
    throw new ToolError(
      `Refusing to delete ${kind} ${id}: confirm_name must exactly match its current name. ` +
        `Expected "${actual}", got ${confirmName === undefined ? "nothing" : `"${confirmName}"`}. ` +
        `Show the user what is about to be deleted and pass the name back to confirm.`
    );
  }
}

export function registerDatasetTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "dataset_list",
    title: "List datasets",
    description:
      "List every dataset the account can read, with id, owner, size and access level. " +
      "Use the returned `did` with the other dataset tools.",
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (_args, ctx) => {
      const datasets = await listDatasets(ctx.client);
      if (datasets.length === 0) {
        return "No datasets. Create one with dataset_create.";
      }
      return joinSections(
        `${datasets.length} dataset(s):`,
        formatTable(
          ["did", "name", "owner", "access", "public", "size"],
          datasets.map(entry => [
            entry.dataset.did,
            entry.dataset.name,
            entry.ownerEmail,
            entry.isOwner ? "owner" : entry.accessPrivilege,
            entry.dataset.isPublic ? "yes" : "no",
            formatBytes(entry.size),
          ])
        )
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_get",
    title: "Show one dataset",
    description:
      "Show a dataset's metadata, its versions, and any staged-but-uncommitted changes. " +
      "Use dataset_list_files to see the files inside a version.",
    inputSchema: { did: z.number().int().describe("Dataset id, from dataset_list") },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { did: number }, ctx) => {
      const [dataset, versions, diffs] = await Promise.all([
        getDataset(ctx.client, args.did),
        listDatasetVersions(ctx.client, args.did).catch(() => []),
        getUncommittedChanges(ctx.client, args.did).catch(() => []),
      ]);

      const summary = [
        `Dataset ${dataset.dataset.did}: ${dataset.dataset.name}`,
        `Owner:       ${dataset.ownerEmail}${dataset.isOwner ? " (you)" : ""}`,
        `Access:      ${dataset.accessPrivilege}`,
        `Visibility:  ${dataset.dataset.isPublic ? "public" : "private"}, ${dataset.dataset.isDownloadable ? "downloadable" : "not downloadable"}`,
        `Size:        ${formatBytes(dataset.size)}`,
        `Description: ${dataset.dataset.description || "(none)"}`,
      ].join("\n");

      const versionSection =
        versions.length === 0
          ? "Versions: none yet — uploaded files are not readable by workflows until you call dataset_create_version."
          : joinSections(
              `Versions (newest first):`,
              formatTable(
                ["dvid", "name", "created"],
                versions.map(version => [version.dvid, version.name, formatTimestamp(version.creationTime)])
              )
            );

      const diffSection =
        diffs.length === 0
          ? undefined
          : joinSections(
              `${diffs.length} staged change(s) not yet committed:`,
              formatTable(
                ["change", "path", "size"],
                diffs.map(diff => [diff.diffType, diff.path, formatBytes(diff.sizeBytes)])
              ),
              "Call dataset_create_version to commit them."
            );

      return joinSections(summary, versionSection, diffSection);
    },
  });

  registerTool(server, context, {
    name: "dataset_create",
    title: "Create a dataset",
    description:
      "Create an empty dataset owned by this account. Follow it with dataset_upload_file and then " +
      "dataset_create_version to make the files usable. Dataset names must be unique per owner.",
    inputSchema: {
      name: z.string().min(1).describe("Dataset name, unique among this account's datasets"),
      description: z.string().optional().describe("Human-readable description"),
      is_public: z.boolean().optional().describe("Readable by anyone on the deployment. Defaults to false."),
      is_downloadable: z.boolean().optional().describe("Allow others to download the files. Defaults to false."),
    },
    handler: async (
      args: { name: string; description?: string; is_public?: boolean; is_downloadable?: boolean },
      ctx
    ) => {
      const created = await createDataset(ctx.client, {
        datasetName: args.name,
        datasetDescription: args.description ?? "",
        isDatasetPublic: args.is_public ?? false,
        isDatasetDownloadable: args.is_downloadable ?? false,
      });
      return (
        `Created dataset ${created.dataset.did} "${created.dataset.name}" ` +
        `(${created.dataset.isPublic ? "public" : "private"}).\n` +
        `Next: dataset_upload_file to add files, then dataset_create_version to commit them.`
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_update",
    title: "Update dataset metadata",
    description:
      "Rename a dataset, change its description, or change its visibility. Only the fields you pass are " +
      "changed. Visibility changes are idempotent — passing the value it already has is a no-op.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      name: z.string().min(1).optional().describe("New name"),
      description: z.string().optional().describe("New description"),
      is_public: z.boolean().optional().describe("Desired visibility"),
      is_downloadable: z.boolean().optional().describe("Desired downloadability (owner only)"),
    },
    handler: async (
      args: { did: number; name?: string; description?: string; is_public?: boolean; is_downloadable?: boolean },
      ctx
    ) => {
      const changes: string[] = [];
      if (args.name !== undefined) {
        await updateDatasetName(ctx.client, args.did, args.name);
        changes.push(`name -> "${args.name}"`);
      }
      if (args.description !== undefined) {
        await updateDatasetDescription(ctx.client, args.did, args.description);
        changes.push("description updated");
      }
      if (args.is_public !== undefined) {
        const changed = await setDatasetPublic(ctx.client, args.did, args.is_public);
        changes.push(
          changed
            ? `visibility -> ${args.is_public ? "public" : "private"}`
            : `visibility already ${args.is_public ? "public" : "private"}`
        );
      }
      if (args.is_downloadable !== undefined) {
        const changed = await setDatasetDownloadable(ctx.client, args.did, args.is_downloadable);
        changes.push(
          changed ? `downloadable -> ${args.is_downloadable}` : `downloadable already ${args.is_downloadable}`
        );
      }
      if (changes.length === 0) {
        throw new ToolError("Nothing to update — pass at least one of name, description, is_public, is_downloadable.");
      }
      return `Dataset ${args.did}: ${changes.join("; ")}.`;
    },
  });

  registerTool(server, context, {
    name: "dataset_delete",
    title: "Delete a dataset",
    description:
      "Permanently delete a dataset, all of its versions and all of its files. This cannot be undone and " +
      "will break any workflow that reads from it. Requires confirm_name to exactly match the dataset's " +
      "current name — show the user what will be deleted and get their agreement before calling this.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      confirm_name: z.string().describe("The dataset's exact current name, as a confirmation"),
    },
    annotations: { destructiveHint: true },
    handler: async (args: { did: number; confirm_name: string }, ctx) => {
      const dataset = await getDataset(ctx.client, args.did);
      requireExactName(dataset.dataset.name, args.confirm_name, "dataset", args.did);
      await deleteDataset(ctx.client, args.did);
      return `Deleted dataset ${args.did} "${dataset.dataset.name}" and all of its versions.`;
    },
  });

  registerTool(server, context, {
    name: "dataset_list_versions",
    title: "List dataset versions",
    description: "List a dataset's committed versions, newest first.",
    inputSchema: { did: z.number().int().describe("Dataset id") },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { did: number }, ctx) => {
      const versions = await listDatasetVersions(ctx.client, args.did);
      if (versions.length === 0) {
        return `Dataset ${args.did} has no versions yet. Upload files, then call dataset_create_version.`;
      }
      return formatTable(
        ["dvid", "name", "created", "commit"],
        versions.map(version => [
          version.dvid,
          version.name,
          formatTimestamp(version.creationTime),
          version.versionHash?.slice(0, 12),
        ])
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_create_version",
    title: "Commit staged changes as a new dataset version",
    description:
      "Commit every staged upload and deletion as a new immutable version. This is the step that makes " +
      "uploaded files readable by workflows — without it the files exist but no operator can see them. " +
      "Fails if nothing is staged.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      name: z.string().optional().describe("Optional label; the deployment prefixes it with v1, v2, …"),
    },
    handler: async (args: { did: number; name?: string }, ctx) => {
      try {
        const created = await createDatasetVersion(ctx.client, args.did, args.name ?? "");
        const dataset = await getDataset(ctx.client, args.did);
        const rootPath = versionRootPath(dataset.ownerEmail, dataset.dataset.name, created.datasetVersion.name);
        const files = flattenFileNodes(created.fileNodes ?? [], rootPath);
        return joinSections(
          `Committed version "${created.datasetVersion.name}" (dvid ${created.datasetVersion.dvid}) of dataset ${args.did}.`,
          files.length === 0
            ? undefined
            : joinSections(
                "Files in this version, with the path to use in an operator's fileName property:",
                formatTable(
                  ["file", "size", "workflow path"],
                  files.map(file => [file.relativePath, formatBytes(file.sizeBytes), file.workflowPath])
                )
              )
        );
      } catch (error) {
        // The backend answers "nothing staged" with a 400; that is an expected
        // state, not a failure the model should retry.
        if (error instanceof TexeraApiError && error.status === 400 && /No changes detected/i.test(error.body)) {
          throw new ToolError(
            `Dataset ${args.did} has no staged changes, so there is nothing to commit. ` +
              `Upload or delete a file first.`
          );
        }
        throw error;
      }
    },
  });

  registerTool(server, context, {
    name: "dataset_list_files",
    title: "List the files in a dataset version",
    description:
      "List the files in a committed dataset version. Each row includes the `workflow path` — the exact " +
      "string to put in a file-reading operator's fileName property (e.g. CSVFileScan). " +
      "Defaults to the newest version.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      version: z
        .union([z.number().int(), z.string()])
        .optional()
        .describe("Version id (dvid) or version name. Defaults to the newest version."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { did: number; version?: number | string }, ctx) => {
      const [dataset, version] = await Promise.all([
        getDataset(ctx.client, args.did),
        resolveVersion(ctx, args.did, args.version),
      ]);
      const response = await getDatasetVersionFileNodes(ctx.client, args.did, version.dvid);
      const rootPath = versionRootPath(dataset.ownerEmail, dataset.dataset.name, version.name);
      const files = flattenFileNodes(response.fileNodes, rootPath);

      if (files.length === 0) {
        return `Version "${version.name}" of dataset ${args.did} contains no files.`;
      }

      return joinSections(
        `Version "${version.name}" (dvid ${version.dvid}) of dataset "${dataset.dataset.name}" — ${files.length} file(s), ${formatBytes(response.size)}:`,
        formatTable(
          ["file", "size", "workflow path"],
          files.map(file => [file.relativePath, formatBytes(file.sizeBytes), file.workflowPath])
        )
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_upload_file",
    title: "Upload a text file into a dataset",
    description:
      `Upload UTF-8 text content as a file in a dataset. ${COMMIT_NOTE} ` +
      "Intended for content the assistant can produce or has read (CSV, JSON, JSONL, text). " +
      "Binary formats are not supported here — upload those through the Texera web UI.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      file_path: z
        .string()
        .min(1)
        .describe('Path within the dataset, e.g. "data/cases.csv". Directories are created implicitly.'),
      content: z.string().describe("UTF-8 file content"),
      message: z.string().optional().describe("Optional note recorded with the change"),
    },
    handler: async (args: { did: number; file_path: string; content: string; message?: string }, ctx) => {
      const bytes = new TextEncoder().encode(args.content);
      if (bytes.byteLength > ctx.config.maxUploadBytes) {
        throw new ToolError(
          `That content is ${formatBytes(bytes.byteLength)}, over the ${formatBytes(ctx.config.maxUploadBytes)} ` +
            `upload limit for this server. Split it into smaller files, or upload it through the Texera web UI. ` +
            `(The limit is configurable with TEXERA_MAX_UPLOAD_BYTES.)`
        );
      }
      if (args.file_path.startsWith("/") || args.file_path.includes("..")) {
        throw new ToolError(
          `Invalid file_path "${args.file_path}": use a relative path inside the dataset, without ".." segments.`
        );
      }

      await uploadFile(ctx.client, args.did, args.file_path, bytes, { message: args.message });
      return (
        `Uploaded ${args.file_path} (${formatBytes(bytes.byteLength)}) to dataset ${args.did}.\n` +
        `${COMMIT_NOTE} Call dataset_create_version when you have finished uploading.`
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_delete_file",
    title: "Delete a file from a dataset",
    description:
      `Stage the deletion of one file from a dataset's working branch. ${COMMIT_NOTE} ` +
      "Existing committed versions keep the file — this only affects versions created afterwards.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      file_path: z.string().min(1).describe('Path within the dataset, e.g. "data/cases.csv"'),
    },
    annotations: { destructiveHint: true },
    handler: async (args: { did: number; file_path: string }, ctx) => {
      await deleteFile(ctx.client, args.did, args.file_path);
      return `Staged deletion of ${args.file_path} from dataset ${args.did}. ${COMMIT_NOTE}`;
    },
  });

  registerTool(server, context, {
    name: "dataset_read_file",
    title: "Read a file from a dataset version",
    description:
      "Read the contents of a text file from a committed dataset version, truncated to fit. " +
      "Use it to inspect data before building a workflow over it — for example to see a CSV's header row.",
    inputSchema: {
      did: z.number().int().describe("Dataset id"),
      file_path: z.string().min(1).describe('Path within the dataset, e.g. "data/cases.csv"'),
      version: z
        .union([z.number().int(), z.string()])
        .optional()
        .describe("Version id (dvid) or name. Defaults to the newest version."),
      max_chars: z.number().int().positive().optional().describe("Cap on returned characters"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { did: number; file_path: string; version?: number | string; max_chars?: number }, ctx) => {
      const [dataset, version] = await Promise.all([
        getDataset(ctx.client, args.did),
        resolveVersion(ctx, args.did, args.version),
      ]);
      const repositoryName = dataset.dataset.repositoryName;
      if (!repositoryName) {
        throw new ToolError(`Dataset ${args.did} has no storage repository recorded; it may be mid-creation.`);
      }

      const url = await getPresignedDownloadUrl(ctx.client, {
        filePath: args.file_path,
        repositoryName,
        commitHash: version.versionHash,
      });
      if (!url) {
        throw new ToolError(
          `The deployment did not return a download URL for ${args.file_path} in version "${version.name}". ` +
            `Check the path with dataset_list_files.`
        );
      }

      // The presigned URL points at object storage, not at Texera, so it is
      // fetched directly and must not carry the Texera bearer token.
      const response = await fetch(url);
      if (!response.ok) {
        throw new ToolError(
          `Could not download ${args.file_path} from version "${version.name}": ${response.status} ${response.statusText}. ` +
            `Check the path with dataset_list_files.`
        );
      }
      const text = await response.text();
      const limit = Math.min(args.max_chars ?? ctx.config.maxResultChars, ctx.config.maxResultChars);

      return joinSections(
        `${args.file_path} from version "${version.name}" of dataset "${dataset.dataset.name}" (${formatBytes(text.length)}):`,
        truncate(text, limit)
      );
    },
  });

  registerTool(server, context, {
    name: "dataset_uncommitted_changes",
    title: "Show staged, uncommitted dataset changes",
    description:
      "List the uploads and deletions staged on a dataset that have not been committed to a version yet. " +
      "Anything listed here is invisible to workflows until dataset_create_version runs.",
    inputSchema: { did: z.number().int().describe("Dataset id") },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { did: number }, ctx) => {
      const diffs = await getUncommittedChanges(ctx.client, args.did);
      if (diffs.length === 0) {
        return `Dataset ${args.did} has no staged changes — everything is committed.`;
      }
      return joinSections(
        `${diffs.length} staged change(s) on dataset ${args.did}:`,
        formatTable(
          ["change", "path", "size"],
          diffs.map(diff => [diff.diffType, diff.path, formatBytes(diff.sizeBytes)])
        ),
        "Call dataset_create_version to commit them."
      );
    },
  });
}
