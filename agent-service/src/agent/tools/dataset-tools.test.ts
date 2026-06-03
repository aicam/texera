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

import { afterEach, describe, expect, test } from "bun:test";
import {
  collectDatasetFilePaths,
  createListDatasetFilesTool,
  createListDatasetsTool,
  formatAccessibleDatasets,
  formatDatasetFilePaths,
  type DatasetToolConfig,
} from "./dataset-tools";
import type { DatasetFileNode } from "../../api/dataset-api";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function mockJsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
    ...init,
  });
}

function setMockFetch(handler: (url: string | URL | Request, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = handler as unknown as typeof fetch;
}

const config: DatasetToolConfig = { userToken: "token" };

describe("dataset tools", () => {
  test("formats accessible datasets with visibility, ownership, and access", () => {
    const text = formatAccessibleDatasets([
      {
        isOwner: true,
        ownerEmail: "alice@example.com",
        accessPrivilege: "WRITE",
        size: 12,
        dataset: {
          did: 1,
          name: "private_sales",
          isPublic: false,
          isDownloadable: true,
          description: "private data",
        },
      },
      {
        isOwner: false,
        ownerEmail: "bob@example.com",
        accessPrivilege: "READ",
        size: 34,
        dataset: {
          did: 2,
          name: "public_census",
          isPublic: true,
          isDownloadable: false,
          description: "",
        },
      },
    ]);

    expect(text).toContain("Accessible datasets (2):");
    expect(text).toContain(
      "did=1, name=private_sales, owner=alice@example.com, visibility=private, access=WRITE, ownership=owned"
    );
    expect(text).toContain(
      "did=2, name=public_census, owner=bob@example.com, visibility=public, access=READ, ownership=shared"
    );
    expect(text).not.toContain("size=");
  });

  test("returns a clear message for an empty dataset list", () => {
    expect(formatAccessibleDatasets([])).toBe("No accessible datasets found.");
  });

  test("collects file paths recursively and ignores directories", () => {
    const nodes: DatasetFileNode[] = [
      {
        name: "raw",
        type: "directory",
        parentDir: "/alice@example.com/sales/v1",
        children: [
          {
            name: "data.csv",
            type: "file",
            parentDir: "/alice@example.com/sales/v1/raw",
            size: 100,
          },
        ],
      },
      {
        name: "README.md",
        type: "file",
        parentDir: "/alice@example.com/sales/v1",
        size: 10,
      },
    ];

    expect(collectDatasetFilePaths(nodes)).toEqual([
      { path: "/alice@example.com/sales/v1/raw/data.csv", size: 100 },
      { path: "/alice@example.com/sales/v1/README.md", size: 10 },
    ]);
  });

  test("formats file paths with dataset version context", () => {
    const text = formatDatasetFilePaths({ did: 1, dvid: 2, versionName: "v1" }, [
      { path: "/alice@example.com/sales/v1/raw/data.csv", size: 100 },
    ]);

    expect(text).toBe(
      "Files in dataset did=1, version=v1 (dvid=2):\n- /alice@example.com/sales/v1/raw/data.csv (100 bytes)"
    );
  });

  test("listDatasets tool applies visibility filters", async () => {
    setMockFetch(async () =>
      mockJsonResponse([
        {
          isOwner: true,
          ownerEmail: "alice@example.com",
          accessPrivilege: "WRITE",
          size: 0,
          dataset: { did: 1, name: "private_sales", isPublic: false, isDownloadable: true, description: "" },
        },
        {
          isOwner: false,
          ownerEmail: "bob@example.com",
          accessPrivilege: "READ",
          size: 0,
          dataset: { did: 2, name: "public_census", isPublic: true, isDownloadable: true, description: "" },
        },
      ])
    );

    const toolDef = createListDatasetsTool(() => config);
    const result = await (toolDef as any).execute({ visibility: "public", ownership: "all" });

    expect(result).toContain("did=2");
    expect(result).not.toContain("did=1");
  });

  test("listDatasetFiles tool defaults to the latest version", async () => {
    const calls: string[] = [];
    setMockFetch(async (url: string | URL | Request) => {
      calls.push(String(url));
      return mockJsonResponse({
        datasetVersion: { did: 1, dvid: 9, creatorUid: 1, name: "v2", versionHash: "abc" },
        fileNodes: [{ name: "data.csv", type: "file", parentDir: "/alice@example.com/sales/v2", size: 42 }],
      });
    });

    const toolDef = createListDatasetFilesTool(() => config);
    const result = await (toolDef as any).execute({ did: 1 });

    expect(result).toContain("version=v2 (dvid=9)");
    expect(result).toContain("/alice@example.com/sales/v2/data.csv");
    expect(calls).toEqual(["http://localhost:9092/api/dataset/1/version/latest"]);
  });

  test("listDatasetFiles tool reports invalid dataset IDs", async () => {
    const toolDef = createListDatasetFilesTool(() => config);
    const result = await (toolDef as any).execute({ did: 0 });

    expect(result).toBe("[ERROR] did must be a positive integer.");
  });
});
