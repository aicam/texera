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
  buildDatasetApiUrl,
  getFullPathFromDatasetFileNode,
  listAccessibleDatasets,
  listDatasetVersions,
  retrieveDatasetVersionFileTree,
  retrieveLatestDatasetVersion,
  type DatasetFileNode,
} from "./dataset-api";

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

describe("dataset-api", () => {
  test("builds dataset URLs for file-service endpoints with or without api prefix", () => {
    expect(buildDatasetApiUrl("http://localhost:9092", "/list")).toBe("http://localhost:9092/api/dataset/list");
    expect(buildDatasetApiUrl("http://localhost:9092/api", "/list")).toBe("http://localhost:9092/api/dataset/list");
    expect(buildDatasetApiUrl("http://localhost:9092/api/", "7/version/list")).toBe(
      "http://localhost:9092/api/dataset/7/version/list"
    );
  });

  test("lists accessible datasets through the file-service dataset route", async () => {
    const calls: Array<[string, RequestInit | undefined]> = [];
    setMockFetch(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push([String(url), init]);
      return mockJsonResponse([
        {
          isOwner: true,
          ownerEmail: "alice@example.com",
          accessPrivilege: "WRITE",
          size: 123,
          dataset: { did: 7, name: "sales", isPublic: false, isDownloadable: true, description: "" },
        },
      ]);
    });

    const datasets = await listAccessibleDatasets("token");

    expect(datasets[0].dataset.did).toBe(7);
    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe("http://localhost:9092/api/dataset/list");
    expect(calls[0][1]?.headers).toEqual({
      Authorization: "Bearer token",
      "Content-Type": "application/json",
    });
  });

  test("retrieves dataset versions and root file nodes", async () => {
    const calls: string[] = [];
    setMockFetch(async (url: string | URL | Request) => {
      calls.push(String(url));
      if (String(url).endsWith("/version/list")) {
        return mockJsonResponse([{ dvid: 11, did: 7, creatorUid: 1, name: "v1", versionHash: "abc" }]);
      }
      return mockJsonResponse({ fileNodes: [], size: 0 });
    });

    const versions = await listDatasetVersions("token", 7);
    const tree = await retrieveDatasetVersionFileTree("token", 7, 11);

    expect(versions[0].dvid).toBe(11);
    expect(tree.fileNodes).toEqual([]);
    expect(calls).toEqual([
      "http://localhost:9092/api/dataset/7/version/list",
      "http://localhost:9092/api/dataset/7/version/11/rootFileNodes",
    ]);
  });

  test("retrieves the latest dataset version with file nodes", async () => {
    setMockFetch(async () =>
      mockJsonResponse({
        datasetVersion: { dvid: 12, did: 7, creatorUid: 1, name: "v2", versionHash: "def" },
        fileNodes: [{ name: "data.csv", type: "file", parentDir: "/alice@example.com/sales/v2", size: 10 }],
      })
    );

    const latest = await retrieveLatestDatasetVersion("token", 7);

    expect(latest.datasetVersion.name).toBe("v2");
    expect(latest.fileNodes[0].name).toBe("data.csv");
  });

  test("includes response details when file-service rejects a request", async () => {
    setMockFetch(async () => new Response("no access", { status: 403, statusText: "Forbidden" }));

    await expect(listDatasetVersions("token", 7)).rejects.toThrow(
      "Failed to list dataset versions: 403 Forbidden - no access"
    );
  });

  test("builds full dataset paths from serialized file nodes", () => {
    const node: DatasetFileNode = {
      name: "data.csv",
      type: "file",
      parentDir: "/alice@example.com/sales/v1/raw",
      size: 100,
    };

    expect(getFullPathFromDatasetFileNode(node)).toBe("/alice@example.com/sales/v1/raw/data.csv");
  });
});
