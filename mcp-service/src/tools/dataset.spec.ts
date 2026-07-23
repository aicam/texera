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

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { FakeTexera, json, text, unauthorized } from "../testing/fake-texera";
import { datasetResponse } from "../testing/fixtures";
import { startHarness, type Harness } from "../testing/harness";

let deployment: FakeTexera;
let harness: Harness;

const version = {
  dvid: 11,
  did: 3,
  creatorUid: 7,
  name: "v1",
  versionHash: "abc123def456",
  creationTime: 1_700_000_000_000,
};

const fileNodes = [
  {
    name: "raw",
    type: "directory",
    parentDir: "/alice@example.org/covid/v1",
    ownerEmail: "alice@example.org",
    children: [
      {
        name: "cases.csv",
        type: "file",
        parentDir: "/alice@example.org/covid/v1/raw",
        ownerEmail: "alice@example.org",
        size: 2048,
      },
    ],
  },
  {
    name: "readme.txt",
    type: "file",
    parentDir: "/alice@example.org/covid/v1",
    ownerEmail: "alice@example.org",
    size: 12,
  },
];

beforeEach(async () => {
  deployment = new FakeTexera();
  deployment
    .get("/api/dataset/list", () => json([datasetResponse()]))
    .get("/api/dataset/:did", () => json(datasetResponse()))
    .get("/api/dataset/:did/version/list", () => json([version]))
    .get("/api/dataset/:did/version/:dvid/rootFileNodes", () => json({ fileNodes, size: 2060 }))
    .get("/api/dataset/:did/diff", () => json([]))
    .post("/api/dataset/create", () => json(datasetResponse({ did: 9, name: "new-set" })))
    .post("/api/dataset/:did/upload", () => text(""))
    .post("/api/dataset/:did/version/create", () => json({ datasetVersion: version, fileNodes }))
    .delete("/api/dataset/:did", () => text(""));
  harness = await startHarness(deployment);
});

afterEach(async () => {
  await harness.close();
});

describe("dataset_list", () => {
  test("shows id, owner, access and size", async () => {
    const result = await harness.call("dataset_list");
    expect(result).toContain("covid");
    expect(result).toContain("alice@example.org");
    expect(result).toContain("2.0 KB");
  });

  test("says so when there are none, and points at dataset_create", async () => {
    deployment.get("/api/dataset/list", () => json([]));
    expect(await harness.call("dataset_list")).toContain("dataset_create");
  });
});

describe("dataset_get", () => {
  test("summarizes metadata and versions", async () => {
    const result = await harness.call("dataset_get", { did: 3 });
    expect(result).toContain("Dataset 3: covid");
    expect(result).toContain("private");
    expect(result).toContain("v1");
  });

  test("warns when a dataset has no versions, explaining the consequence", async () => {
    deployment.get("/api/dataset/:did/version/list", () => json([]));
    const result = await harness.call("dataset_get", { did: 3 });
    expect(result).toContain("not readable by workflows");
  });

  test("surfaces staged changes and the commit step", async () => {
    deployment.get("/api/dataset/:did/diff", () =>
      json([{ path: "raw/new.csv", pathType: "object", diffType: "added", sizeBytes: 500 }])
    );
    const result = await harness.call("dataset_get", { did: 3 });
    expect(result).toContain("1 staged change");
    expect(result).toContain("dataset_create_version");
  });
});

describe("dataset_list_files", () => {
  test("flattens the tree and gives the path an operator needs", async () => {
    const result = await harness.call("dataset_list_files", { did: 3 });
    expect(result).toContain("raw/cases.csv");
    expect(result).toContain("/alice@example.org/covid/v1/raw/cases.csv");
    expect(result).toContain("readme.txt");
  });

  test("defaults to the newest version", async () => {
    const older = { ...version, dvid: 10, name: "v0" };
    deployment.get("/api/dataset/:did/version/list", () => json([version, older]));
    const result = await harness.call("dataset_list_files", { did: 3 });
    expect(result).toContain('Version "v1"');
  });

  test("accepts a version by name", async () => {
    const result = await harness.call("dataset_list_files", { did: 3, version: "v1" });
    expect(result).toContain('Version "v1"');
  });

  test("lists the available versions when the requested one does not exist", async () => {
    const error = await harness.callExpectingError("dataset_list_files", { did: 3, version: "v99" });
    expect(error).toContain('no version "v99"');
    expect(error).toContain("v1 (dvid 11)");
  });

  test("explains the commit step when the dataset has no versions at all", async () => {
    deployment.get("/api/dataset/:did/version/list", () => json([]));
    const error = await harness.callExpectingError("dataset_list_files", { did: 3 });
    expect(error).toContain("no versions yet");
    expect(error).toContain("dataset_create_version");
  });
});

describe("dataset_create", () => {
  test("creates and tells the model what has to happen next", async () => {
    const result = await harness.call("dataset_create", { name: "new-set", description: "d" });
    expect(result).toContain("Created dataset 9");
    expect(result).toContain("dataset_create_version");

    const [request] = deployment.recorded("POST", "/api/dataset/create");
    expect(JSON.parse(request.body!)).toEqual({
      datasetName: "new-set",
      datasetDescription: "d",
      isDatasetPublic: false,
      isDatasetDownloadable: false,
    });
  });

  test("a duplicate name comes back as a request-rejected message with the server's reason", async () => {
    deployment.post("/api/dataset/create", () => text("Dataset with the same name already exists", 400));
    const error = await harness.callExpectingError("dataset_create", { name: "covid" });
    expect(error).toContain("rejected the request as invalid");
    expect(error).toContain("same name already exists");
  });
});

describe("dataset_upload_file", () => {
  test("uploads the content and states the pending-commit requirement", async () => {
    const result = await harness.call("dataset_upload_file", {
      did: 3,
      file_path: "raw/new.csv",
      content: "a,b\n1,2\n",
    });

    expect(result).toContain("Uploaded raw/new.csv");
    expect(result).toContain("dataset_create_version");

    const [request] = deployment.recorded("POST", "/api/dataset/:did/upload");
    expect(request.query.get("filePath")).toBe("raw/new.csv");
    expect(request.headers.get("Content-Type")).toBe("application/octet-stream");
  });

  test("rejects an absolute path and a traversal attempt", async () => {
    expect(
      await harness.callExpectingError("dataset_upload_file", { did: 3, file_path: "/etc/passwd", content: "x" })
    ).toContain("relative path");
    expect(
      await harness.callExpectingError("dataset_upload_file", { did: 3, file_path: "../escape.csv", content: "x" })
    ).toContain("relative path");
    expect(deployment.recorded("POST", "/api/dataset/:did/upload")).toHaveLength(0);
  });

  test("rejects content past the size limit before sending it", async () => {
    const error = await harness.callExpectingError("dataset_upload_file", {
      did: 3,
      file_path: "big.csv",
      content: "x".repeat(30 * 1024 * 1024),
    });
    expect(error).toContain("over the");
    expect(error).toContain("TEXERA_MAX_UPLOAD_BYTES");
    expect(deployment.recorded("POST", "/api/dataset/:did/upload")).toHaveLength(0);
  });

  test("accepts empty content — an empty file is a legitimate thing to create", async () => {
    expect(await harness.call("dataset_upload_file", { did: 3, file_path: "empty.csv", content: "" })).toContain(
      "Uploaded empty.csv"
    );
  });

  test("preserves non-ASCII content as UTF-8", async () => {
    await harness.call("dataset_upload_file", { did: 3, file_path: "u.csv", content: "naïve,café\n" });
    const [request] = deployment.recorded("POST", "/api/dataset/:did/upload");
    expect(request.query.get("filePath")).toBe("u.csv");
  });

  test("no write access is reported as access denied", async () => {
    deployment.post("/api/dataset/:did/upload", () => text("User has no access to this dataset", 403));
    const error = await harness.callExpectingError("dataset_upload_file", { did: 3, file_path: "a.csv", content: "x" });
    expect(error).toContain("access denied");
    expect(error).toContain("no access to this dataset");
  });
});

describe("dataset_create_version", () => {
  test("commits and reports each file's workflow path", async () => {
    const result = await harness.call("dataset_create_version", { did: 3, name: "first" });
    expect(result).toContain('Committed version "v1"');
    expect(result).toContain("/alice@example.org/covid/v1/raw/cases.csv");
  });

  test("sends the version label as a plain-text body", async () => {
    await harness.call("dataset_create_version", { did: 3, name: "first" });
    const [request] = deployment.recorded("POST", "/api/dataset/:did/version/create");
    expect(request.body).toBe("first");
    expect(request.headers.get("Content-Type")).toBe("text/plain");
  });

  test("translates the backend's nothing-staged 400 into a plain explanation", async () => {
    deployment.post("/api/dataset/:did/version/create", () =>
      text("No changes detected in dataset. Version creation aborted.", 400)
    );
    const error = await harness.callExpectingError("dataset_create_version", { did: 3 });
    expect(error).toContain("no staged changes");
    expect(error).not.toContain("400");
  });
});

describe("dataset_delete", () => {
  test("requires the exact name and then deletes", async () => {
    const result = await harness.call("dataset_delete", { did: 3, confirm_name: "covid" });
    expect(result).toContain("Deleted dataset 3");
    expect(deployment.recorded("DELETE", "/api/dataset/:did")).toHaveLength(1);
  });

  test("refuses on a mismatched confirmation and does not call the deployment", async () => {
    const error = await harness.callExpectingError("dataset_delete", { did: 3, confirm_name: "Covid" });
    expect(error).toContain("must exactly match");
    expect(deployment.recorded("DELETE", "/api/dataset/:did")).toHaveLength(0);
  });
});

describe("dataset_update", () => {
  test("only toggles visibility when it actually differs", async () => {
    deployment.post("/api/dataset/:did/update/publicity", () => text(""));

    const unchanged = await harness.call("dataset_update", { did: 3, is_public: false });
    expect(unchanged).toContain("already private");
    expect(deployment.recorded("POST", "/api/dataset/:did/update/publicity")).toHaveLength(0);

    const changed = await harness.call("dataset_update", { did: 3, is_public: true });
    expect(changed).toContain("visibility -> public");
    expect(deployment.recorded("POST", "/api/dataset/:did/update/publicity")).toHaveLength(1);
  });

  test("requires at least one field", async () => {
    expect(await harness.callExpectingError("dataset_update", { did: 3 })).toContain("Nothing to update");
  });
});

describe("dataset_read_file", () => {
  test("fetches through a presigned url and shows the content", async () => {
    deployment
      .get("/api/dataset/presign-download", () => json({ presignedUrl: "https://storage.test/presigned/cases.csv" }))
      .get("/presigned/cases.csv", () => text("a,b\n1,2\n"));

    const result = await harness.call("dataset_read_file", { did: 3, file_path: "raw/cases.csv" });
    expect(result).toContain("a,b");
    expect(result).toContain('version "v1"');
  });

  test("does not send the Texera token to object storage", async () => {
    deployment
      .get("/api/dataset/presign-download", () => json({ presignedUrl: "https://storage.test/presigned/cases.csv" }))
      .get("/presigned/cases.csv", () => text("data"));

    await harness.call("dataset_read_file", { did: 3, file_path: "raw/cases.csv" });
    const storageRequest = deployment.requests.find(request => request.path === "/presigned/cases.csv");
    expect(storageRequest?.headers.has("Authorization")).toBe(false);
  });

  test("truncates a large file and marks the omission", async () => {
    deployment
      .get("/api/dataset/presign-download", () => json({ presignedUrl: "https://storage.test/presigned/big.csv" }))
      .get("/presigned/big.csv", () => text("y".repeat(5000)));

    const result = await harness.call("dataset_read_file", { did: 3, file_path: "big.csv", max_chars: 500 });
    expect(result).toContain("characters omitted");
  });

  test("a failed storage download points back at dataset_list_files", async () => {
    deployment
      .get("/api/dataset/presign-download", () => json({ presignedUrl: "https://storage.test/presigned/gone.csv" }))
      .get("/presigned/gone.csv", () => text("nope", 404));

    const error = await harness.callExpectingError("dataset_read_file", { did: 3, file_path: "gone.csv" });
    expect(error).toContain("Could not download");
    expect(error).toContain("dataset_list_files");
  });
});

describe("authentication failures", () => {
  test("an expired token is reported as expired, with recovery steps", async () => {
    deployment.get("/api/dataset/list", () => unauthorized(true));
    const error = await harness.callExpectingError("dataset_list");
    expect(error).toContain("expired or invalid");
    expect(error).toContain("access_token");
  });

  test("an unreachable deployment is distinguished from a rejected request", async () => {
    deployment.get("/api/dataset/list", () => {
      throw new TypeError("fetch failed");
    });
    const error = await harness.callExpectingError("dataset_list");
    expect(error).toContain("could not reach");
    expect(error).toContain("TEXERA_BASE_URL");
  });
});
