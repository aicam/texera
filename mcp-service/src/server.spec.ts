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
import { FakeTexera, json, text } from "./testing/fake-texera";
import { datasetResponse, OPERATOR_METADATA, workflowResponse } from "./testing/fixtures";
import { startHarness, type Harness } from "./testing/harness";

let deployment: FakeTexera;
let harness: Harness;

beforeEach(async () => {
  deployment = new FakeTexera();
  deployment
    .get("/api/healthcheck", () => text("OK"))
    .get("/api/config/pre-login", () => json({ localLogin: true, googleLogin: false }))
    .get("/api/config/gui", () => json({ sharingComputingUnitEnabled: true }))
    .get("/api/resources/operator-metadata", () => json(OPERATOR_METADATA))
    .get("/api/workflow/:wid", () => json(workflowResponse()))
    .get("/api/dataset/:did", () => json(datasetResponse()))
    .get("/api/dataset/:did/version/list", () => json([]))
    .get("/api/access/workflow/list/:wid", () => json([{ email: "bob@example.org", name: "bob", privilege: "READ" }]))
    .get("/api/access/workflow/owner/:wid", () => text("alice@example.org"))
    .put("/api/access/workflow/grant/:wid/:email/:privilege", () => text(""));
  harness = await startHarness(deployment);
});

afterEach(async () => {
  await harness.close();
});

describe("tool surface", () => {
  test("exposes the dataset, workflow, execution and sharing tools", async () => {
    const names = (await harness.client.listTools()).tools.map(tool => tool.name);

    for (const expected of [
      "texera_whoami",
      "dataset_list",
      "dataset_create",
      "dataset_upload_file",
      "dataset_create_version",
      "workflow_list",
      "workflow_open",
      "workflow_add_operator",
      "workflow_validate",
      "workflow_save",
      "workflow_run",
      "operator_list_types",
      "operator_get_schema",
      "computing_unit_list",
      "workflow_share",
    ]) {
      expect(names).toContain(expected);
    }
  });

  test("marks read-only tools so a client can auto-approve them", async () => {
    const tools = (await harness.client.listTools()).tools;
    const byName = new Map(tools.map(tool => [tool.name, tool]));

    expect(byName.get("dataset_list")?.annotations?.readOnlyHint).toBe(true);
    expect(byName.get("workflow_describe")?.annotations?.readOnlyHint).toBe(true);
    expect(byName.get("operator_get_schema")?.annotations?.readOnlyHint).toBe(true);
  });

  test("marks destructive tools so a client asks first", async () => {
    const byName = new Map((await harness.client.listTools()).tools.map(tool => [tool.name, tool]));

    for (const name of [
      "dataset_delete",
      "workflow_delete",
      "workflow_delete_operator",
      "computing_unit_terminate",
      "workflow_share",
      "dataset_share",
    ]) {
      expect(byName.get(name)?.annotations?.destructiveHint).toBe(true);
    }
  });

  test("never marks a mutating tool read-only", async () => {
    const tools = (await harness.client.listTools()).tools;
    const mutating = ["dataset_create", "workflow_save", "workflow_add_operator", "dataset_upload_file"];
    for (const name of mutating) {
      expect(tools.find(tool => tool.name === name)?.annotations?.readOnlyHint).not.toBe(true);
    }
  });

  test("every tool has a description the model can act on", async () => {
    for (const tool of (await harness.client.listTools()).tools) {
      expect(tool.description?.length ?? 0).toBeGreaterThan(40);
    }
  });
});

describe("server instructions", () => {
  test("state the two ordering rules that cause silent failures", async () => {
    const instructions = harness.client.getInstructions() ?? "";
    expect(instructions).toContain("dataset_create_version");
    expect(instructions).toContain("workflow_save");
    expect(instructions).toContain("staged");
  });
});

describe("texera_whoami", () => {
  test("reports the deployment, the account and the token expiry", async () => {
    const result = await harness.call("texera_whoami");
    expect(result).toContain("https://texera.test");
    expect(result).toContain("alice");
    expect(result).toContain("alice@example.org");
    expect(result).toContain("healthcheck OK");
  });

  test("warns loudly when the deployment does not answer its healthcheck", async () => {
    deployment.get("/api/healthcheck", () => text("down", 503));
    const result = await harness.call("texera_whoami");
    expect(result).toContain("WARNING");
    expect(result).toContain("TEXERA_BASE_URL may be wrong");
  });

  test("still reports identity when the optional config endpoints are missing", async () => {
    deployment.get("/api/config/pre-login", () => text("not found", 404));
    deployment.get("/api/config/gui", () => text("not found", 404));
    expect(await harness.call("texera_whoami")).toContain("healthcheck OK");
  });

  test("lists workflows currently open for editing", async () => {
    await harness.call("workflow_open", { wid: 42 });
    expect(await harness.call("texera_whoami")).toContain('42 ("Covid analysis")');
  });
});

describe("resources", () => {
  test("publishes the operator catalogue as a readable resource", async () => {
    const resources = (await harness.client.listResources()).resources;
    expect(resources.map(resource => resource.uri)).toContain("texera://operator-metadata");

    const read = await harness.client.readResource({ uri: "texera://operator-metadata" });
    const catalogue = JSON.parse((read.contents[0] as { text: string }).text);
    expect(Object.keys(catalogue)).toContain("CSVFileScan");
  });

  test("serves a workflow by uri", async () => {
    const read = await harness.client.readResource({ uri: "texera://workflow/42" });
    const workflow = JSON.parse((read.contents[0] as { text: string }).text);
    expect(workflow.wid).toBe(42);
    expect(workflow.content.operators).toHaveLength(2);
  });

  test("serves a dataset by uri", async () => {
    const read = await harness.client.readResource({ uri: "texera://dataset/3" });
    const dataset = JSON.parse((read.contents[0] as { text: string }).text);
    expect(dataset.dataset.name).toBe("covid");
  });
});

describe("prompts", () => {
  test("offers the build-from-dataset walkthrough in the required order", async () => {
    expect((await harness.client.listPrompts()).prompts.map(prompt => prompt.name)).toContain(
      "build_workflow_from_dataset"
    );

    const prompt = await harness.client.getPrompt({
      name: "build_workflow_from_dataset",
      arguments: { goal: "count cases by region" },
    });
    const rendered = (prompt.messages[0].content as { text: string }).text;

    expect(rendered).toContain("count cases by region");
    expect(rendered).toContain("dataset_create_version");
    expect(rendered.indexOf("workflow_validate")).toBeLessThan(rendered.indexOf("workflow_save"));
  });
});

describe("sharing", () => {
  test("lists who a workflow is shared with, including its owner", async () => {
    const result = await harness.call("workflow_list_access", { wid: 42 });
    expect(result).toContain("owner: alice@example.org");
    expect(result).toContain("bob@example.org");
  });

  test("grants access with the exact email and privilege it was given", async () => {
    const result = await harness.call("workflow_share", { wid: 42, email: "bob@example.org", privilege: "WRITE" });
    expect(result).toContain("Granted WRITE");

    const [request] = deployment.recorded("PUT", "/api/access/workflow/grant/:wid/:email/:privilege");
    expect(request.path).toContain(encodeURIComponent("bob@example.org"));
    expect(request.path).toEndWith("/WRITE");
  });

  test("rejects a privilege outside READ/WRITE at the schema boundary", async () => {
    const error = await harness.callExpectingError("workflow_share", {
      wid: 42,
      email: "bob@example.org",
      privilege: "OWNER",
    });
    expect(error.toLowerCase()).toContain("invalid");
    expect(deployment.recorded("PUT", "/api/access/workflow/grant/:wid/:email/:privilege")).toHaveLength(0);
  });
});

describe("operator catalogue tools", () => {
  test("lists operator types with descriptions", async () => {
    const result = await harness.call("operator_list_types");
    expect(result).toContain("CSVFileScan");
    expect(result).toContain("Read a CSV file");
  });

  test("filters by search term", async () => {
    const result = await harness.call("operator_list_types", { search: "csv" });
    expect(result).toContain("CSVFileScan");
    expect(result).not.toContain("Join");
  });

  test("suggests alternatives when a search matches nothing", async () => {
    const result = await harness.call("operator_list_types", { search: "kafka" });
    expect(result).toContain("No operator type matches");
    expect(result).toContain("3 operator types");
  });

  test("shows required properties and port layout for a type", async () => {
    const result = await harness.call("operator_get_schema", { operator_type: "CSVFileScan" });
    expect(result).toContain("Required properties: fileName");
    expect(result).toContain("none (this is a source operator)");
    expect(result).toContain("customDelimiter");
  });

  test("names the ports of a multi-input operator", async () => {
    const result = await harness.call("operator_get_schema", { operator_type: "Join" });
    expect(result).toContain("0=left");
    expect(result).toContain("1=right");
  });

  test("suggests a near match for an unknown type", async () => {
    const error = await harness.callExpectingError("operator_get_schema", { operator_type: "Filtr" });
    expect(error).toContain("Filter");
  });

  test("an unreachable catalogue is reported, and retried on the next call", async () => {
    deployment.get("/api/resources/operator-metadata", () => text("boom", 500));
    expect(await harness.callExpectingError("operator_list_types")).toContain("500");

    // A transient failure must not poison the rest of the session.
    deployment.get("/api/resources/operator-metadata", () => json(OPERATOR_METADATA));
    expect(await harness.call("operator_list_types")).toContain("CSVFileScan");
  });
});
