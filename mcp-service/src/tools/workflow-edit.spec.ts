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
import type { WorkflowContent } from "@texera/sdk";
import { FakeTexera, json, text } from "../testing/fake-texera";
import { EMPTY_CONTENT, OPERATOR_METADATA, twoOperatorContent, workflowResponse } from "../testing/fixtures";
import { startHarness, type Harness } from "../testing/harness";

let deployment: FakeTexera;
let harness: Harness;
/** The workflow the fake deployment currently stores, mutated by /persist. */
let stored: ReturnType<typeof workflowResponse>;

function persistedContent(): WorkflowContent {
  return JSON.parse(stored.content) as WorkflowContent;
}

beforeEach(async () => {
  stored = workflowResponse();
  deployment = new FakeTexera();
  deployment
    .get("/api/resources/operator-metadata", () => json(OPERATOR_METADATA))
    .get("/api/workflow/:wid", () => json(stored))
    .post("/api/workflow/persist", request => {
      const body = JSON.parse(request.body ?? "{}");
      stored = { ...stored, ...body, lastModifiedTime: (stored.lastModifiedTime ?? 0) + 1000 };
      return json(stored);
    })
    .post("/api/compile", () =>
      json({
        operatorOutputSchemas: {
          scan1: { "0_false": [{ attributeName: "cases", attributeType: "integer" }] },
        },
        operatorErrors: {},
      })
    );
  harness = await startHarness(deployment);
});

afterEach(async () => {
  await harness.close();
});

describe("workflow_open", () => {
  test("loads the graph and reports operators and links", async () => {
    const result = await harness.call("workflow_open", { wid: 42 });

    expect(result).toContain('Workflow 42 "Covid analysis"');
    expect(result).toContain("scan1");
    expect(result).toContain("CSVFileScan");
    expect(result).toContain("filter1");
    expect(result).toContain("scan1:out0");
    expect(result).toContain("filter1:in0");
  });

  test("flags read-only access and points at the workaround", async () => {
    stored = workflowResponse({ readonly: true });
    const result = await harness.call("workflow_open", { wid: 42 });
    expect(result).toContain("read-only");
    expect(result).toContain("workflow_duplicate");
  });

  test("reports an empty workflow as empty rather than showing nothing", async () => {
    stored = workflowResponse({ content: EMPTY_CONTENT });
    expect(await harness.call("workflow_open", { wid: 42 })).toContain("empty");
  });

  test("a missing workflow becomes an actionable error", async () => {
    deployment.get("/api/workflow/:wid", () => text("not found", 404));
    const error = await harness.callExpectingError("workflow_open", { wid: 999 });
    expect(error).toContain("not found");
  });
});

describe("editing without an open workflow", () => {
  test("edit tools explain that nothing is open", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", { operator_type: "Filter" });
    expect(error).toContain("No workflow is open");
    expect(error).toContain("workflow_open");
  });

  test("describe explains it too", async () => {
    expect(await harness.callExpectingError("workflow_describe")).toContain("No workflow is open");
  });
});

describe("workflow_add_operator", () => {
  beforeEach(async () => {
    await harness.call("workflow_open", { wid: 42 });
  });

  test("adds an operator, wires its input and reports the connection", async () => {
    const result = await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter2",
      properties: { predicate: "deaths > 0" },
      inputs: { "0": ["scan1"] },
    });

    expect(result).toContain("Added filter2 (Filter)");
    expect(result).toContain("scan1 -> filter2:in0");
    expect(result).toContain("Unsaved");

    const graph = await harness.call("workflow_describe");
    expect(graph).toContain("filter2");
    expect(graph).toContain("UNSAVED CHANGES");
  });

  test("fills schema defaults for properties that were not given", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "CSVFileScan",
      operator_id: "scan2",
      properties: { fileName: "/alice@example.org/covid/v1/other.csv" },
    });
    await harness.call("workflow_save");

    const scan2 = persistedContent().operators.find(operator => operator.operatorID === "scan2");
    expect(scan2?.operatorProperties.customDelimiter).toBe(",");
    expect(scan2?.operatorProperties.hasHeader).toBe(true);
  });

  test("generates an id when none is given", async () => {
    const result = await harness.call("workflow_add_operator", {
      operator_type: "CSVFileScan",
      properties: { fileName: "/a/b/v1/c.csv" },
    });
    expect(result).toMatch(/Added \S+ \(CSVFileScan\)/);
  });

  test("rejects a missing required property, naming it and the schema tool", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "CSVFileScan",
      operator_id: "scan9",
    });
    expect(error).toContain("Invalid properties for CSVFileScan");
    expect(error).toContain("fileName");
    expect(error).toContain("operator_get_schema");
  });

  test("rejects a property of the wrong type", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "CSVFileScan",
      operator_id: "scan9",
      properties: { fileName: 42 },
    });
    expect(error).toContain("Invalid properties");
  });

  test("suggests near matches for an unknown operator type", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "CSVScan",
      properties: {},
    });
    expect(error).toContain('No operator type "CSVScan"');
    expect(error).toContain("CSVFileScan");
  });

  test("refuses to overwrite an existing operator id", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter1",
      properties: { predicate: "x" },
    });
    expect(error).toContain("already has an operator");
    expect(error).toContain("workflow_modify_operator");
  });

  test("rejects wiring to an input port the operator does not have", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter3",
      properties: { predicate: "x" },
      inputs: { "5": ["scan1"] },
    });
    expect(error).toContain("input port(s)");
    expect(error).toContain("does not exist");
  });

  test("rejects wiring from an operator that does not exist", async () => {
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter4",
      properties: { predicate: "x" },
      inputs: { "0": ["ghost"] },
    });
    expect(error).toContain('has no operator "ghost"');
  });

  test("refuses to edit a read-only workflow", async () => {
    stored = workflowResponse({ readonly: true });
    await harness.call("workflow_open", { wid: 42 });
    const error = await harness.callExpectingError("workflow_add_operator", {
      operator_type: "Filter",
      properties: { predicate: "x" },
    });
    expect(error).toContain("read-only");
    expect(error).toContain("workflow_duplicate");
  });
});

describe("workflow_modify_operator", () => {
  beforeEach(async () => {
    await harness.call("workflow_open", { wid: 42 });
  });

  test("merges properties rather than replacing the whole object", async () => {
    await harness.call("workflow_modify_operator", {
      operator_id: "scan1",
      properties: { customDelimiter: ";" },
    });
    await harness.call("workflow_save");

    const scan1 = persistedContent().operators.find(operator => operator.operatorID === "scan1");
    expect(scan1?.operatorProperties.customDelimiter).toBe(";");
    // The property that was not mentioned survives.
    expect(scan1?.operatorProperties.fileName).toBe("/alice@example.org/covid/v1/cases.csv");
  });

  test("validates the merged result, not just the new keys", async () => {
    const error = await harness.callExpectingError("workflow_modify_operator", {
      operator_id: "scan1",
      properties: { fileName: 5 },
    });
    expect(error).toContain("Invalid properties for CSVFileScan");
  });

  test("replaces incoming links when inputs are given", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "CSVFileScan",
      operator_id: "scan2",
      properties: { fileName: "/a/b/v1/c.csv" },
    });
    const result = await harness.call("workflow_modify_operator", {
      operator_id: "filter1",
      inputs: { "0": ["scan2"] },
    });

    expect(result).toContain("removed links: scan1 -> filter1");
    expect(result).toContain("added links: scan2 -> filter1:in0");

    await harness.call("workflow_save");
    const links = persistedContent().links;
    expect(links).toHaveLength(1);
    expect(links[0].source.operatorID).toBe("scan2");
  });

  test("requires at least one thing to change", async () => {
    expect(await harness.callExpectingError("workflow_modify_operator", { operator_id: "scan1" })).toContain(
      "Nothing to change"
    );
  });

  test("names the available operators when the id is wrong", async () => {
    const error = await harness.callExpectingError("workflow_modify_operator", {
      operator_id: "nope",
      properties: {},
    });
    expect(error).toContain('has no operator "nope"');
    expect(error).toContain("scan1");
  });
});

describe("links", () => {
  beforeEach(async () => {
    await harness.call("workflow_open", { wid: 42 });
  });

  test("add and delete round-trip", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter2",
      properties: { predicate: "x" },
    });

    expect(await harness.call("workflow_add_link", { from_operator_id: "scan1", to_operator_id: "filter2" })).toContain(
      "Connected scan1:out0 -> filter2:in0"
    );
    expect(
      await harness.call("workflow_delete_link", { from_operator_id: "scan1", to_operator_id: "filter2" })
    ).toContain("Disconnected");
  });

  test("adding an existing link is a no-op rather than a duplicate", async () => {
    const result = await harness.call("workflow_add_link", {
      from_operator_id: "scan1",
      to_operator_id: "filter1",
    });
    expect(result).toContain("already connected");

    await harness.call("workflow_save");
    expect(persistedContent().links).toHaveLength(1);
  });

  test("deleting a link that does not exist says so", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter2",
      properties: { predicate: "x" },
    });
    const error = await harness.callExpectingError("workflow_delete_link", {
      from_operator_id: "scan1",
      to_operator_id: "filter2",
    });
    expect(error).toContain("No link from");
    expect(error).toContain("workflow_describe");
  });

  test("explains that a source operator has no input ports", async () => {
    const error = await harness.callExpectingError("workflow_add_link", {
      from_operator_id: "filter1",
      to_operator_id: "scan1",
    });
    expect(error).toContain("source operator");
  });

  test("addresses the second input port of a multi-input operator", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "Join",
      operator_id: "join1",
      inputs: { "0": ["scan1"], "1": ["filter1"] },
    });
    await harness.call("workflow_save");

    const links = persistedContent().links.filter(link => link.target.operatorID === "join1");
    expect(links.map(link => link.target.portID).sort()).toEqual(["input-0", "input-1"]);
  });
});

describe("workflow_delete_operator", () => {
  test("removes the operator and its links", async () => {
    await harness.call("workflow_open", { wid: 42 });
    const result = await harness.call("workflow_delete_operator", { operator_id: "filter1" });

    expect(result).toContain("Deleted filter1 and 1 attached link(s)");

    await harness.call("workflow_save");
    const content = persistedContent();
    expect(content.operators.map(operator => operator.operatorID)).toEqual(["scan1"]);
    expect(content.links).toHaveLength(0);
  });
});

describe("workflow_validate", () => {
  beforeEach(async () => {
    await harness.call("workflow_open", { wid: 42 });
  });

  test("passes a well-formed workflow and reports resolved schemas", async () => {
    const result = await harness.call("workflow_validate");
    expect(result).toContain("validates cleanly");
    expect(result).toContain("cases:integer");
  });

  test("reports an unconnected required input port", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "orphan",
      properties: { predicate: "x" },
    });
    const result = await harness.call("workflow_validate");
    expect(result).toContain("orphan");
    expect(result).toContain("no incoming link");
  });

  test("surfaces per-operator compilation errors from the deployment", async () => {
    deployment.post("/api/compile", () =>
      json({
        operatorOutputSchemas: {},
        operatorErrors: { filter1: { type: "COMPILATION_ERROR", message: "unknown attribute 'cases'" } },
      })
    );
    const result = await harness.call("workflow_validate");
    expect(result).toContain("filter1: unknown attribute 'cases'");
  });

  test("degrades gracefully when the compiling service is down", async () => {
    deployment.post("/api/compile", () => text("gateway timeout", 504));
    const result = await harness.call("workflow_validate");
    expect(result).toContain("could not be reached");
  });

  test("says an empty workflow has nothing to validate", async () => {
    stored = workflowResponse({ content: EMPTY_CONTENT });
    await harness.call("workflow_open", { wid: 42 });
    expect(await harness.call("workflow_validate")).toContain("nothing to validate");
  });
});

describe("workflow_save", () => {
  beforeEach(async () => {
    await harness.call("workflow_open", { wid: 42 });
  });

  test("persists the edited graph as a JSON content string", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter2",
      properties: { predicate: "x" },
      inputs: { "0": ["scan1"] },
    });
    const result = await harness.call("workflow_save");

    expect(result).toContain("Saved workflow 42");
    expect(result).toContain("3 operator(s)");

    const [request] = deployment.recorded("POST", "/api/workflow/persist");
    const body = JSON.parse(request.body!);
    expect(body.wid).toBe(42);
    // The backend stores content as a *string*, not a nested object.
    expect(typeof body.content).toBe("string");
    expect(JSON.parse(body.content).operators).toHaveLength(3);
  });

  test("is a no-op when nothing changed", async () => {
    expect(await harness.call("workflow_save")).toContain("no unsaved changes");
    expect(deployment.recorded("POST", "/api/workflow/persist")).toHaveLength(0);
  });

  test("clears the unsaved marker after saving", async () => {
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });
    await harness.call("workflow_save");
    expect(await harness.call("workflow_describe")).not.toContain("UNSAVED");
  });

  test("refuses to overwrite a workflow that changed on the server", async () => {
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });
    // Someone else saves in the meantime.
    stored = { ...stored, lastModifiedTime: (stored.lastModifiedTime ?? 0) + 60_000 };

    const error = await harness.callExpectingError("workflow_save");
    expect(error).toContain("modified on the server");
    expect(error).toContain("browser tab");
    expect(error).toContain("force=true");
    expect(deployment.recorded("POST", "/api/workflow/persist")).toHaveLength(0);
  });

  test("force overwrites the newer server version and says so", async () => {
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });
    stored = { ...stored, lastModifiedTime: (stored.lastModifiedTime ?? 0) + 60_000 };

    const result = await harness.call("workflow_save", { force: true });
    expect(result).toContain("Saved workflow 42");
    expect(result).toContain("overwrote a newer server-side version");
  });

  test("a second save after a first one does not falsely report drift", async () => {
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });
    await harness.call("workflow_save");

    await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "filter9",
      properties: { predicate: "y" },
      inputs: { "0": ["scan1"] },
    });
    expect(await harness.call("workflow_save")).toContain("Saved workflow 42");
  });
});

describe("workflow_discard", () => {
  test("throws away in-memory edits and reloads from the server", async () => {
    await harness.call("workflow_open", { wid: 42 });
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });

    const result = await harness.call("workflow_discard");

    expect(result).toContain("Discarded unsaved edits");
    expect(result).toContain("filter1");
    expect(deployment.recorded("POST", "/api/workflow/persist")).toHaveLength(0);
  });
});

describe("multiple open workflows", () => {
  test("edits target the most recently opened workflow, and wid overrides that", async () => {
    const other = workflowResponse({ wid: 43, name: "Other", content: twoOperatorContent() });
    deployment.get("/api/workflow/:wid", request => json(request.query.get("wid") === "43" ? other : stored));

    await harness.call("workflow_open", { wid: 42 });
    await harness.call("workflow_open", { wid: 43 });

    // No wid -> the most recent one.
    expect(await harness.call("workflow_describe")).toContain('Workflow 43 "Other"');
    // Explicit wid -> that one.
    expect(await harness.call("workflow_describe", { wid: 42 })).toContain('Workflow 42 "Covid analysis"');
  });

  test("an unopened workflow id is rejected with a pointer to workflow_open", async () => {
    await harness.call("workflow_open", { wid: 42 });
    const error = await harness.callExpectingError("workflow_describe", { wid: 99 });
    expect(error).toContain("not open");
    expect(error).toContain("workflow_open(99)");
  });
});
