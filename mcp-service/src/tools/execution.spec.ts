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
import { FakeTexera, json, text } from "../testing/fake-texera";
import { computingUnitResponse, OPERATOR_METADATA, workflowResponse } from "../testing/fixtures";
import { startHarness, type Harness } from "../testing/harness";

let deployment: FakeTexera;
let harness: Harness;

const successfulRun = {
  success: true,
  state: "Completed",
  operators: {
    filter1: {
      state: "Completed",
      inputTuples: 10,
      outputTuples: 2,
      resultMode: "SET_SNAPSHOT",
      totalRowCount: 2,
      result: [
        { __row_index__: 0, region: "north", cases: 120 },
        { __row_index__: 1, region: "south", cases: 305 },
      ],
    },
  },
};

beforeEach(async () => {
  deployment = new FakeTexera();
  deployment
    .get("/api/resources/operator-metadata", () => json(OPERATOR_METADATA))
    .get("/api/workflow/:wid", () => json(workflowResponse()))
    .get("/api/computing-unit", () => json([computingUnitResponse()]))
    .get("/api/computing-unit/limits", () =>
      json({ cpuLimitOptions: ["1", "2"], memoryLimitOptions: ["2Gi", "4Gi"], gpuLimitOptions: ["0"] })
    )
    .get("/api/computing-unit/types", () => json({ typeOptions: ["kubernetes", "local"] }))
    .post("/api/computing-unit/create", () => json(computingUnitResponse({ cuid: 5, name: "new", status: "Pending" })))
    .post("/api/execution/:wid/:cuid/run", () => json(successfulRun));
  harness = await startHarness(deployment);
});

afterEach(async () => {
  await harness.close();
});

describe("computing_unit_list", () => {
  test("shows status and resource usage", async () => {
    const result = await harness.call("computing_unit_list");
    expect(result).toContain("default-unit");
    expect(result).toContain("Running");
  });

  test("points at computing_unit_create when there are none", async () => {
    deployment.get("/api/computing-unit", () => json([]));
    expect(await harness.call("computing_unit_list")).toContain("computing_unit_create");
  });
});

describe("computing_unit_create", () => {
  test("defaults resources to the deployment's first allowed values", async () => {
    const result = await harness.call("computing_unit_create", { name: "new" });
    expect(result).toContain("Started computing unit 5");

    const [request] = deployment.recorded("POST", "/api/computing-unit/create");
    const body = JSON.parse(request.body!);
    expect(body).toMatchObject({ name: "new", unitType: "kubernetes", cpuLimit: "1", memoryLimit: "2Gi" });
  });

  test("rejects a resource value the deployment does not allow, listing the options", async () => {
    const error = await harness.callExpectingError("computing_unit_create", { name: "new", cpu: "64" });
    expect(error).toContain('cpu "64" is not allowed');
    expect(error).toContain("1, 2");
    expect(deployment.recorded("POST", "/api/computing-unit/create")).toHaveLength(0);
  });

  test("rejects an unsupported unit type", async () => {
    const error = await harness.callExpectingError("computing_unit_create", { name: "new", unit_type: "docker" });
    expect(error).toContain("not supported here");
    expect(error).toContain("kubernetes, local");
  });
});

describe("computing_unit_terminate", () => {
  test("requires a matching confirmation name", async () => {
    deployment.post("/api/computing-unit/:cuid/terminate", () => text(""));

    const error = await harness.callExpectingError("computing_unit_terminate", { cuid: 1, confirm_name: "wrong" });
    expect(error).toContain("must match its name exactly");
    expect(deployment.recorded("POST", "/api/computing-unit/:cuid/terminate")).toHaveLength(0);

    expect(await harness.call("computing_unit_terminate", { cuid: 1, confirm_name: "default-unit" })).toContain(
      "Terminated computing unit 1"
    );
  });
});

describe("workflow_run", () => {
  beforeEach(async () => {
    await harness.call("workflow_open", { wid: 42 });
  });

  test("runs on an available unit and renders the result table", async () => {
    const result = await harness.call("workflow_run", { target_operator_id: "filter1" });

    expect(result).toContain("Execution succeeded");
    expect(result).toContain("region");
    expect(result).toContain("north");
    // The synthetic row index is noise for a reader and is dropped.
    expect(result).not.toContain("__row_index__");
  });

  test("sends a logical plan, not the stored workflow content", async () => {
    await harness.call("workflow_run", {});
    const [request] = deployment.recorded("POST", "/api/execution/:wid/:cuid/run");
    const body = JSON.parse(request.body!);

    expect(body.logicalPlan.operators).toHaveLength(2);
    // Logical links use port ordinals, not the "output-0" port ids of stored content.
    expect(body.logicalPlan.links[0]).toMatchObject({
      fromOpId: "scan1",
      fromPortId: { id: 0, internal: false },
      toOpId: "filter1",
      toPortId: { id: 0, internal: false },
    });
  });

  test("runs unsaved edits without requiring a save first", async () => {
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });
    const result = await harness.call("workflow_run", {});

    expect(result).toContain("including unsaved edits");
    const [request] = deployment.recorded("POST", "/api/execution/:wid/:cuid/run");
    expect(JSON.parse(request.body!).logicalPlan.operators).toHaveLength(1);
  });

  test("narrows the plan to the target operator's upstream sub-graph", async () => {
    await harness.call("workflow_add_operator", {
      operator_type: "Filter",
      operator_id: "downstream",
      properties: { predicate: "z" },
      inputs: { "0": ["filter1"] },
    });

    await harness.call("workflow_run", { target_operator_id: "scan1" });
    const request = deployment.recorded("POST", "/api/execution/:wid/:cuid/run").at(-1)!;
    const body = JSON.parse(request.body!);

    expect(body.logicalPlan.operators.map((operator: any) => operator.operatorID)).toEqual(["scan1"]);
    expect(body.targetOperatorIds).toEqual(["scan1"]);
  });

  test("reports compilation errors as a non-start, and names the cheaper check", async () => {
    deployment.post("/api/execution/:wid/:cuid/run", () =>
      json({
        success: false,
        state: "CompilationFailed",
        operators: {},
        compilationErrors: { filter1: "attribute 'cases' not found" },
      })
    );

    const result = await harness.call("workflow_run", {});
    expect(result).toContain("did not start");
    expect(result).toContain("filter1: attribute 'cases' not found");
    expect(result).toContain("workflow_validate");
  });

  test("reports a per-operator runtime error", async () => {
    deployment.post("/api/execution/:wid/:cuid/run", () =>
      json({
        success: false,
        state: "Failed",
        operators: { filter1: { state: "Failed", inputTuples: 0, outputTuples: 0, resultMode: "", error: "boom" } },
      })
    );

    const result = await harness.call("workflow_run", {});
    expect(result).toContain("ERROR: boom");
  });

  test("explains a timeout kill and what to do about it", async () => {
    deployment.post("/api/execution/:wid/:cuid/run", () =>
      json({ success: false, state: "Killed", operators: {}, errors: ["timeout"] })
    );

    const result = await harness.call("workflow_run", {});
    expect(result).toContain("exceeded the timeout");
    expect(result).toContain("timeout_seconds");
  });

  test("surfaces console output from a UDF", async () => {
    deployment.post("/api/execution/:wid/:cuid/run", () =>
      json({
        success: true,
        state: "Completed",
        operators: {
          filter1: {
            state: "Completed",
            inputTuples: 1,
            outputTuples: 1,
            resultMode: "SET_SNAPSHOT",
            consoleLogs: [{ msgType: "PRINT", message: "hello from python" }],
          },
        },
      })
    );

    expect(await harness.call("workflow_run", {})).toContain("hello from python");
  });

  test("refuses to run an empty workflow", async () => {
    await harness.call("workflow_delete_operator", { operator_id: "filter1" });
    await harness.call("workflow_delete_operator", { operator_id: "scan1" });
    expect(await harness.callExpectingError("workflow_run", {})).toContain("empty");
  });

  test("rejects a target operator that is not in the workflow, listing the real ones", async () => {
    const error = await harness.callExpectingError("workflow_run", { target_operator_id: "ghost" });
    expect(error).toContain('has no operator "ghost"');
    expect(error).toContain("scan1");
  });

  test("explains that a run needs a computing unit when there are none", async () => {
    deployment.get("/api/computing-unit", () => json([]));
    const error = await harness.callExpectingError("workflow_run", {});
    expect(error).toContain("no computing units");
    expect(error).toContain("computing_unit_create");
  });

  test("reports each unit's status when none is Running", async () => {
    deployment.get("/api/computing-unit", () => json([computingUnitResponse({ status: "Pending" })]));
    const error = await harness.callExpectingError("workflow_run", {});
    expect(error).toContain("None of your 1 computing unit(s) is Running");
    expect(error).toContain("1: Pending");
  });

  test("rejects a named unit that is not Running rather than silently using another", async () => {
    deployment.get("/api/computing-unit", () =>
      json([computingUnitResponse({ cuid: 1, status: "Pending" }), computingUnitResponse({ cuid: 2 })])
    );
    const error = await harness.callExpectingError("workflow_run", { computing_unit_id: 1 });
    expect(error).toContain('is "Pending", not Running');
  });

  test("rejects a unit id the account cannot use", async () => {
    const error = await harness.callExpectingError("workflow_run", { computing_unit_id: 99 });
    expect(error).toContain("No computing unit 99");
  });
});
