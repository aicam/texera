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

import { describe, expect, test } from "bun:test";
import { WorkflowState } from "./workflow-state";
import type { OperatorPredicate, OperatorLink } from "../types/workflow";

function makeOperator(id: string, overrides: Partial<OperatorPredicate> = {}): OperatorPredicate {
  return {
    operatorID: id,
    operatorType: "TestOp",
    operatorVersion: "1.0",
    operatorProperties: {},
    inputPorts: [{ portID: "input-0", displayName: "Input 0" }],
    outputPorts: [{ portID: "output-0", displayName: "Output 0" }],
    showAdvanced: false,
    ...overrides,
  };
}

function makeLink(linkId: string, sourceId: string, targetId: string): OperatorLink {
  return {
    linkID: linkId,
    source: { operatorID: sourceId, portID: "output-0" },
    target: { operatorID: targetId, portID: "input-0" },
  };
}

describe("WorkflowState - operators", () => {
  test("add and get operator round-trips", () => {
    const state = new WorkflowState();
    const op = makeOperator("op1");
    state.addOperator(op);
    expect(state.getOperator("op1")).toEqual(op);
    expect(state.getAllOperators()).toHaveLength(1);
  });

  test("delete operator removes connected links", () => {
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1"));
    state.addOperator(makeOperator("op2"));
    state.addLink(makeLink("l1", "op1", "op2"));

    expect(state.deleteOperator("op1")).toBe(true);
    expect(state.getOperator("op1")).toBeUndefined();
    expect(state.getAllLinks()).toHaveLength(0);
  });

  test("delete on missing operator returns false", () => {
    const state = new WorkflowState();
    expect(state.deleteOperator("missing")).toBe(false);
  });

  test("updateOperatorProperties merges, does not replace", () => {
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1", { operatorProperties: { a: 1, b: 2 } }));
    state.updateOperatorProperties("op1", { b: 99, c: 3 });

    expect(state.getOperator("op1")?.operatorProperties).toEqual({ a: 1, b: 99, c: 3 });
  });

  test("updateOperatorDisplayName sets customDisplayName", () => {
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1"));
    expect(state.updateOperatorDisplayName("op1", "Filter rows")).toBe(true);
    expect(state.getOperator("op1")?.customDisplayName).toBe("Filter rows");
  });

  test("update on missing operator returns false", () => {
    const state = new WorkflowState();
    expect(state.updateOperatorProperties("missing", { a: 1 })).toBe(false);
    expect(state.updateOperatorDisplayName("missing", "x")).toBe(false);
  });
});

describe("WorkflowState - links", () => {
  test("add, get, and delete link", () => {
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1"));
    state.addOperator(makeOperator("op2"));
    const link = makeLink("l1", "op1", "op2");
    state.addLink(link);

    expect(state.getLink("l1")).toEqual(link);
    expect(state.deleteLink("l1")).toBe(true);
    expect(state.getLink("l1")).toBeUndefined();
  });

  test("getLinksConnectedToOperator returns both inbound and outbound", () => {
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1"));
    state.addOperator(makeOperator("op2"));
    state.addOperator(makeOperator("op3"));
    state.addLink(makeLink("l1", "op1", "op2"));
    state.addLink(makeLink("l2", "op2", "op3"));

    const connected = state.getLinksConnectedToOperator("op2");
    expect(connected.map(l => l.linkID).sort()).toEqual(["l1", "l2"]);
  });
});

describe("WorkflowState - generated ids", () => {
  test("generateLinkId is monotonically increasing", () => {
    const state = new WorkflowState();
    expect(state.generateLinkId()).toBe("link-1");
    expect(state.generateLinkId()).toBe("link-2");
    expect(state.generateLinkId()).toBe("link-3");
  });

  test("generateOperatorId is namespaced by type", () => {
    const state = new WorkflowState();
    expect(state.generateOperatorId("Filter")).toBe("Filter-operator-1");
    expect(state.generateOperatorId("Filter")).toBe("Filter-operator-2");
    expect(state.generateOperatorId("Sort")).toBe("Sort-operator-3");
  });
});

describe("WorkflowState - getSubDAG", () => {
  test("walks ancestors of the target operator", () => {
    // op1 -> op2 -> op4
    //        op3 -> op4
    // sub-DAG of op4 should include all four.
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1"));
    state.addOperator(makeOperator("op2"));
    state.addOperator(makeOperator("op3"));
    state.addOperator(makeOperator("op4"));
    state.addLink(makeLink("l1", "op1", "op2"));
    state.addLink(makeLink("l2", "op2", "op4"));
    state.addLink(makeLink("l3", "op3", "op4"));

    const subDag = state.getSubDAG("op4");
    expect(subDag.operators.map(o => o.operatorID).sort()).toEqual(["op1", "op2", "op3", "op4"]);
    expect(subDag.links.map(l => l.linkID).sort()).toEqual(["l1", "l2", "l3"]);
  });

  test("excludes downstream operators", () => {
    // op1 -> op2 -> op3
    // sub-DAG of op2 should include op1 and op2 but not op3.
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1"));
    state.addOperator(makeOperator("op2"));
    state.addOperator(makeOperator("op3"));
    state.addLink(makeLink("l1", "op1", "op2"));
    state.addLink(makeLink("l2", "op2", "op3"));

    const subDag = state.getSubDAG("op2");
    expect(subDag.operators.map(o => o.operatorID).sort()).toEqual(["op1", "op2"]);
  });

  test("disabled upstream operators are skipped", () => {
    const state = new WorkflowState();
    state.addOperator(makeOperator("op1", { isDisabled: true }));
    state.addOperator(makeOperator("op2"));
    state.addLink(makeLink("l1", "op1", "op2"));

    const subDag = state.getSubDAG("op2");
    expect(subDag.operators.map(o => o.operatorID)).toEqual(["op2"]);
  });
});

describe("toLogicalPlan", () => {
  // A -> B -> C, plus an unrelated D.
  function chain(): WorkflowState {
    const state = new WorkflowState();
    const make = (id: string, inputs: number, outputs: number): OperatorPredicate => ({
      operatorID: id,
      operatorType: "Op",
      operatorVersion: "1.0",
      operatorProperties: { label: id },
      inputPorts: Array.from({ length: inputs }, (_, index) => ({ portID: `input-${index}` })),
      outputPorts: Array.from({ length: outputs }, (_, index) => ({ portID: `output-${index}` })),
      showAdvanced: false,
    });
    state.addOperator(make("a", 0, 1));
    state.addOperator(make("b", 1, 1));
    state.addOperator(make("c", 1, 1));
    state.addOperator(make("d", 0, 1));
    state.addLink({
      linkID: "l1",
      source: { operatorID: "a", portID: "output-0" },
      target: { operatorID: "b", portID: "input-0" },
    });
    state.addLink({
      linkID: "l2",
      source: { operatorID: "b", portID: "output-0" },
      target: { operatorID: "c", portID: "input-0" },
    });
    return state;
  }

  test("includes every enabled operator when no target is given", () => {
    const plan = chain().toLogicalPlan();
    expect(plan.operators.map(op => op.operatorID).sort()).toEqual(["a", "b", "c", "d"]);
    expect(plan.links).toHaveLength(2);
  });

  test("narrows to the target and its upstream when a target is given", () => {
    const plan = chain().toLogicalPlan("b");
    expect(plan.operators.map(op => op.operatorID).sort()).toEqual(["a", "b"]);
    // The b -> c link is dropped along with c.
    expect(plan.links).toHaveLength(1);
    expect(plan.links[0]).toMatchObject({ fromOpId: "a", toOpId: "b" });
  });

  test("a source operator as target yields just itself", () => {
    const plan = chain().toLogicalPlan("a");
    expect(plan.operators.map(op => op.operatorID)).toEqual(["a"]);
    expect(plan.links).toHaveLength(0);
  });

  test("an unknown target yields an empty plan rather than the whole graph", () => {
    const plan = chain().toLogicalPlan("missing");
    expect(plan.operators).toHaveLength(0);
  });

  test("flattens properties and converts links to port ordinals", () => {
    const plan = chain().toLogicalPlan();
    expect(plan.operators.find(op => op.operatorID === "a")).toMatchObject({ operatorType: "Op", label: "a" });
    expect(plan.links[0].fromPortId).toEqual({ id: 0, internal: false });
  });
});
