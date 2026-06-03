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

import { ExecutionMode, type WorkflowContent } from "../../../common/type/workflow";
import type { OperatorLink, OperatorPredicate, Point } from "../../types/workflow-common.interface";
import type { WorkflowActionService } from "../workflow-graph/model/workflow-action.service";
import { applyWorkflowContentDelta, computeOperatorDelta } from "./workflow-delta";

function op(id: string, overrides: Partial<OperatorPredicate> = {}): OperatorPredicate {
  return {
    operatorID: id,
    operatorType: "Filter",
    operatorVersion: "1.0",
    operatorProperties: {},
    inputPorts: [{ portID: "input-0" }],
    outputPorts: [{ portID: "output-0" }],
    showAdvanced: false,
    ...overrides,
  } as OperatorPredicate;
}

function link(id: string, from: string, to: string): OperatorLink {
  return { linkID: id, source: { operatorID: from, portID: "output-0" }, target: { operatorID: to, portID: "input-0" } };
}

function content(operators: OperatorPredicate[], links: OperatorLink[] = []): WorkflowContent {
  const operatorPositions: { [key: string]: Point } = {};
  operators.forEach((o, i) => (operatorPositions[o.operatorID] = { x: i * 100, y: 0 }));
  return {
    operators,
    operatorPositions,
    links,
    commentBoxes: [],
    settings: { dataTransferBatchSize: 400, executionMode: ExecutionMode.PIPELINED },
  };
}

/** Minimal in-memory stand-in for WorkflowActionService that records the granular calls made. */
function mockService(initial: WorkflowContent) {
  const operators = new Map(initial.operators.map(o => [o.operatorID, o]));
  const positions = new Map<string, Point>(Object.entries(initial.operatorPositions ?? {}));
  const links = new Map(initial.links.map(l => [l.linkID, l]));
  const calls: string[] = [];

  const removeLinksFor = (operatorID: string) => {
    for (const [lid, l] of links) {
      if (l.source.operatorID === operatorID || l.target.operatorID === operatorID) links.delete(lid);
    }
  };

  const graph = {
    hasOperator: (id: string) => operators.has(id),
    hasLinkWithID: (id: string) => links.has(id),
    getAllLinks: () => Array.from(links.values()),
  };

  const service = {
    getTexeraGraph: () => graph,
    getWorkflowContent: (): WorkflowContent => ({
      operators: Array.from(operators.values()),
      operatorPositions: Object.fromEntries(positions),
      links: Array.from(links.values()),
      commentBoxes: [],
      settings: { dataTransferBatchSize: 400, executionMode: ExecutionMode.PIPELINED },
    }),
    addOperator: (operator: OperatorPredicate, pos: Point) => {
      calls.push(`add:${operator.operatorID}`);
      operators.set(operator.operatorID, operator);
      positions.set(operator.operatorID, pos);
    },
    deleteOperator: (id: string) => {
      calls.push(`delete:${id}`);
      operators.delete(id);
      positions.delete(id);
      removeLinksFor(id);
    },
    setOperatorProperty: (id: string, props: object) => {
      calls.push(`setProp:${id}`);
      const existing = operators.get(id);
      if (existing) operators.set(id, { ...existing, operatorProperties: props } as OperatorPredicate);
    },
    addLink: (l: OperatorLink) => {
      calls.push(`addLink:${l.linkID}`);
      links.set(l.linkID, l);
    },
    deleteLinkWithID: (id: string) => {
      calls.push(`delLink:${id}`);
      links.delete(id);
    },
  };

  return { service: service as unknown as WorkflowActionService, calls, operators, links };
}

/** Assert the live mock state now equals the target content (operators + links). */
function expectMatches(state: ReturnType<typeof mockService>, target: WorkflowContent) {
  expect([...state.operators.keys()].sort()).toEqual(target.operators.map(o => o.operatorID).sort());
  expect([...state.links.keys()].sort()).toEqual(target.links.map(l => l.linkID).sort());
  for (const o of target.operators) {
    expect(state.operators.get(o.operatorID)!.operatorProperties).toEqual(o.operatorProperties);
  }
}

describe("computeOperatorDelta", () => {
  it("detects additions and removals", () => {
    const delta = computeOperatorDelta(content([op("a")]), content([op("b")]));
    expect(delta.toAdd.map(x => x.op.operatorID)).toEqual(["b"]);
    expect(delta.toRemove).toEqual(["a"]);
    expect(delta.toUpdate).toEqual([]);
    expect(delta.toReplace).toEqual([]);
  });

  it("treats a properties-only change as an in-place update", () => {
    const before = content([op("a", { operatorProperties: { k: 1 } })]);
    const after = content([op("a", { operatorProperties: { k: 2 } })]);
    const delta = computeOperatorDelta(before, after);
    expect(delta.toUpdate).toEqual([{ operatorID: "a", properties: { k: 2 } }]);
    expect(delta.toReplace).toEqual([]);
  });

  it("ignores key order when comparing properties (no spurious update)", () => {
    const before = content([op("a", { operatorProperties: { x: 1, y: 2 } })]);
    const after = content([op("a", { operatorProperties: { y: 2, x: 1 } })]);
    expect(computeOperatorDelta(before, after).toUpdate).toEqual([]);
  });

  it("treats a display-name change as a replace (no granular setter exists)", () => {
    const before = content([op("a", { customDisplayName: "Old" })]);
    const after = content([op("a", { customDisplayName: "New" })]);
    const delta = computeOperatorDelta(before, after);
    expect(delta.toReplace.map(x => x.op.operatorID)).toEqual(["a"]);
    expect(delta.toUpdate).toEqual([]);
  });

  it("treats a structural change (ports) as a replace", () => {
    const before = content([op("a", { inputPorts: [{ portID: "input-0" }] })]);
    const after = content([op("a", { inputPorts: [{ portID: "input-0" }, { portID: "input-1" }] })]);
    expect(computeOperatorDelta(before, after).toReplace.map(x => x.op.operatorID)).toEqual(["a"]);
  });

  it("produces no work when content is identical", () => {
    const same = content([op("a", { operatorProperties: { k: 1 } })], []);
    const delta = computeOperatorDelta(same, content([op("a", { operatorProperties: { k: 1 } })]));
    expect(delta).toEqual({ toAdd: [], toReplace: [], toUpdate: [], toRemove: [] });
  });
});

describe("applyWorkflowContentDelta", () => {
  it("adds new operators and links, reaching the target", () => {
    const state = mockService(content([op("a")]));
    const target = content([op("a"), op("b")], [link("l1", "a", "b")]);
    expect(applyWorkflowContentDelta(state.service, target)).toBe(true);
    expectMatches(state, target);
    expect(state.calls).toContain("add:b");
    expect(state.calls).toContain("addLink:l1");
  });

  it("updates a changed property in place (no delete/add)", () => {
    const state = mockService(content([op("a", { operatorProperties: { code: "x" } })]));
    const target = content([op("a", { operatorProperties: { code: "y" } })]);
    applyWorkflowContentDelta(state.service, target);
    expect(state.calls).toEqual(["setProp:a"]);
    expect(state.operators.get("a")!.operatorProperties).toEqual({ code: "y" });
  });

  it("removes operators that disappear, along with their links", () => {
    const state = mockService(content([op("a"), op("b")], [link("l1", "a", "b")]));
    const target = content([op("a")]);
    applyWorkflowContentDelta(state.service, target);
    expectMatches(state, target);
    expect(state.links.size).toBe(0);
  });

  it("replaces a structurally-changed operator and restores its links", () => {
    const state = mockService(content([op("a"), op("b")], [link("l1", "a", "b")]));
    // b gains a second input port (structural) -> replace; link l1 must survive.
    const target = content(
      [op("a"), op("b", { inputPorts: [{ portID: "input-0" }, { portID: "input-1" }] })],
      [link("l1", "a", "b")]
    );
    applyWorkflowContentDelta(state.service, target);
    expectMatches(state, target);
    expect(state.calls).toContain("delete:b");
    expect(state.calls).toContain("add:b");
    expect(state.calls).toContain("addLink:l1"); // dropped by the replace, then restored
    expect(state.operators.get("b")!.inputPorts.length).toBe(2);
  });

  it("removes stale links when an edge is dropped", () => {
    const state = mockService(content([op("a"), op("b")], [link("l1", "a", "b")]));
    const target = content([op("a"), op("b")], []);
    applyWorkflowContentDelta(state.service, target);
    expect(state.links.size).toBe(0);
    expect(state.calls).toContain("delLink:l1");
  });

  it("skips a blank snapshot so a transient empty payload can't wipe the canvas", () => {
    const state = mockService(content([op("a"), op("b")], [link("l1", "a", "b")]));
    const result = applyWorkflowContentDelta(state.service, content([]));
    expect(result).toBe(false);
    expect(state.operators.size).toBe(2); // untouched
    expect(state.calls).toEqual([]);
  });

  it("is idempotent: re-applying the same target is a no-op", () => {
    const target = content([op("a", { operatorProperties: { k: 1 } }), op("b")], [link("l1", "a", "b")]);
    const state = mockService(target);
    expect(applyWorkflowContentDelta(state.service, target)).toBe(true);
    expect(state.calls).toEqual([]);
  });
});
