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

import type { WorkflowContent } from "../../../common/type/workflow";
import type { OperatorPredicate, Point } from "../../types/workflow-common.interface";
import type { WorkflowActionService } from "../workflow-graph/model/workflow-action.service";

/**
 * Granular reconciliation of an agent-produced workflow snapshot onto the live canvas.
 *
 * The agent edits its own in-memory copy of the workflow and streams back the full
 * post-edit content per step. Applying that by tearing the canvas down and rebuilding it
 * (`reloadWorkflow`) flickers, loses viewport/selection, and clobbers anything the agent
 * did not touch. Instead we diff the snapshot against the current canvas and apply only
 * the changed operators/links through the normal `WorkflowActionService` edit methods, so
 * the edits flow into the shared model, render live, and auto-persist exactly like a human
 * edit.
 */

/** An operator to add (or re-add) at a position. */
export interface OperatorAddition {
  op: OperatorPredicate;
  pos: Point;
}

/** A granular, in-place property update for an operator that is otherwise unchanged. */
export interface OperatorPropertyUpdate {
  operatorID: string;
  properties: Readonly<{ [key: string]: any }>;
}

/** The operator-level diff between the current canvas and a target snapshot. */
export interface WorkflowOperatorDelta {
  /** Operators present in target but not on the canvas. */
  toAdd: OperatorAddition[];
  /**
   * Operators present in both whose structure or display name changed. There is no clean
   * granular setter for those fields, so they are replaced (delete + re-add) — the new
   * predicate carries the updated structure/name.
   */
  toReplace: OperatorAddition[];
  /** Operators present in both that differ only in `operatorProperties` — updated in place. */
  toUpdate: OperatorPropertyUpdate[];
  /** Operator IDs present on the canvas but not in target. */
  toRemove: string[];
}

const DEFAULT_POSITION: Point = { x: 100, y: 100 };

/**
 * Deterministic stringify with recursively sorted object keys, so two operators that carry
 * the same properties in a different key order compare equal.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const keys = Object.keys(value as Record<string, unknown>).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify((value as Record<string, unknown>)[k])}`).join(",")}}`;
}

/**
 * Everything about an operator except its properties. If any of these differ the operator
 * cannot be updated in place (there is no granular setter for ports, version, type, name,
 * or flags), so it is replaced.
 */
function operatorShape(op: OperatorPredicate): unknown {
  return {
    operatorType: op.operatorType,
    operatorVersion: op.operatorVersion,
    inputPorts: op.inputPorts,
    outputPorts: op.outputPorts,
    dynamicInputPorts: op.dynamicInputPorts ?? false,
    dynamicOutputPorts: op.dynamicOutputPorts ?? false,
    showAdvanced: op.showAdvanced,
    isDisabled: op.isDisabled ?? false,
    viewResult: op.viewResult ?? false,
    markedForReuse: op.markedForReuse ?? false,
    customDisplayName: op.customDisplayName ?? null,
  };
}

function positionOf(content: WorkflowContent, operatorID: string): Point {
  return content.operatorPositions?.[operatorID] ?? DEFAULT_POSITION;
}

/**
 * Compute the operator-level diff between the current canvas content and a target snapshot.
 * Pure and side-effect free so it can be unit tested without Angular.
 */
export function computeOperatorDelta(current: WorkflowContent, target: WorkflowContent): WorkflowOperatorDelta {
  const currentById = new Map(current.operators.map(op => [op.operatorID, op]));
  const targetById = new Map(target.operators.map(op => [op.operatorID, op]));

  const delta: WorkflowOperatorDelta = { toAdd: [], toReplace: [], toUpdate: [], toRemove: [] };

  for (const [id, targetOp] of targetById) {
    const currentOp = currentById.get(id);
    if (!currentOp) {
      delta.toAdd.push({ op: targetOp, pos: positionOf(target, id) });
      continue;
    }
    if (stableStringify(operatorShape(currentOp)) !== stableStringify(operatorShape(targetOp))) {
      delta.toReplace.push({ op: targetOp, pos: positionOf(target, id) });
    } else if (stableStringify(currentOp.operatorProperties) !== stableStringify(targetOp.operatorProperties)) {
      delta.toUpdate.push({ operatorID: id, properties: targetOp.operatorProperties });
    }
  }

  for (const id of currentById.keys()) {
    if (!targetById.has(id)) {
      delta.toRemove.push(id);
    }
  }

  return delta;
}

/**
 * Reconcile the live canvas to match `target`, applying only the differences through the
 * normal edit API. Returns true if the reconcile ran, false if it was skipped by the
 * safety guard.
 *
 * Guard: a target with zero operators while the canvas is non-empty is treated as a
 * spurious/blank snapshot and ignored, so a transient empty payload can never wipe the
 * user's workflow. An agent that genuinely empties a workflow is not a supported flow.
 */
export function applyWorkflowContentDelta(
  workflowActionService: WorkflowActionService,
  target: WorkflowContent
): boolean {
  const current = workflowActionService.getWorkflowContent();
  if ((target.operators?.length ?? 0) === 0 && current.operators.length > 0) {
    return false;
  }

  const delta = computeOperatorDelta(current, target);
  const graph = workflowActionService.getTexeraGraph();

  const run = (label: string, action: () => void) => {
    try {
      action();
    } catch (error) {
      console.warn(`agent workflow replay: failed to ${label}`, error);
    }
  };

  // 1. Remove operators that disappeared (also removes their connected links).
  for (const id of delta.toRemove) {
    if (graph.hasOperator(id)) {
      run(`delete operator ${id}`, () => workflowActionService.deleteOperator(id));
    }
  }

  // 2. Tear down operators that changed structurally so they can be re-added below.
  for (const { op } of delta.toReplace) {
    if (graph.hasOperator(op.operatorID)) {
      run(`replace-delete operator ${op.operatorID}`, () => workflowActionService.deleteOperator(op.operatorID));
    }
  }

  // 3. Add new and replaced operators (with positions). Operators must exist before links.
  for (const { op, pos } of [...delta.toAdd, ...delta.toReplace]) {
    if (!graph.hasOperator(op.operatorID)) {
      run(`add operator ${op.operatorID}`, () => workflowActionService.addOperator(op, pos));
    }
  }

  // 4. In-place property updates for operators whose structure is unchanged.
  for (const { operatorID, properties } of delta.toUpdate) {
    if (graph.hasOperator(operatorID)) {
      run(`update operator ${operatorID}`, () => workflowActionService.setOperatorProperty(operatorID, { ...properties }));
    }
  }

  // 5. Reconcile links against the live graph (covers links dropped by a replace in step 2).
  const targetLinkIds = new Set(target.links.map(link => link.linkID));
  for (const link of [...graph.getAllLinks()]) {
    if (!targetLinkIds.has(link.linkID)) {
      run(`delete link ${link.linkID}`, () => workflowActionService.deleteLinkWithID(link.linkID));
    }
  }
  for (const link of target.links) {
    const endpointsExist = graph.hasOperator(link.source.operatorID) && graph.hasOperator(link.target.operatorID);
    if (endpointsExist && !graph.hasLinkWithID(link.linkID)) {
      run(`add link ${link.linkID}`, () => workflowActionService.addLink(link));
    }
  }

  return true;
}
