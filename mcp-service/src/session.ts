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

import { WorkflowState, type Workflow } from "@texera/sdk";
import { ToolError } from "./errors";

/**
 * An open workflow being edited.
 *
 * Edits accumulate in memory and are written back by `workflow_save` in one
 * `persist` call. `openedLastModifiedTime` is the optimistic-concurrency token:
 * the workspace UI edits through a Yjs document and persists from the browser,
 * so if that timestamp moved while the session was open, someone else (or the
 * user's own open tab) has written since — and a blind save would discard their
 * work.
 */
export interface EditSession {
  wid: number;
  name: string;
  description: string;
  isPublic: boolean;
  readonly: boolean;
  state: WorkflowState;
  openedLastModifiedTime?: number;
  /** True once any mutating tool has touched `state`. */
  dirty: boolean;
  openedAt: number;
}

export class EditSessionStore {
  private sessions = new Map<number, EditSession>();
  /** The workflow the edit tools act on when no `wid` is given. */
  private activeWid?: number;

  open(workflow: Workflow, readonly: boolean): EditSession {
    const state = new WorkflowState();
    state.setWorkflowContent(workflow.content);

    const session: EditSession = {
      wid: workflow.wid,
      name: workflow.name,
      description: workflow.description ?? "",
      isPublic: workflow.isPublic ?? false,
      readonly,
      state,
      openedLastModifiedTime: workflow.lastModifiedTime,
      dirty: false,
      openedAt: Date.now(),
    };

    this.sessions.get(workflow.wid)?.state.destroy();
    this.sessions.set(workflow.wid, session);
    this.activeWid = workflow.wid;
    return session;
  }

  /**
   * The session the edit tools operate on. Omitting `wid` uses the most
   * recently opened workflow, which is what a conversation implies by
   * "add a filter" right after opening one.
   */
  require(wid?: number): EditSession {
    const targetWid = wid ?? this.activeWid;
    if (targetWid === undefined) {
      throw new ToolError(
        "No workflow is open. Call workflow_open with a workflow id first (workflow_list shows the ids)."
      );
    }
    const session = this.sessions.get(targetWid);
    if (!session) {
      throw new ToolError(`Workflow ${targetWid} is not open in this session. Call workflow_open(${targetWid}) first.`);
    }
    this.activeWid = targetWid;
    return session;
  }

  /** Like {@link require}, and additionally refuses read-only workflows. */
  requireWritable(wid?: number): EditSession {
    const session = this.require(wid);
    if (session.readonly) {
      throw new ToolError(
        `You have read-only access to workflow ${session.wid} ("${session.name}"). ` +
          `Use workflow_duplicate to get your own editable copy.`
      );
    }
    return session;
  }

  get(wid: number): EditSession | undefined {
    return this.sessions.get(wid);
  }

  list(): EditSession[] {
    return [...this.sessions.values()];
  }

  close(wid: number): boolean {
    const session = this.sessions.get(wid);
    if (!session) return false;
    session.state.destroy();
    this.sessions.delete(wid);
    if (this.activeWid === wid) this.activeWid = undefined;
    return true;
  }

  markSaved(session: EditSession, lastModifiedTime: number | undefined): void {
    session.dirty = false;
    session.openedLastModifiedTime = lastModifiedTime;
  }
}
