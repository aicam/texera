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

import { Injectable } from "@angular/core";
import { Observable, exhaustMap, from, timer } from "rxjs";
import { WorkflowActionService } from "../workflow-graph/model/workflow-action.service";
import { LabelingService } from "./labeling.service";

export const REVIEW_OPERATOR_TYPE = "ReviewAndCorrect";
export const TRAIN_OPERATOR_TYPE = "TrainSegmenter";

/** What a Review & Correct operator's labeling session holds right now. */
export interface LabelingSession {
  open: number;
  labeled: number;
}

const POLL_MS = 5000;
const RESOLVE_RETRY_MS = 15000;

/**
 * Follows the labeling session behind every Review & Correct operator on the
 * canvas. A session lives in its datasets, not in an execution: people keep
 * labeling through its link while the workflow is stopped, edited, or broken,
 * so the canvas asks the session itself rather than the engine.
 */
@Injectable({ providedIn: "root" })
export class LabelingSessionService {
  private links = new Map<string, { token?: string; triedAt: number }>();

  constructor(
    private workflowActionService: WorkflowActionService,
    private labeling: LabelingService
  ) {}

  /** Each Review & Correct operator's session, keyed by operator ID, refreshed every few seconds. */
  sessions(): Observable<Map<string, LabelingSession>> {
    return timer(0, POLL_MS).pipe(exhaustMap(() => from(this.poll())));
  }

  private async poll(): Promise<Map<string, LabelingSession>> {
    const sessions = new Map<string, LabelingSession>();
    const operators = this.workflowActionService
      .getTexeraGraph()
      .getAllOperators()
      .filter(op => op.operatorType === REVIEW_OPERATOR_TYPE);
    for (const op of operators) {
      try {
        const token = await this.token(op.operatorProperties);
        if (token) {
          const queue = await this.labeling.queue(token);
          sessions.set(op.operatorID, { open: queue.open.length, labeled: queue.labeled });
        }
      } catch {
        // A session that cannot be read right now simply shows nothing until the next poll.
      }
    }
    return sessions;
  }

  private async token(properties: Record<string, any>): Promise<string | undefined> {
    const key = ["scansDataset", "labelsDataset", "queueDataset", "modelName"].map(k => properties[k]).join("\u0000");
    const link = this.links.get(key);
    if (link?.token || (link && Date.now() - link.triedAt < RESOLVE_RETRY_MS)) {
      return link.token;
    }
    const entry: { token?: string; triedAt: number } = { triedAt: Date.now() };
    this.links.set(key, entry);
    const resources = await this.labeling.resolve(properties);
    entry.token = resources && (await this.labeling.linkFor(resources)).token;
    return entry.token;
  }
}
