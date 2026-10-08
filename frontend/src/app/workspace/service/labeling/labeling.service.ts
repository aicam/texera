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
import { HttpClient } from "@angular/common/http";
import { firstValueFrom } from "rxjs";
import { AppSettings } from "../../../common/app-setting";
import { GuiConfigService } from "../../../common/service/gui-config.service";
import { DatasetService } from "../../../dashboard/service/user/dataset/dataset.service";
import { ModelService } from "../../../dashboard/service/user/model/model.service";
import { DashboardDataset } from "../../../dashboard/type/dashboard-dataset.interface";

/** One suggestion waiting for a label, as file-service's LabelingLinkResource lists it. */
export interface OpenCase {
  case: string;
  round: number;
  suggested_by: string;
  suggested_by_id: number;
  uncertainty: number;
}

/** The datasets and model a Review & Correct operator labels into, once a run has created them. */
export interface LabelingResources {
  scans: DashboardDataset;
  labels: DashboardDataset;
  queue: DashboardDataset;
  modelId: number;
}

export interface QueueState {
  open: OpenCase[];
  labeled: number;
  newestModel: string;
}

/**
 * Calls the labeling-link endpoints. Except for creating a link, they are
 * authorized by the link token alone, so they go through fetch rather than
 * HttpClient: a clinician's browser may hold a stale Texera login that the
 * HTTP interceptor would otherwise attach, and file-service rejects it.
 */
@Injectable({ providedIn: "root" })
export class LabelingService {
  private readonly base = `${AppSettings.getApiEndpoint()}/labeling`;

  constructor(
    private http: HttpClient,
    private datasetService: DatasetService,
    private modelService: ModelService,
    private config: GuiConfigService
  ) {}

  /** Finds the caller's own resources named by a Review & Correct operator's properties. */
  async resolve(properties: Record<string, any>): Promise<LabelingResources | undefined> {
    const datasets = await firstValueFrom(this.datasetService.retrieveAccessibleDatasets());
    const byName = (key: string) => datasets.find(d => d.isOwner && d.dataset.name === properties[key]);
    const models = await firstValueFrom(this.modelService.retrieveAccessibleModels());
    const modelId = models.find(m => m.isOwner && m.model.name === properties["modelName"])?.model.mid;
    const [scans, labels, queue] = [byName("scansDataset"), byName("labelsDataset"), byName("queueDataset")];
    return scans && labels && queue && modelId ? { scans, labels, queue, modelId } : undefined;
  }

  linkFor(resources: LabelingResources): Promise<{ token: string; expiresAt: number }> {
    const { scans, labels, queue, modelId } = resources;
    return this.createLink(scans.dataset.did!, labels.dataset.did!, queue.dataset.did!, modelId);
  }

  /** Signed in: a link that lets anyone holding it label this run for the next 14 days. */
  createLink(
    scans: number,
    labels: number,
    queue: number,
    model: number
  ): Promise<{ token: string; expiresAt: number }> {
    return firstValueFrom(
      this.http.post<{ token: string; expiresAt: number }>(`${this.base}/link`, { scans, labels, queue, model })
    );
  }

  /** Where a link points: the configured address a phone can reach, else the one this page was opened at. */
  linkUrl(token: string): string {
    const base = this.config.env.labelingLinkBaseUrl?.replace(/\/+$/, "") || window.location.origin;
    return `${base}/label/${token}`;
  }

  imageUrl(token: string, kind: "scan" | "suggestion", caseName: string): string {
    return `${this.endpoint(token)}/image/${kind}/${encodeURIComponent(caseName)}`;
  }

  async queue(token: string): Promise<QueueState> {
    return this.json(await fetch(`${this.endpoint(token)}/queue`));
  }

  async submit(token: string, caseName: string, maskPng: Blob, annotator: string, seconds: number): Promise<void> {
    const mask = await new Promise<string>(resolve => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(",")[1]);
      reader.readAsDataURL(maskPng);
    });
    await this.json(
      await fetch(`${this.endpoint(token)}/label`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case: caseName, mask, annotator, seconds }),
      })
    );
  }

  private endpoint(token: string): string {
    return `/${this.base}/${encodeURIComponent(token)}`;
  }

  private async json<T>(response: Response): Promise<T> {
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.message ?? `Request failed (${response.status})`);
    }
    return response.json();
  }
}
