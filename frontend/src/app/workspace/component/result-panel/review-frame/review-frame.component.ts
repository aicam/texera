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

import { Component, Input, OnInit } from "@angular/core";
import { DatePipe, NgIf } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzWaveDirective } from "ng-zorro-antd/core/wave";
import { NzRadioComponent, NzRadioGroupComponent } from "ng-zorro-antd/radio";
import { NzInputDirective } from "ng-zorro-antd/input";
import { NzQRCodeComponent } from "ng-zorro-antd/qr-code";
import { WorkflowActionService } from "../../../service/workflow-graph/model/workflow-action.service";
import { DashboardDataset } from "../../../../dashboard/type/dashboard-dataset.interface";
import { UserService } from "../../../../common/service/user/user.service";
import { LabelingResources, LabelingService } from "../../../service/labeling/labeling.service";
import { LabelingPageComponent } from "../../labeling-page/labeling-page.component";
import { LabelRecordsComponent } from "./label-records.component";

/**
 * The Review tab of a Review & Correct operator: label here, look back at
 * every label in Records, or generate a link that lets a clinician label on
 * the same page from any device without a Texera account.
 */
@Component({
  selector: "texera-review-frame",
  templateUrl: "./review-frame.component.html",
  styleUrls: ["./review-frame.component.scss"],
  imports: [
    NgIf,
    DatePipe,
    FormsModule,
    NzButtonComponent,
    NzWaveDirective,
    NzRadioGroupComponent,
    NzRadioComponent,
    NzInputDirective,
    NzQRCodeComponent,
    LabelingPageComponent,
    LabelRecordsComponent,
  ],
})
export class ReviewFrameComponent implements OnInit {
  @Input() operatorId!: string;

  mode: "review" | "records" = "review";
  scans?: DashboardDataset;
  labels?: DashboardDataset;
  queue?: DashboardDataset;
  /** A link for this tab's own use; Generate Link makes a separate one to hand out. */
  ownToken?: string;
  shared?: { url: string; expiresAt: number };
  copied = false;
  error = "";

  private resources?: LabelingResources;

  constructor(
    private workflowActionService: WorkflowActionService,
    private userService: UserService,
    private labeling: LabelingService
  ) {}

  get annotator(): string {
    return this.userService.getCurrentUser()?.email ?? "developer";
  }

  async ngOnInit(): Promise<void> {
    try {
      const properties = this.workflowActionService.getTexeraGraph().getOperator(this.operatorId).operatorProperties;
      this.resources = await this.labeling.resolve(properties);
      if (!this.resources) {
        this.error = "Run the workflow once so its datasets and model exist, then reopen this tab.";
        return;
      }
      ({ scans: this.scans, labels: this.labels, queue: this.queue } = this.resources);
      this.ownToken = (await this.labeling.linkFor(this.resources)).token;
    } catch (err: any) {
      this.error = err?.error?.message ?? err?.message ?? String(err);
    }
  }

  async generateLink(): Promise<void> {
    const link = await this.labeling.linkFor(this.resources!);
    this.shared = { url: this.labeling.linkUrl(link.token), expiresAt: link.expiresAt };
    this.copied = false;
  }

  async copy(): Promise<void> {
    if (!this.shared) {
      return;
    }
    try {
      await navigator.clipboard.writeText(this.shared.url);
      this.copied = true;
    } catch {
      this.copied = false;
    }
  }
}
