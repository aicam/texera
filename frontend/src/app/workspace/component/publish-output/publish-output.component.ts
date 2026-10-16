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

import { Component, inject, OnInit } from "@angular/core";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { NgFor, NgIf } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { NZ_MODAL_DATA } from "ng-zorro-antd/modal";
import { NzInputDirective } from "ng-zorro-antd/input";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzAlertComponent } from "ng-zorro-antd/alert";
import { NzTagComponent } from "ng-zorro-antd/tag";
import { NzTypographyComponent } from "ng-zorro-antd/typography";
import {
  SharedOutputAccess,
  SharedOutputEntry,
  SharedOutputService,
} from "../../../common/service/shared-output/shared-output.service";
import { NotificationService } from "../../../common/service/notification/notification.service";

export interface PublishOutputData {
  wid: number;
  operatorId: string;
  operatorName: string;
}

/**
 * Publishes an operator's output under a name, so other workflows, including other people's,
 * read it in place with a Shared Output source, and manages who may read it.
 */
@UntilDestroy()
@Component({
  selector: "texera-publish-output",
  templateUrl: "./publish-output.component.html",
  styleUrls: ["./publish-output.component.scss"],
  imports: [
    NgIf,
    NgFor,
    FormsModule,
    NzInputDirective,
    NzButtonComponent,
    NzAlertComponent,
    NzTagComponent,
    NzTypographyComponent,
  ],
})
export class PublishOutputComponent implements OnInit {
  readonly data: PublishOutputData = inject(NZ_MODAL_DATA);
  published?: SharedOutputEntry;
  access: SharedOutputAccess[] = [];
  name = "";
  description = "";
  readerEmail = "";
  loading = true;

  constructor(
    private sharedOutputService: SharedOutputService,
    private notificationService: NotificationService
  ) {}

  ngOnInit(): void {
    this.name = this.data.operatorName
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "-")
      .replace(/^-+|-+$/g, "");
    this.sharedOutputService
      .ofWorkflow(this.data.wid)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: entries => {
          this.published = entries.find(entry => entry.operatorId === this.data.operatorId);
          this.loading = false;
          this.loadAccess();
        },
        error: () => (this.loading = false),
      });
  }

  publish(): void {
    this.sharedOutputService
      .publish(this.data.wid, this.data.operatorId, this.name.trim(), this.description.trim())
      .pipe(untilDestroyed(this))
      .subscribe({
        next: entry => {
          this.published = entry;
          this.notificationService.success(`Published as ${entry.reference}`);
        },
        error: (e: unknown) => this.notificationService.error(this.messageOf(e)),
      });
  }

  unpublish(): void {
    if (!this.published) return;
    this.sharedOutputService
      .unpublish(this.published.soid)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: () => {
          this.published = undefined;
          this.access = [];
        },
        error: (e: unknown) => this.notificationService.error(this.messageOf(e)),
      });
  }

  share(): void {
    if (!this.published || !this.readerEmail.trim()) return;
    this.sharedOutputService
      .share(this.published.soid, this.readerEmail.trim())
      .pipe(untilDestroyed(this))
      .subscribe({
        next: () => {
          this.readerEmail = "";
          this.loadAccess();
        },
        error: (e: unknown) => this.notificationService.error(this.messageOf(e)),
      });
  }

  revoke(email: string): void {
    if (!this.published) return;
    this.sharedOutputService
      .revoke(this.published.soid, email)
      .pipe(untilDestroyed(this))
      .subscribe(() => this.loadAccess());
  }

  private loadAccess(): void {
    if (!this.published?.isOwner) return;
    this.sharedOutputService
      .access(this.published.soid)
      .pipe(untilDestroyed(this))
      .subscribe(access => (this.access = access));
  }

  private messageOf(e: unknown): string {
    const error = e as { error?: { message?: string }; message?: string };
    return error.error?.message ?? error.message ?? "Request failed";
  }
}
