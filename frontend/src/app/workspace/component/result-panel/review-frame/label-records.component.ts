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

import { Component, ElementRef, Input, OnInit, QueryList, ViewChildren } from "@angular/core";
import { DatePipe, DecimalPipe, NgFor, NgIf } from "@angular/common";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { firstValueFrom, interval, startWith } from "rxjs";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzWaveDirective } from "ng-zorro-antd/core/wave";
import { NzTagComponent } from "ng-zorro-antd/tag";
import { DatasetService } from "../../../../dashboard/service/user/dataset/dataset.service";
import { DashboardDataset } from "../../../../dashboard/type/dashboard-dataset.interface";
import { DatasetVersion } from "../../../../common/type/dataset";
import { COLORS, datasetFilePath, decodePng, drawLayers, filePaths, SIZE, toMask, windowed } from "./review-images";

/** One label's provenance file, as Review & Correct writes it. Seed labels carry only case and annotator. */
interface LabelRecord {
  case: string;
  annotator: string;
  round?: number;
  suggested_by?: string;
  newest_model_at_submit?: string;
  versions_behind?: number;
  uncertainty?: number;
  dice_suggested_vs_final?: number;
  pixels_changed?: number;
  seconds?: number;
  submitted_at?: string;
}

type View = "scan" | "suggestion" | "label" | "changes";

/**
 * Every label of an active-labeling run as a table of its provenance, with a
 * viewer that puts the scan, the model's suggestion, the final label and the
 * person's changes side by side.
 */
@UntilDestroy()
@Component({
  selector: "texera-label-records",
  templateUrl: "./label-records.component.html",
  styleUrls: ["./label-records.component.scss"],
  imports: [NgIf, NgFor, DecimalPipe, DatePipe, NzButtonComponent, NzWaveDirective, NzTagComponent],
})
export class LabelRecordsComponent implements OnInit {
  @Input() scans!: DashboardDataset;
  @Input() labels!: DashboardDataset;
  @Input() queue!: DashboardDataset;
  @ViewChildren("view") canvases?: QueryList<ElementRef<HTMLCanvasElement>>;

  readonly views: { key: View; title: string }[] = [
    { key: "scan", title: "Scan" },
    { key: "suggestion", title: "AI suggestion" },
    { key: "label", title: "Final label" },
    { key: "changes", title: "Person's changes" },
  ];
  records: LabelRecord[] = [];
  selected?: LabelRecord;
  hasSuggestion = false;
  added = 0;
  removed = 0;
  error = "";

  private labelsVersion?: DatasetVersion;
  private loaded = new Map<string, LabelRecord>();

  constructor(private datasetService: DatasetService) {}

  ngOnInit(): void {
    interval(8000)
      .pipe(startWith(0), untilDestroyed(this))
      .subscribe(() => this.refresh().catch(err => (this.error = String(err?.message ?? err))));
  }

  private async refresh(): Promise<void> {
    const version = await firstValueFrom(this.datasetService.retrieveDatasetLatestVersion(this.labels.dataset.did!));
    if (version.dvid === this.labelsVersion?.dvid) {
      return;
    }
    this.labelsVersion = version;
    const cases = filePaths(version.fileNodes)
      .filter(p => p.startsWith("provenance/"))
      .map(p => p.slice("provenance/".length, -".json".length))
      .filter(c => !this.loaded.has(c));
    await Promise.all(
      cases.map(async c => {
        const blob = await firstValueFrom(this.read(this.labels, version, `provenance/${c}.json`));
        this.loaded.set(c, JSON.parse(await blob.text()));
      })
    );
    this.records = [...this.loaded.values()].sort((a, b) => (b.submitted_at ?? "").localeCompare(a.submitted_at ?? ""));
  }

  async open(record: LabelRecord): Promise<void> {
    this.selected = record;
    this.error = "";
    try {
      const labelsVersion = this.labelsVersion!;
      const [scansVersion, queueVersion] = await Promise.all([
        firstValueFrom(this.datasetService.retrieveDatasetLatestVersion(this.scans.dataset.did!)),
        firstValueFrom(this.datasetService.retrieveDatasetLatestVersion(this.queue.dataset.did!)).catch(
          () => undefined
        ),
      ]);
      const inLabels = filePaths(labelsVersion.fileNodes).includes(`suggestions/${record.case}.png`);
      const inQueue = queueVersion && filePaths(queueVersion.fileNodes).includes(`items/${record.case}.png`);
      const [scan, label, suggestion] = await Promise.all([
        this.image(this.scans, scansVersion, `scans/${record.case}.png`),
        this.image(this.labels, labelsVersion, `masks/${record.case}.png`),
        inLabels
          ? this.image(this.labels, labelsVersion, `suggestions/${record.case}.png`)
          : inQueue
            ? this.image(this.queue, queueVersion!, `items/${record.case}.png`)
            : Promise.resolve(undefined),
      ]);
      const labelMask = toMask(label);
      const suggestionMask = suggestion ? toMask(suggestion) : new Uint8Array(SIZE * SIZE);
      this.hasSuggestion = !!suggestion;
      const addedMask = labelMask.map((v, i) => (v && !suggestionMask[i] ? 1 : 0));
      const removedMask = suggestionMask.map((v, i) => (v && !labelMask[i] ? 1 : 0));
      this.added = addedMask.reduce((a, b) => a + b, 0);
      this.removed = removedMask.reduce((a, b) => a + b, 0);

      // The canvases render after `selected` is set; wait one tick for them.
      await new Promise(resolve => setTimeout(resolve));
      const layers: Record<View, { mask: Uint8Array; color: readonly number[]; alpha: number }[]> = {
        scan: [],
        suggestion: [{ mask: suggestionMask, color: COLORS.suggestion, alpha: 0.5 }],
        label: [{ mask: labelMask, color: COLORS.label, alpha: 0.5 }],
        changes: [
          { mask: addedMask, color: COLORS.added, alpha: 0.75 },
          { mask: removedMask, color: COLORS.removed, alpha: 0.75 },
        ],
      };
      const shown = windowed(scan);
      this.canvases?.forEach((ref, index) => drawLayers(ref.nativeElement, shown, layers[this.views[index].key]));
    } catch (err: any) {
      this.error = `Could not open ${record.case}: ${err?.message ?? err}`;
    }
  }

  private read(dataset: DashboardDataset, version: DatasetVersion, path: string) {
    return this.datasetService.retrieveDatasetVersionSingleFile(datasetFilePath(dataset, version, path));
  }

  private async image(dataset: DashboardDataset, version: DatasetVersion, path: string): Promise<ImageData> {
    return decodePng(await firstValueFrom(this.read(dataset, version, path)));
  }
}
