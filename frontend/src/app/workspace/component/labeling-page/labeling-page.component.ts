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

import { Component, ElementRef, Input, OnDestroy, OnInit, ViewChild } from "@angular/core";
import { NgIf } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { ActivatedRoute } from "@angular/router";
import { LabelingService, OpenCase } from "../../service/labeling/labeling.service";
import { COLORS, decodePng, SIZE, toMask, windowed } from "../result-panel/review-frame/review-images";

const NAME_KEY = "labeling-annotator-name";
const BRUSHES = { small: 2, medium: 4, large: 7 } as const;

/**
 * The page a clinician labels on: one scan at a time, the AI's outline drawn
 * over it, a finger or mouse to paint or erase, and Save & next. It is also
 * embedded in the Review tab, so developers and clinicians use the same page.
 */
@Component({
  selector: "texera-labeling-page",
  templateUrl: "./labeling-page.component.html",
  styleUrls: ["./labeling-page.component.scss"],
  imports: [NgIf, FormsModule],
})
export class LabelingPageComponent implements OnInit, OnDestroy {
  /** Set when embedded; on the standalone page it comes from the URL. */
  @Input() token?: string;
  /** Set when embedded, so a signed-in developer is never asked for a name. */
  @Input() annotator?: string;
  @Input() embedded = false;
  @ViewChild("canvas") canvasRef?: ElementRef<HTMLCanvasElement>;

  readonly brushes = BRUSHES;
  name = "";
  nameDraft = "";
  current?: OpenCase;
  remaining = 0;
  labeled = 0;
  tool: "paint" | "erase" = "paint";
  brush: keyof typeof BRUSHES = "medium";
  showAi = true;
  loading = true;
  saving = false;
  message = "";
  error = "";

  private scan?: ImageData;
  private suggestion: Uint8Array = new Uint8Array(SIZE * SIZE);
  private mask: Uint8Array = new Uint8Array(SIZE * SIZE);
  private history: Uint8Array[] = [];
  private skipped = new Set<string>();
  private openedAt = 0;
  private drawing = false;
  private poll?: ReturnType<typeof setInterval>;

  constructor(
    private route: ActivatedRoute,
    private labeling: LabelingService
  ) {}

  ngOnInit(): void {
    this.token ??= this.route.snapshot.paramMap.get("token") ?? undefined;
    this.name = this.annotator ?? this.readName();
    this.poll = setInterval(() => {
      if (!this.current && this.name) {
        this.next();
      }
    }, 4000);
    if (this.name) {
      this.next();
    } else {
      this.loading = false;
    }
  }

  ngOnDestroy(): void {
    clearInterval(this.poll);
  }

  get canUndo(): boolean {
    return this.history.length > 0;
  }

  start(): void {
    const name = this.nameDraft.trim();
    if (!name) {
      return;
    }
    this.name = name;
    try {
      localStorage.setItem(NAME_KEY, name);
    } catch {
      // Private browsing: the name just isn't remembered next time.
    }
    this.next();
  }

  /** Loads the most uncertain open case this reviewer has not skipped. */
  async next(): Promise<void> {
    if (!this.token) {
      this.error = "This link is incomplete. Ask for a new one.";
      return;
    }
    try {
      const state = await this.labeling.queue(this.token);
      this.labeled = state.labeled;
      const open = state.open.filter(c => !this.skipped.has(c.case));
      this.remaining = open.length;
      this.error = "";
      if (!open.length) {
        this.current = undefined;
        this.loading = false;
        this.draw();
        return;
      }
      const target = open[0];
      if (target.case === this.current?.case) {
        return;
      }
      const [scan, suggestion] = await Promise.all([
        this.image("scan", target.case),
        this.image("suggestion", target.case),
      ]);
      this.current = target;
      this.scan = windowed(scan);
      this.suggestion = toMask(suggestion);
      this.mask = this.suggestion.slice();
      this.history = [];
      this.openedAt = performance.now();
      this.loading = false;
      this.draw();
    } catch (err: any) {
      this.loading = false;
      this.error = err?.message ?? "Something went wrong. Check your connection and try again.";
    }
  }

  async save(): Promise<void> {
    if (!this.current || !this.token || this.saving) {
      return;
    }
    this.saving = true;
    try {
      const seconds = (performance.now() - this.openedAt) / 1000;
      await this.labeling.submit(this.token, this.current.case, await this.maskPng(), this.name, seconds);
      this.message = "Saved";
      setTimeout(() => (this.message = ""), 1500);
      this.current = undefined;
      await this.next();
    } catch (err: any) {
      this.error = err?.message ?? "Could not save. Try again.";
    } finally {
      this.saving = false;
    }
  }

  skip(): void {
    if (this.current) {
      this.skipped.add(this.current.case);
      this.current = undefined;
      this.next();
    }
  }

  undo(): void {
    const previous = this.history.pop();
    if (previous) {
      this.mask = previous;
      this.draw();
    }
  }

  resetToAi(): void {
    this.remember();
    this.mask = this.suggestion.slice();
    this.draw();
  }

  clear(): void {
    this.remember();
    this.mask.fill(0);
    this.draw();
  }

  toggleAi(): void {
    this.showAi = !this.showAi;
    this.draw();
  }

  onPointerDown(event: PointerEvent): void {
    if (!this.current) {
      return;
    }
    (event.target as HTMLElement).setPointerCapture(event.pointerId);
    this.remember();
    this.drawing = true;
    this.paint(event);
  }

  onPointerMove(event: PointerEvent): void {
    if (this.drawing) {
      this.paint(event);
    }
  }

  onPointerUp(): void {
    this.drawing = false;
  }

  private remember(): void {
    this.history.push(this.mask.slice());
    if (this.history.length > 30) {
      this.history.shift();
    }
  }

  private paint(event: PointerEvent): void {
    const rect = (event.target as HTMLCanvasElement).getBoundingClientRect();
    const cx = ((event.clientX - rect.left) / rect.width) * SIZE;
    const cy = ((event.clientY - rect.top) / rect.height) * SIZE;
    const radius = BRUSHES[this.brush];
    const value = this.tool === "paint" ? 1 : 0;
    for (let y = Math.floor(cy - radius); y <= cy + radius; y++) {
      for (let x = Math.floor(cx - radius); x <= cx + radius; x++) {
        if (x >= 0 && y >= 0 && x < SIZE && y < SIZE && (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2) {
          this.mask[y * SIZE + x] = value;
        }
      }
    }
    this.draw();
  }

  /**
   * The scan with the reviewer's edits against the AI's guess: what they kept in
   * orange, what they added in green, what they removed in red, and the AI's
   * outline in cyan, so every change is visible however large the guess is.
   */
  private draw(): void {
    const canvas = this.canvasRef?.nativeElement;
    if (!canvas) {
      setTimeout(() => this.canvasRef && this.draw());
      return;
    }
    const frame = new ImageData(SIZE, SIZE);
    for (let i = 0; i < SIZE * SIZE; i++) {
      const gray = this.scan && this.current ? this.scan.data[i * 4] : 24;
      let [r, g, b] = [gray, gray, gray];
      const color = this.current ? this.pixelColor(i) : undefined;
      if (color) {
        [r, g, b] = [0.45 * r + 0.55 * color[0], 0.45 * g + 0.55 * color[1], 0.45 * b + 0.55 * color[2]];
      }
      if (this.current && this.showAi && this.isEdge(this.suggestion, i)) {
        [r, g, b] = [...COLORS.suggestion];
      }
      frame.data.set([r, g, b, 255], i * 4);
    }
    const small = new OffscreenCanvas(SIZE, SIZE);
    small.getContext("2d")!.putImageData(frame, 0, 0);
    const context = canvas.getContext("2d")!;
    context.imageSmoothingEnabled = false;
    context.drawImage(small, 0, 0, canvas.width, canvas.height);
  }

  /** With the AI's guess hidden, only the reviewer's own outline is shown. */
  private pixelColor(i: number): readonly number[] | undefined {
    const [mine, ai] = [this.mask[i], this.showAi && this.suggestion[i]];
    return mine && ai
      ? COLORS.label
      : mine
        ? this.showAi
          ? COLORS.added
          : COLORS.label
        : ai
          ? COLORS.removed
          : undefined;
  }

  private isEdge(mask: Uint8Array, i: number): boolean {
    if (!mask[i]) {
      return false;
    }
    const x = i % SIZE;
    const y = Math.floor(i / SIZE);
    return (
      x === 0 ||
      y === 0 ||
      x === SIZE - 1 ||
      y === SIZE - 1 ||
      !mask[i - 1] ||
      !mask[i + 1] ||
      !mask[i - SIZE] ||
      !mask[i + SIZE]
    );
  }

  private async image(kind: "scan" | "suggestion", caseName: string): Promise<ImageData> {
    const response = await fetch(this.labeling.imageUrl(this.token!, kind, caseName));
    if (!response.ok) {
      throw new Error(
        response.status === 401 ? "This link has expired. Ask for a new one." : "Could not load the image."
      );
    }
    return decodePng(await response.blob());
  }

  private maskPng(): Promise<Blob> {
    const canvas = new OffscreenCanvas(SIZE, SIZE);
    const context = canvas.getContext("2d")!;
    const image = context.createImageData(SIZE, SIZE);
    for (let i = 0; i < SIZE * SIZE; i++) {
      const v = this.mask[i] ? 255 : 0;
      image.data.set([v, v, v, 255], i * 4);
    }
    context.putImageData(image, 0, 0);
    return canvas.convertToBlob({ type: "image/png" });
  }

  private readName(): string {
    try {
      return localStorage.getItem(NAME_KEY) ?? "";
    } catch {
      return "";
    }
  }
}
