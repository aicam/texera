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

import { DashboardDataset } from "../../../../dashboard/type/dashboard-dataset.interface";
import { DatasetVersion } from "../../../../common/type/dataset";
import { DatasetFileNode } from "../../../../common/type/datasetVersionFileTree";

/** Scans and masks in an active-labeling run are SIZE x SIZE single-channel PNGs. */
export const SIZE = 128;

export const COLORS = {
  suggestion: [34, 195, 214],
  label: [255, 159, 28],
  added: [82, 196, 26],
  removed: [245, 34, 45],
} as const;

/** The logical path file-service presigns for one file of a dataset version. */
export function datasetFilePath(dataset: DashboardDataset, version: DatasetVersion, path: string): string {
  return `/dataset/${dataset.ownerEmail}/${dataset.dataset.name}/${version.name}/${path}`;
}

export function filePaths(nodes: DatasetFileNode[] | undefined, prefix = ""): string[] {
  return (nodes ?? []).flatMap(node =>
    node.type === "directory" ? filePaths(node.children, `${prefix}${node.name}/`) : [`${prefix}${node.name}`]
  );
}

export async function decodePng(blob: Blob): Promise<ImageData> {
  const bitmap = await createImageBitmap(blob);
  const canvas = new OffscreenCanvas(SIZE, SIZE);
  const context = canvas.getContext("2d")!;
  context.drawImage(bitmap, 0, 0, SIZE, SIZE);
  return context.getImageData(0, 0, SIZE, SIZE);
}

/**
 * A scan with its contrast stretched for people to read: the darkest pixel to
 * black and the 99th-percentile pixel to white, as a radiology viewer windows
 * an image. Slices at the edge of the brain carry little signal and would
 * otherwise look black. Only the display changes; the model sees raw pixels.
 */
export function windowed(scan: ImageData): ImageData {
  const values = new Uint8Array(SIZE * SIZE);
  for (let i = 0; i < values.length; i++) {
    values[i] = scan.data[i * 4];
  }
  const sorted = values.slice().sort();
  const low = sorted[0];
  const high = Math.max(sorted[Math.floor(sorted.length * 0.99)], low + 1);
  const out = new ImageData(SIZE, SIZE);
  for (let i = 0; i < values.length; i++) {
    const v = Math.min(255, Math.round(((values[i] - low) * 255) / (high - low)));
    out.data.set([v, v, v, 255], i * 4);
  }
  return out;
}

/** A mask PNG as one 0/1 value per pixel. */
export function toMask(image: ImageData): Uint8Array {
  const mask = new Uint8Array(SIZE * SIZE);
  for (let i = 0; i < mask.length; i++) {
    mask[i] = image.data[i * 4] > 127 ? 1 : 0;
  }
  return mask;
}

/**
 * Draws the scan and, over it, each layer's pixels in its color, scaled up
 * without smoothing so pixel edits stay visible.
 */
export function drawLayers(
  canvas: HTMLCanvasElement,
  scan: ImageData | undefined,
  layers: { mask: Uint8Array; color: readonly number[]; alpha: number }[]
): void {
  const frame = new ImageData(SIZE, SIZE);
  for (let i = 0; i < SIZE * SIZE; i++) {
    let [r, g, b] = scan ? [scan.data[i * 4], scan.data[i * 4], scan.data[i * 4]] : [20, 20, 20];
    for (const layer of layers) {
      if (layer.mask[i]) {
        r = (1 - layer.alpha) * r + layer.alpha * layer.color[0];
        g = (1 - layer.alpha) * g + layer.alpha * layer.color[1];
        b = (1 - layer.alpha) * b + layer.alpha * layer.color[2];
      }
    }
    frame.data.set([r, g, b, 255], i * 4);
  }
  const small = new OffscreenCanvas(SIZE, SIZE);
  small.getContext("2d")!.putImageData(frame, 0, 0);
  const context = canvas.getContext("2d")!;
  context.imageSmoothingEnabled = false;
  context.drawImage(small, 0, 0, canvas.width, canvas.height);
}
