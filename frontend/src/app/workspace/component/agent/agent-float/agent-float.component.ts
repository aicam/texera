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

import { Component, OnDestroy, OnInit } from "@angular/core";
import { NgIf } from "@angular/common";
import { CdkDrag, CdkDragEnd, CdkDragHandle } from "@angular/cdk/drag-drop";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzWaveDirective } from "ng-zorro-antd/core/wave";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { GuiConfigService } from "../../../../common/service/gui-config.service";
import { AgentWorkbenchComponent } from "../agent-workbench/agent-workbench.component";

type ResizeHandle = "left" | "bottom" | "bottom-left";

/**
 * The floating agent panel for the workflow workspace. It is anchored to the
 * top-right corner, moved with cdkDrag (via the title bar), and resized on the
 * left / bottom / bottom-left edges with a plain drag splitter — so it grows down
 * and to the left into open space, keeping the top-right (and the header) fixed,
 * with no anchor compensation.
 */
@Component({
  selector: "texera-agent-float",
  templateUrl: "agent-float.component.html",
  styleUrls: ["agent-float.component.scss"],
  imports: [
    NgIf,
    CdkDrag,
    CdkDragHandle,
    NzButtonComponent,
    NzWaveDirective,
    NzTooltipDirective,
    NzIconDirective,
    AgentWorkbenchComponent,
  ],
})
export class AgentFloatComponent implements OnInit, OnDestroy {
  private static readonly WIDTH_KEY = "agent-panel-float-width";
  private static readonly HEIGHT_KEY = "agent-panel-float-height";
  // Position keys are versioned because the anchor changed from bottom-right to
  // top-right; old drag offsets would mis-place the panel.
  private static readonly DRAG_X_KEY = "agent-panel-float-pos-x";
  private static readonly DRAG_Y_KEY = "agent-panel-float-pos-y";
  private static readonly MIN_WIDTH = 320;
  private static readonly MIN_HEIGHT = 450;
  private static readonly MAX_WIDTH_RATIO = 0.9;
  private static readonly MAX_HEIGHT_RATIO = 0.85;
  private static readonly DEFAULT_WIDTH = 400;

  width = 0; // 0 means collapsed (only the floating button shows).
  height = Math.max(AgentFloatComponent.MIN_HEIGHT, Math.round(window.innerHeight * 0.7));
  dragPosition = { x: 0, y: 0 };

  private lastOpenWidth = AgentFloatComponent.DEFAULT_WIDTH;
  private lastOpenHeight = this.height;
  private removeResizeListeners?: () => void;

  constructor(private config: GuiConfigService) {}

  get copilotEnabled(): boolean {
    try {
      return this.config.env.copilotEnabled;
    } catch {
      return false;
    }
  }

  get isOpen(): boolean {
    return this.width > 0;
  }

  ngOnInit(): void {
    const savedWidth = Number(localStorage.getItem(AgentFloatComponent.WIDTH_KEY));
    if (!isNaN(savedWidth) && savedWidth > 0) {
      this.lastOpenWidth = this.clampWidth(savedWidth);
    }
    const savedHeight = Number(localStorage.getItem(AgentFloatComponent.HEIGHT_KEY));
    if (!isNaN(savedHeight) && savedHeight > 0) {
      this.lastOpenHeight = this.clampHeight(savedHeight);
      this.height = this.lastOpenHeight;
    }
    const savedX = Number(localStorage.getItem(AgentFloatComponent.DRAG_X_KEY));
    const savedY = Number(localStorage.getItem(AgentFloatComponent.DRAG_Y_KEY));
    if (!isNaN(savedX) && !isNaN(savedY)) {
      this.dragPosition = { x: savedX, y: savedY };
    }
  }

  ngOnDestroy(): void {
    this.removeResizeListeners?.();
  }

  togglePanel(): void {
    if (this.isOpen) {
      this.lastOpenWidth = this.width;
      this.lastOpenHeight = this.height;
      this.width = 0;
    } else {
      this.width = this.clampWidth(this.lastOpenWidth);
      this.height = this.clampHeight(this.lastOpenHeight);
    }
  }

  onDragEnded(event: CdkDragEnd): void {
    this.dragPosition = event.source.getFreeDragPosition();
    this.persist();
  }

  /** Begin a resize from the left / bottom / bottom-left edge. */
  startResize(event: MouseEvent, handle: ResizeHandle): void {
    event.preventDefault();
    event.stopPropagation(); // keep cdkDrag from also reacting
    const startX = event.clientX;
    const startY = event.clientY;
    const startWidth = this.width;
    const startHeight = this.height;
    const resizesWidth = handle === "left" || handle === "bottom-left";
    const resizesHeight = handle === "bottom" || handle === "bottom-left";

    const onMove = (e: MouseEvent): void => {
      // Anchored top-right: dragging left widens, dragging down heightens. The
      // top-right corner stays put, so no drag-position compensation is needed.
      if (resizesWidth) {
        this.width = this.clampWidth(startWidth + (startX - e.clientX));
      }
      if (resizesHeight) {
        this.height = this.clampHeight(startHeight + (e.clientY - startY));
      }
    };
    const onUp = (): void => {
      this.removeResizeListeners?.();
      this.lastOpenWidth = this.width;
      this.lastOpenHeight = this.height;
      this.persist();
      window.dispatchEvent(new Event("resize"));
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    document.body.classList.add("agent-resizing");
    this.removeResizeListeners = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.classList.remove("agent-resizing");
      this.removeResizeListeners = undefined;
    };
  }

  private persist(): void {
    localStorage.setItem(AgentFloatComponent.WIDTH_KEY, String(this.width));
    localStorage.setItem(AgentFloatComponent.HEIGHT_KEY, String(this.height));
    localStorage.setItem(AgentFloatComponent.DRAG_X_KEY, String(this.dragPosition.x));
    localStorage.setItem(AgentFloatComponent.DRAG_Y_KEY, String(this.dragPosition.y));
  }

  private clampWidth(width: number): number {
    const max = Math.max(AgentFloatComponent.MIN_WIDTH, Math.floor(window.innerWidth * AgentFloatComponent.MAX_WIDTH_RATIO));
    return Math.min(Math.max(Math.round(width), AgentFloatComponent.MIN_WIDTH), max);
  }

  private clampHeight(height: number): number {
    const max = Math.max(
      AgentFloatComponent.MIN_HEIGHT,
      Math.floor(window.innerHeight * AgentFloatComponent.MAX_HEIGHT_RATIO)
    );
    return Math.min(Math.max(Math.round(height), AgentFloatComponent.MIN_HEIGHT), max);
  }
}
