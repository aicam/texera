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

import { Component, HostBinding, OnDestroy, OnInit } from "@angular/core";
import { NgIf } from "@angular/common";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzWaveDirective } from "ng-zorro-antd/core/wave";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { AgentWorkbenchComponent } from "../agent-workbench/agent-workbench.component";

/**
 * The docked agent panel for the dashboard. It renders as a real flex item beside the
 * dashboard content, so the content shrinks to make room for it (no overlay, no
 * reserved-margin hacks). Resizing is a plain drag splitter on its left edge, which
 * works regardless of zone / pointer-events subtleties.
 */
@Component({
  selector: "texera-agent-dock",
  templateUrl: "agent-dock.component.html",
  styleUrls: ["agent-dock.component.scss"],
  imports: [NgIf, NzButtonComponent, NzWaveDirective, NzTooltipDirective, NzIconDirective, AgentWorkbenchComponent],
})
export class AgentDockComponent implements OnInit, OnDestroy {
  private static readonly STORAGE_KEY = "agent-panel-dock-width";
  private static readonly MIN_WIDTH = 320;
  private static readonly MAX_WIDTH_RATIO = 0.6;
  private static readonly DEFAULT_WIDTH_RATIO = 0.25;

  protected readonly minWidth = AgentDockComponent.MIN_WIDTH;

  // 0 means collapsed (only the floating button shows).
  width = 0;
  private lastOpenWidth = AgentDockComponent.defaultWidth();
  private removeResizeListeners?: () => void;

  @HostBinding("style.width.px") get hostWidthPx(): number {
    return this.width;
  }

  @HostBinding("class.is-open") get open(): boolean {
    return this.isOpen;
  }

  get isOpen(): boolean {
    return this.width > 0;
  }

  ngOnInit(): void {
    const saved = Number(localStorage.getItem(AgentDockComponent.STORAGE_KEY));
    if (!isNaN(saved) && saved > 0) {
      this.lastOpenWidth = this.clampWidth(saved);
    }
  }

  ngOnDestroy(): void {
    this.removeResizeListeners?.();
  }

  togglePanel(): void {
    if (this.isOpen) {
      this.lastOpenWidth = this.width;
      this.width = 0;
    } else {
      this.width = this.clampWidth(this.lastOpenWidth);
    }
    window.dispatchEvent(new Event("resize"));
  }

  /** Begin a horizontal resize from the panel's left edge. */
  startResize(event: MouseEvent): void {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = this.width;

    const onMove = (e: MouseEvent): void => {
      // Panel is anchored on the right, so dragging left widens it.
      this.width = this.clampWidth(startWidth + (startX - e.clientX));
    };
    const onUp = (): void => {
      this.removeResizeListeners?.();
      this.lastOpenWidth = this.width;
      this.persist();
      window.dispatchEvent(new Event("resize"));
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
    document.body.classList.add("agent-resizing-ew");
    this.removeResizeListeners = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.classList.remove("agent-resizing-ew");
      this.removeResizeListeners = undefined;
    };
  }

  private persist(): void {
    localStorage.setItem(AgentDockComponent.STORAGE_KEY, String(this.width));
  }

  private clampWidth(width: number): number {
    return Math.min(Math.max(Math.round(width), AgentDockComponent.MIN_WIDTH), AgentDockComponent.maxWidth());
  }

  private static maxWidth(): number {
    return Math.max(AgentDockComponent.MIN_WIDTH, Math.floor(window.innerWidth * AgentDockComponent.MAX_WIDTH_RATIO));
  }

  private static defaultWidth(): number {
    const target = Math.round(window.innerWidth * AgentDockComponent.DEFAULT_WIDTH_RATIO);
    return Math.min(Math.max(target, AgentDockComponent.MIN_WIDTH), AgentDockComponent.maxWidth());
  }
}
