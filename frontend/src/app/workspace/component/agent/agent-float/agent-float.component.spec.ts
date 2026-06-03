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

import { AgentFloatComponent } from "./agent-float.component";
import { GuiConfigService } from "../../../../common/service/gui-config.service";

// jsdom viewport is 1024x768. Float defaults: width 400, height max(450, round(768*0.7))=538.
const DEFAULT_WIDTH = 400;
const DEFAULT_HEIGHT = Math.max(450, Math.round(768 * 0.7));

function mousedown(clientX: number, clientY: number): MouseEvent {
  return { clientX, clientY, preventDefault: () => {}, stopPropagation: () => {} } as unknown as MouseEvent;
}

function makeComponent(copilotEnabled = true): AgentFloatComponent {
  const config = { env: { copilotEnabled } } as unknown as GuiConfigService;
  const component = new AgentFloatComponent(config);
  component.ngOnInit();
  return component;
}

describe("AgentFloatComponent", () => {
  let component: AgentFloatComponent;

  beforeEach(() => {
    localStorage.clear();
    component = makeComponent();
  });

  afterEach(() => {
    component.ngOnDestroy();
  });

  it("is gated on the copilot config flag", () => {
    expect(component.copilotEnabled).toBe(true);
    expect(makeComponent(false).copilotEnabled).toBe(false);
  });

  it("opens to the default size and collapses back to zero width", () => {
    expect(component.isOpen).toBe(false);

    component.togglePanel();
    expect(component.isOpen).toBe(true);
    expect(component.width).toBe(DEFAULT_WIDTH);
    expect(component.height).toBe(DEFAULT_HEIGHT);

    component.togglePanel();
    expect(component.width).toBe(0);
  });

  it("widens when dragging the left edge, without moving the panel", () => {
    component.togglePanel();
    component.startResize(mousedown(1000, 500), "left");
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 900, clientY: 500 })); // drag left 100px
    expect(component.width).toBe(DEFAULT_WIDTH + 100);
    expect(component.height).toBe(DEFAULT_HEIGHT);
    expect(component.dragPosition).toEqual({ x: 0, y: 0 });
    document.dispatchEvent(new MouseEvent("mouseup"));
  });

  it("heightens when dragging the bottom edge down", () => {
    component.togglePanel();
    component.startResize(mousedown(500, 500), "bottom");
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 500, clientY: 600 })); // drag down 100px
    expect(component.height).toBe(DEFAULT_HEIGHT + 100);
    expect(component.width).toBe(DEFAULT_WIDTH);
    document.dispatchEvent(new MouseEvent("mouseup"));
  });

  it("resizes both axes from the bottom-left corner and stops after mouseup", () => {
    component.togglePanel();
    component.startResize(mousedown(1000, 500), "bottom-left");
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 950, clientY: 560 })); // left 50, down 60
    expect(component.width).toBe(DEFAULT_WIDTH + 50);
    expect(component.height).toBe(DEFAULT_HEIGHT + 60);

    document.dispatchEvent(new MouseEvent("mouseup"));
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 100, clientY: 700 }));
    expect(component.width).toBe(DEFAULT_WIDTH + 50);
    expect(component.height).toBe(DEFAULT_HEIGHT + 60);
  });
});
