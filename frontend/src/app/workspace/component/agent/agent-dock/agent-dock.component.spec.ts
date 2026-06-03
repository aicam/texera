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

import { AgentDockComponent } from "./agent-dock.component";

// jsdom's default viewport is 1024px wide: 1/4 = 256 clamps up to the 320 min; the
// max is floor(1024 * 0.6) = 614.
const DEFAULT_WIDTH = 320;
const MAX_WIDTH = 614;

function mousedown(clientX: number): MouseEvent {
  return { clientX, preventDefault: () => {} } as unknown as MouseEvent;
}

describe("AgentDockComponent", () => {
  let component: AgentDockComponent;

  beforeEach(() => {
    localStorage.clear();
    component = new AgentDockComponent();
    component.ngOnInit();
  });

  afterEach(() => {
    component.ngOnDestroy();
  });

  it("starts collapsed and opens to a quarter of the viewport", () => {
    expect(component.isOpen).toBe(false);
    expect(component.width).toBe(0);

    component.togglePanel();

    expect(component.isOpen).toBe(true);
    expect(component.width).toBe(DEFAULT_WIDTH);
  });

  it("collapses back to zero width and remembers the last open width", () => {
    component.togglePanel(); // open -> 320
    component.togglePanel(); // collapse -> 0
    expect(component.width).toBe(0);

    component.togglePanel(); // reopen -> 320
    expect(component.width).toBe(DEFAULT_WIDTH);
  });

  it("widens as the splitter is dragged left and clamps to the max width", () => {
    component.togglePanel(); // open -> 320

    component.startResize(mousedown(1000));
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 900 })); // drag left 100px
    expect(component.width).toBe(DEFAULT_WIDTH + 100);

    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 0 })); // drag far left
    expect(component.width).toBe(MAX_WIDTH);

    document.dispatchEvent(new MouseEvent("mouseup"));
    // After the gesture ends, further moves do nothing.
    document.dispatchEvent(new MouseEvent("mousemove", { clientX: 1000 }));
    expect(component.width).toBe(MAX_WIDTH);
  });

  it("restores a persisted width on init", () => {
    localStorage.setItem("agent-panel-dock-width", "480");
    const restored = new AgentDockComponent();
    restored.ngOnInit();
    restored.togglePanel();
    expect(restored.width).toBe(480);
    restored.ngOnDestroy();
  });
});
