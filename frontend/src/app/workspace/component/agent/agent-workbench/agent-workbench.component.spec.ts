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

import { Subject, of } from "rxjs";

import { AgentWorkbenchComponent } from "./agent-workbench.component";
import { AgentService, AgentInfo } from "../../../service/agent/agent.service";
import { UserService } from "../../../../common/service/user/user.service";

function agent(id: string, name: string): AgentInfo {
  return { id, name, modelType: "gpt", isBaselineMode: false, createdAt: new Date(0) };
}

describe("AgentWorkbenchComponent", () => {
  let component: AgentWorkbenchComponent;
  let agentService: Partial<AgentService>;
  let userService: Partial<UserService>;
  const agents = [agent("a1", "Agent One"), agent("a2", "Agent Two")];

  function build(agentIdToActivate?: string): void {
    agentService = {
      agentChange$: new Subject<void>(),
      getAgent: vi.fn((id: string) => of(agents.find(a => a.id === id)!)),
      getAllAgents: vi.fn(() => of([])),
      activateAgent: vi.fn(),
      deactivateAgent: vi.fn(),
      updateAgent: vi.fn((id: string, updates: Partial<Pick<AgentInfo, "name" | "modelType">>) =>
        of({ ...agents.find(a => a.id === id)!, ...updates })
      ),
      deleteAgent: vi.fn().mockReturnValue(of(true)),
    } as Partial<AgentService>;
    userService = {
      userChanged: vi.fn(() => of({ uid: 1 } as any)),
    } as Partial<UserService>;
    component = new AgentWorkbenchComponent(agentService as AgentService, userService as UserService);
    component.agentIdToActivate = agentIdToActivate;
    component.ngOnInit();
  }

  beforeEach(() => {
    build();
  });

  afterEach(() => {
    component.ngOnDestroy();
  });

  it("starts with a pending chat instead of fetching the agent list", () => {
    expect(component.currentAgent).toBeNull();
    expect(component.activeAgentId).toBeNull();
    expect(component.tabs).toEqual([{ localId: "pending-1", agentInfo: null }]);
    expect(component.activeTabId).toBe("pending-1");
    expect(agentService.getAllAgents).toHaveBeenCalled();
  });

  it("loads persisted agents into tabs on startup", () => {
    component.ngOnDestroy();
    agentService = {
      agentChange$: new Subject<void>(),
      getAgent: vi.fn((id: string) => of(agents.find(a => a.id === id)!)),
      getAllAgents: vi.fn(() => of(agents)),
      activateAgent: vi.fn(),
      deactivateAgent: vi.fn(),
      updateAgent: vi.fn((id: string, updates: Partial<Pick<AgentInfo, "name" | "modelType">>) =>
        of({ ...agents.find(a => a.id === id)!, ...updates })
      ),
      deleteAgent: vi.fn().mockReturnValue(of(true)),
    } as Partial<AgentService>;
    userService = {
      userChanged: vi.fn(() => of({ uid: 1 } as any)),
    } as Partial<UserService>;
    component = new AgentWorkbenchComponent(agentService as AgentService, userService as UserService);

    component.ngOnInit();

    expect(component.tabs.map(tab => tab.agentInfo?.id)).toEqual(["a1", "a2"]);
    expect(component.activeTabId).toBe("agent-a1");
    expect(component.currentAgent).toEqual(agents[0]);
    expect(agentService.activateAgent).toHaveBeenCalledWith("a1");
  });

  it("reloads persisted tabs after a user logs back in", () => {
    component.ngOnDestroy();
    const userSubject = new Subject<any>();
    agentService = {
      agentChange$: new Subject<void>(),
      getAgent: vi.fn((id: string) => of(agents.find(a => a.id === id)!)),
      getAllAgents: vi.fn(() => of(agents)),
      activateAgent: vi.fn(),
      deactivateAgent: vi.fn(),
      updateAgent: vi.fn((id: string, updates: Partial<Pick<AgentInfo, "name" | "modelType">>) =>
        of({ ...agents.find(a => a.id === id)!, ...updates })
      ),
      deleteAgent: vi.fn().mockReturnValue(of(true)),
    } as Partial<AgentService>;
    userService = {
      userChanged: vi.fn(() => userSubject.asObservable()),
    } as Partial<UserService>;
    component = new AgentWorkbenchComponent(agentService as AgentService, userService as UserService);
    component.ngOnInit();

    userSubject.next(undefined);
    expect(component.tabs).toEqual([{ localId: "pending-1", agentInfo: null }]);

    userSubject.next({ uid: 1 });
    expect(component.tabs.map(tab => tab.agentInfo?.id)).toEqual(["a1", "a2"]);
    expect(component.activeTabId).toBe("agent-a1");
  });

  it("opens a new pending tab from the plus action", () => {
    component.addPendingTab();

    expect(component.tabs).toEqual([
      { localId: "pending-1", agentInfo: null },
      { localId: "pending-2", agentInfo: null },
    ]);
    expect(component.activeTabId).toBe("pending-2");
    expect(component.currentAgent).toBeNull();
  });

  it("loads and activates a requested existing agent", () => {
    component.ngOnDestroy();
    build("a1");

    expect(agentService.getAgent).toHaveBeenCalledWith("a1");
    expect(agentService.activateAgent).toHaveBeenCalledWith("a1");
    expect(component.currentAgent).toEqual(agents[0]);
    expect(component.activeAgentId).toBe("a1");
    expect(component.tabs).toEqual([{ localId: "pending-1", agentInfo: agents[0] }]);
  });

  it("turns the active pending tab into an agent when lazy creation completes", () => {
    component.onAgentReady(agents[0], "pending-1");

    expect(component.tabs[0].agentInfo).toEqual(agents[0]);
    expect(agentService.activateAgent).toHaveBeenCalledWith("a1");
    expect(component.currentAgent).toEqual(agents[0]);
    expect(component.activeAgentId).toBe("a1");
  });

  it("updates the active tab when the chat reports updated agent metadata", () => {
    component.onAgentReady(agents[0], "pending-1");

    component.onAgentUpdated({ ...agents[0], modelType: "gpt-4o" }, "pending-1");

    expect(component.tabs[0].agentInfo?.modelType).toBe("gpt-4o");
    expect(component.currentAgent?.modelType).toBe("gpt-4o");
  });

  it("renames an agent tab through the update API", () => {
    component.onAgentReady(agents[0], "pending-1");

    component.startTabNameEdit(component.tabs[0], new MouseEvent("click"));
    component.editingName = "Renamed";
    component.saveTabName(component.tabs[0]);

    expect(agentService.updateAgent).toHaveBeenCalledWith("a1", { name: "Renamed" });
    expect(component.tabs[0].agentInfo?.name).toBe("Renamed");
    expect(component.currentAgent?.name).toBe("Renamed");
  });

  it("deactivates the previous agent when switching to a new pending tab", () => {
    component.onAgentReady(agents[0], "pending-1");

    component.addPendingTab();

    expect(agentService.deactivateAgent).toHaveBeenCalledWith("a1");
    expect(component.currentAgent).toBeNull();
    expect(component.activeAgentId).toBeNull();
  });

  it("deletes an agent after confirmation", () => {
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    const event = { stopPropagation: vi.fn() } as unknown as Event;
    component.onAgentReady(agents[0]);

    component.deleteTabAgent(component.tabs[0], event);

    expect(event.stopPropagation).toHaveBeenCalled();
    expect(agentService.deleteAgent).toHaveBeenCalledWith("a1");
    expect(component.currentAgent).toBeNull();
    confirmSpy.mockRestore();
  });
});
