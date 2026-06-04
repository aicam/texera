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

import { Component, HostListener, Input, OnChanges, OnDestroy, OnInit, SimpleChanges } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { NgFor, NgIf } from "@angular/common";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { NzInputDirective } from "ng-zorro-antd/input";
import { NzSpinComponent } from "ng-zorro-antd/spin";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { distinctUntilChanged } from "rxjs/operators";
import { UserService } from "../../../../common/service/user/user.service";
import { AgentService, AgentInfo } from "../../../service/agent/agent.service";
import { AgentChatComponent } from "../agent-panel/agent-chat/agent-chat.component";

interface AgentWorkbenchTab {
  localId: string;
  agentInfo: AgentInfo | null;
}

/**
 * The shared "inside" of every agent panel. It hosts one chat surface that starts
 * in a pending state, or loads a requested existing agent by ID.
 *
 * Both {@link AgentDockComponent} (dashboard) and {@link AgentFloatComponent}
 * (workspace) embed this component, so the chat UI is reused in both places.
 */
@UntilDestroy()
@Component({
  selector: "texera-agent-workbench",
  templateUrl: "agent-workbench.component.html",
  styleUrls: ["agent-workbench.component.scss"],
  imports: [
    NgFor,
    NgIf,
    FormsModule,
    NzButtonComponent,
    NzIconDirective,
    NzInputDirective,
    NzSpinComponent,
    NzTooltipDirective,
    AgentChatComponent,
  ],
})
export class AgentWorkbenchComponent implements OnInit, OnDestroy, OnChanges {
  /**
   * Optional agent ID to activate when the workbench loads. When provided (e.g. from
   * an agent dashboard deep link) the matching agent's tab is selected and activated.
   */
  @Input() agentIdToActivate?: string;

  // Only one agent can be connected at a time.
  activeAgentId: string | null = null;
  currentAgent: AgentInfo | null = null;
  tabs: AgentWorkbenchTab[] = [];
  activeTabId: string | null = null;
  isLoadingAgent = false;
  editingTabId: string | null = null;
  editingName = "";
  private loadingAgentId: string | null = null;
  private nextPendingIndex = 1;

  constructor(
    private agentService: AgentService,
    private userService: UserService
  ) {}

  ngOnInit(): void {
    this.userService
      .userChanged()
      .pipe(
        distinctUntilChanged((previous, current) => previous?.uid === current?.uid),
        untilDestroyed(this)
      )
      .subscribe(user => {
        this.cancelTabNameEdit();
        this.deactivateCurrentAgent();
        this.currentAgent = null;
        this.activeTabId = null;
        this.tabs = [];

        if (user) {
          this.loadPersistedAgents();
        } else {
          this.ensurePendingTab();
        }
      });
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes["agentIdToActivate"] && this.agentIdToActivate) {
      this.loadAgentFromInput();
    }
  }

  @HostListener("window:beforeunload")
  ngOnDestroy(): void {
    this.deactivateCurrentAgent();
  }

  private loadAgentFromInput(): void {
    const agentId = this.agentIdToActivate;
    if (!agentId || this.activeAgentId === agentId || this.loadingAgentId === agentId) {
      return;
    }

    this.isLoadingAgent = true;
    this.loadingAgentId = agentId;
    this.agentService
      .getAgent(agentId)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: agent => {
          this.isLoadingAgent = false;
          this.loadingAgentId = null;
          this.openAgentTab(agent);
          this.agentIdToActivate = undefined;
        },
        error: (error: unknown) => {
          this.isLoadingAgent = false;
          this.loadingAgentId = null;
          this.currentAgent = null;
          this.deactivateCurrentAgent();
          this.ensurePendingTab();
          console.error("Failed to load agent:", error);
        },
      });
  }

  private loadPersistedAgents(): void {
    this.isLoadingAgent = true;
    this.agentService
      .getAllAgents()
      .pipe(untilDestroyed(this))
      .subscribe({
        next: agents => {
          this.isLoadingAgent = false;
          if (agents.length === 0) {
            this.tabs = [];
            this.ensurePendingTab();
            if (this.agentIdToActivate) {
              this.loadAgentFromInput();
            }
            return;
          }

          this.tabs = agents.map(agent => ({
            localId: `agent-${agent.id}`,
            agentInfo: agent,
          }));

          const requestedTab = this.agentIdToActivate
            ? this.tabs.find(tab => tab.agentInfo?.id === this.agentIdToActivate)
            : undefined;

          if (requestedTab) {
            this.selectTab(requestedTab.localId);
            this.agentIdToActivate = undefined;
          } else if (this.agentIdToActivate) {
            this.loadAgentFromInput();
          } else {
            this.selectTab(this.tabs[0].localId);
          }
        },
        error: (error: unknown) => {
          this.isLoadingAgent = false;
          this.tabs = [];
          this.ensurePendingTab();
          console.error("Failed to load agents:", error);
        },
      });
  }

  addPendingTab(): void {
    // Only one unsaved "New chat" tab may exist; if one is already open, just focus it
    // instead of stacking up pending tabs that can't be closed.
    const existingPending = this.tabs.find(tab => !tab.agentInfo);
    if (existingPending) {
      this.selectTab(existingPending.localId);
      return;
    }
    const tab = this.createPendingTab();
    this.tabs = [...this.tabs, tab];
    this.selectTab(tab.localId);
  }

  /** True when an unsaved "New chat" tab (no real agent yet) is already open. */
  get hasPendingTab(): boolean {
    return this.tabs.some(tab => !tab.agentInfo);
  }

  selectTab(tabId: string): void {
    const tab = this.tabs.find(candidate => candidate.localId === tabId);
    if (!tab) {
      return;
    }

    this.deactivateCurrentAgent();
    this.activeTabId = tab.localId;
    this.currentAgent = tab.agentInfo;

    if (tab.agentInfo) {
      this.activeAgentId = tab.agentInfo.id;
      this.agentService.activateAgent(tab.agentInfo.id);
    }
  }

  onAgentReady(agent: AgentInfo, tabId?: string): void {
    const tab = this.tabs.find(candidate => candidate.localId === (tabId ?? this.activeTabId));
    if (!tab) {
      this.openAgentTab(agent);
      return;
    }

    tab.agentInfo = agent;
    this.tabs = [...this.tabs];

    if (this.activeTabId !== tab.localId) {
      this.selectTab(tab.localId);
      return;
    }

    this.deactivateCurrentAgent();
    this.currentAgent = agent;
    this.activeAgentId = agent.id;
    this.agentService.activateAgent(agent.id);
  }

  onAgentUpdated(agent: AgentInfo, tabId?: string): void {
    const tab = this.tabs.find(candidate => candidate.localId === (tabId ?? this.activeTabId));
    if (!tab) {
      return;
    }

    tab.agentInfo = agent;
    this.tabs = [...this.tabs];
    if (this.activeTabId === tab.localId) {
      this.currentAgent = agent;
      this.activeAgentId = agent.id;
    }
  }

  startTabNameEdit(tab: AgentWorkbenchTab, event: MouseEvent): void {
    event.stopPropagation();
    if (!tab.agentInfo) {
      return;
    }
    this.editingTabId = tab.localId;
    this.editingName = tab.agentInfo.name;
  }

  saveTabName(tab: AgentWorkbenchTab): void {
    if (this.editingTabId !== tab.localId) {
      return;
    }

    const agent = tab.agentInfo;
    const nextName = this.editingName.trim();
    this.editingTabId = null;

    if (!agent || !nextName || nextName === agent.name) {
      return;
    }

    this.agentService
      .updateAgent(agent.id, { name: nextName })
      .pipe(untilDestroyed(this))
      .subscribe({
        next: updatedAgent => this.onAgentUpdated(updatedAgent, tab.localId),
        error: (error: unknown) => {
          console.error("Failed to rename agent:", error);
        },
      });
  }

  cancelTabNameEdit(event?: Event): void {
    event?.stopPropagation();
    this.editingTabId = null;
    this.editingName = "";
  }

  deleteTabAgent(tab: AgentWorkbenchTab, event: Event): void {
    if (!tab.agentInfo) {
      event.stopPropagation();
      return;
    }
    this.deleteAgent(tab.agentInfo.id, event);
  }

  getTabLabel(tab: AgentWorkbenchTab): string {
    return tab.agentInfo?.name ?? "New chat";
  }

  isActiveAgentTab(tab: AgentWorkbenchTab): boolean {
    return this.activeTabId === tab.localId && !!tab.agentInfo;
  }

  trackByTabId(_index: number, tab: AgentWorkbenchTab): string {
    return tab.localId;
  }

  private ensurePendingTab(): void {
    if (this.tabs.length > 0) {
      return;
    }

    const tab = this.createPendingTab();
    this.tabs = [tab];
    this.activeTabId = tab.localId;
  }

  private createPendingTab(): AgentWorkbenchTab {
    return {
      localId: `pending-${this.nextPendingIndex++}`,
      agentInfo: null,
    };
  }

  private openAgentTab(agent: AgentInfo): void {
    const existingTab = this.tabs.find(tab => tab.agentInfo?.id === agent.id);
    if (existingTab) {
      existingTab.agentInfo = agent;
      this.tabs = [...this.tabs];
      this.selectTab(existingTab.localId);
      return;
    }

    const reusablePendingTab =
      this.tabs.length === 1 && !this.tabs[0].agentInfo ? this.tabs[0] : this.tabs.find(tab => !tab.agentInfo);
    const targetTab = reusablePendingTab ?? {
      localId: `agent-${agent.id}`,
      agentInfo: null,
    };

    targetTab.agentInfo = agent;
    if (!reusablePendingTab) {
      this.tabs = [...this.tabs, targetTab];
    } else {
      this.tabs = [...this.tabs];
    }
    this.selectTab(targetTab.localId);
  }

  private deactivateCurrentAgent(): void {
    if (this.activeAgentId) {
      this.agentService.deactivateAgent(this.activeAgentId);
      this.activeAgentId = null;
    }
  }

  deleteAgent(agentId: string, event: Event): void {
    event.stopPropagation(); // Prevent tab switch

    if (!confirm("Are you sure you want to delete this agent?")) {
      return;
    }

    if (this.activeAgentId === agentId) {
      this.deactivateCurrentAgent();
    }

    this.agentService
      .deleteAgent(agentId)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: () => {
          const deletedIndex = this.tabs.findIndex(tab => tab.agentInfo?.id === agentId);
          if (deletedIndex >= 0) {
            this.tabs = this.tabs.filter((_, index) => index !== deletedIndex);
          }

          if (this.tabs.length === 0) {
            this.ensurePendingTab();
          }

          if (this.currentAgent?.id === agentId || this.activeTabId === null) {
            const nextTab = this.tabs[Math.min(deletedIndex, this.tabs.length - 1)];
            this.selectTab(nextTab.localId);
          }
        },
        error: (error: unknown) => {
          console.error("Failed to delete agent:", error);
        },
      });
  }
}
