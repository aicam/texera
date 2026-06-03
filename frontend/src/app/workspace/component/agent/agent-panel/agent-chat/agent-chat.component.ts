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

import {
  Component,
  ViewChild,
  ElementRef,
  EventEmitter,
  Input,
  Output,
  OnInit,
  AfterViewChecked,
  ChangeDetectorRef,
  OnDestroy,
  OnChanges,
  SimpleChanges,
} from "@angular/core";
import { NavigationEnd, Router } from "@angular/router";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { Subject } from "rxjs";
import { distinctUntilChanged, filter, finalize, map, switchMap, takeUntil } from "rxjs/operators";
import { AgentState, ReActStep } from "../../../../service/agent/agent-types";
import { AgentInfo, AgentService, ModelType } from "../../../../service/agent/agent.service";
import { WorkflowActionService } from "../../../../service/workflow-graph/model/workflow-action.service";
import { applyWorkflowContentDelta } from "../../../../service/agent/workflow-delta";
import { NotificationService } from "../../../../../common/service/notification/notification.service";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzCardComponent } from "ng-zorro-antd/card";
import { NgIf, NgFor } from "@angular/common";
import { MarkdownComponent } from "ngx-markdown";
import { NzSpinComponent } from "ng-zorro-antd/spin";
import { NzInputDirective, NzAutosizeDirective } from "ng-zorro-antd/input";
import { NzSelectComponent, NzOptionComponent } from "ng-zorro-antd/select";
import { FormsModule } from "@angular/forms";
import { ReActStepDetailModalComponent } from "../react-step-detail-modal/react-step-detail-modal.component";
import { ComputingUnitStatusService } from "../../../../../common/service/computing-unit/computing-unit-status/computing-unit-status.service";
import { DashboardWorkflowComputingUnit } from "../../../../../common/type/workflow-computing-unit";

interface WorkspaceContextBadge {
  workflowId: number;
  computingUnitId?: number;
  computingUnitName?: string;
}

interface SuggestedQuestion {
  title: string;
  prompt: string;
  icon: string;
}

@UntilDestroy()
@Component({
  selector: "texera-agent-chat",
  templateUrl: "agent-chat.component.html",
  styleUrls: ["agent-chat.component.scss"],
  imports: [
    NzIconDirective,
    NzTooltipDirective,
    NzButtonComponent,
    NzCardComponent,
    NgIf,
    NgFor,
    MarkdownComponent,
    NzSpinComponent,
    NzInputDirective,
    NzSelectComponent,
    NzOptionComponent,
    FormsModule,
    NzAutosizeDirective,
    ReActStepDetailModalComponent,
  ],
})
export class AgentChatComponent implements OnInit, AfterViewChecked, OnDestroy, OnChanges {
  @Input() agentInfo: AgentInfo | null = null;
  @Input() isActive: boolean = false;
  @Output() agentCreated = new EventEmitter<AgentInfo>();
  @Output() agentUpdated = new EventEmitter<AgentInfo>();
  @ViewChild("messageContainer", { static: false }) messageContainer?: ElementRef;
  @ViewChild("messageInput", { static: false }) messageInput?: ElementRef;

  /** All steps (for timeline rendering) */
  public agentResponses: ReActStep[] = [];
  /** Steps on the HEAD path only (for chat rendering) */
  public visibleSteps: ReActStep[] = [];
  public currentMessage = "";
  private shouldScrollToBottom = false;
  public isDetailsModalVisible = false;
  public selectedResponse: ReActStep | null = null;
  public hoveredMessageIndex: number | null = null;
  public agentState: AgentState = AgentState.UNAVAILABLE;
  public workspaceContextBadge: WorkspaceContextBadge | null = null;
  // True while connecting and waiting for the agent's initial step history.
  public isLoadingSteps = false;
  public modelTypes: ModelType[] = [];
  public selectedModelType: string | null = null;
  public isLoadingModels = false;
  public isCreatingAgent = false;
  public isUpdatingModel = false;
  public readonly suggestedQuestions: SuggestedQuestion[] = [
    {
      title: "Introduce dknet-ai.org",
      prompt: "Please briefly introduce what I can do on dknet-ai.org.",
      icon: "compass",
    },
    {
      title: "Bio-MCP PubMed Search",
      prompt: "Search PubMed for recent single-cell RNA-seq studies about Alzheimer's disease biomarkers.",
      icon: "experiment",
    },
    {
      title: "Start Your Data Analysis",
      prompt: "Please tell me what data I can analyze and how I can do data analysis here.",
      icon: "bar-chart",
    },
  ];

  // Current HEAD step ID in the version tree
  public currentHeadId: string | null = null;

  // Subject to control workflow subscription lifecycle
  private stopWorkflowSubscription$ = new Subject<void>();
  private stopAgentSubscriptions$ = new Subject<void>();
  private attachedAgentId: string | null = null;
  private currentUrl = "";
  private selectedComputingUnit: DashboardWorkflowComputingUnit | null = null;

  constructor(
    private agentService: AgentService,
    private workflowActionService: WorkflowActionService,
    private notificationService: NotificationService,
    private cdr: ChangeDetectorRef,
    private router: Router,
    private computingUnitStatusService: ComputingUnitStatusService
  ) {}

  ngOnInit(): void {
    this.registerWorkspaceContextBadge();
    this.loadModelTypes();
    this.attachAgent(this.agentInfo);

    // Auto-persist is intentionally left enabled while the agent runs: the agent
    // streams its edits onto the canvas, and the frontend's normal auto-persist then
    // saves them to the backend (the single source of truth). The agent also persists
    // at task completion as a backstop.

    // Note: Workflow subscription is started/stopped via ngOnChanges based on isActive
    // This prevents automatic workflow switching when multiple agents are running

    // Subscribe to scroll-to-step requests
    this.agentService.scrollToStep$.pipe(untilDestroyed(this)).subscribe(({ agentId, messageId, stepId }) => {
      if (this.agentInfo && agentId === this.agentInfo.id) {
        this.scrollToStep(messageId, stepId);
      }
    });
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes["agentInfo"] && !changes["agentInfo"].firstChange) {
      this.attachAgent(this.agentInfo);
    }

    if (changes["isActive"]) {
      if (this.isActive && this.agentInfo) {
        this.startWorkflowSubscription();
      } else {
        this.stopWorkflowSubscription();
      }
    }
  }

  private loadModelTypes(): void {
    this.isLoadingModels = true;
    this.agentService
      .fetchModelTypes()
      .pipe(
        finalize(() => {
          this.isLoadingModels = false;
          this.cdr.detectChanges();
        }),
        untilDestroyed(this)
      )
      .subscribe(models => {
        this.modelTypes = models;
        if (this.agentInfo) {
          this.selectedModelType = this.agentInfo.modelType;
        } else if (!this.selectedModelType && models.length > 0) {
          this.selectedModelType = models[0].id;
        }
      });
  }

  private attachAgent(agentInfo: AgentInfo | null): void {
    if (!agentInfo) {
      this.attachedAgentId = null;
      this.stopAgentSubscriptions$.next();
      this.stopWorkflowSubscription();
      this.agentResponses = [];
      this.visibleSteps = [];
      this.currentHeadId = null;
      this.agentState = AgentState.UNAVAILABLE;
      this.isLoadingSteps = false;
      return;
    }

    if (this.attachedAgentId === agentInfo.id) {
      this.selectedModelType = agentInfo.modelType;
      return;
    }

    this.stopAgentSubscriptions$.next();
    this.attachedAgentId = agentInfo.id;
    this.selectedModelType = agentInfo.modelType;
    this.agentState = agentInfo.state ?? AgentState.UNAVAILABLE;
    this.agentResponses = [];
    this.visibleSteps = [];
    this.currentHeadId = null;
    this.hoveredMessageIndex = null;

    this.agentService
      .getInitializingObservable(agentInfo.id)
      .pipe(distinctUntilChanged(), takeUntil(this.stopAgentSubscriptions$), untilDestroyed(this))
      .subscribe(initializing => {
        this.isLoadingSteps = initializing;
        this.cdr.detectChanges();
      });

    this.agentService
      .getAgentState(agentInfo.id)
      .pipe(takeUntil(this.stopAgentSubscriptions$), untilDestroyed(this))
      .subscribe(state => {
        this.agentState = state;
        this.cdr.detectChanges();
      });

    this.agentService
      .getAgentStateObservable(agentInfo.id)
      .pipe(takeUntil(this.stopAgentSubscriptions$), untilDestroyed(this))
      .subscribe(state => {
        this.agentState = state;
        this.cdr.detectChanges();
      });

    this.agentService
      .getReActStepsObservable(agentInfo.id)
      .pipe(takeUntil(this.stopAgentSubscriptions$), untilDestroyed(this))
      .subscribe(steps => {
        const previousLength = this.visibleSteps.length;
        this.agentResponses = steps;
        this.updateVisibleSteps();
        this.shouldScrollToBottom = true;

        if (this.visibleSteps.length > 0) {
          const latestIndex = this.visibleSteps.length - 1;
          const previousLatestIndex = previousLength - 1;

          if (
            this.hoveredMessageIndex === null ||
            this.hoveredMessageIndex === previousLatestIndex ||
            this.hoveredMessageIndex >= this.visibleSteps.length
          ) {
            this.setHoveredMessage(latestIndex);
          }
        }

        this.cdr.detectChanges();
      });

    this.agentService
      .getHeadIdObservable(agentInfo.id)
      .pipe(takeUntil(this.stopAgentSubscriptions$), untilDestroyed(this))
      .subscribe(headId => {
        this.currentHeadId = headId;
        this.updateVisibleSteps();
        this.cdr.detectChanges();
      });

    if (this.isActive) {
      this.startWorkflowSubscription();
    }
  }

  /**
   * Start subscribing to workflow changes from the agent.
   * Only called when this agent tab is active.
   */
  private startWorkflowSubscription(): void {
    if (!this.agentInfo) {
      return;
    }

    // Stop any existing subscription first
    this.stopWorkflowSubscription$.next();

    // Drive the canvas from genuine edits this agent makes (steps / version
    // checkouts) — NOT from a replayed snapshot or DB poll. This is why merely
    // switching to this tab no longer reloads (and used to wipe) the canvas.
    this.agentService
      .getWorkflowEditObservable(this.agentInfo.id)
      .pipe(
        distinctUntilChanged((prev, curr) => JSON.stringify(prev?.content) === JSON.stringify(curr?.content)),
        takeUntil(this.stopWorkflowSubscription$),
        untilDestroyed(this)
      )
      .subscribe(editedWorkflow => {
        // Apply the agent's edits granularly through the normal edit API so they flow into
        // the shared model, render live, and auto-persist like a human edit — instead of a
        // full canvas reload that flickers, resets the viewport, and clobbers untouched
        // operators. The util skips a blank snapshot so a transient empty payload can never
        // wipe the canvas, and preserves workflow metadata since it never touches it.
        applyWorkflowContentDelta(this.workflowActionService, editedWorkflow.content);
      });
  }

  /**
   * Stop subscribing to workflow changes.
   * Called when switching away from this agent tab.
   */
  private stopWorkflowSubscription(): void {
    this.stopWorkflowSubscription$.next();
  }

  ngOnDestroy(): void {
    // Stop workflow subscription
    this.stopWorkflowSubscription$.next();
    this.stopWorkflowSubscription$.complete();
    this.stopAgentSubscriptions$.next();
    this.stopAgentSubscriptions$.complete();
  }

  ngAfterViewChecked(): void {
    if (this.shouldScrollToBottom) {
      this.scrollToBottom();
      this.shouldScrollToBottom = false;
    }
  }

  public setHoveredMessage(index: number | null): void {
    if (!this.agentInfo) {
      return;
    }

    // When unhovered (null), automatically revert to latest step
    if (index === null && this.visibleSteps.length > 0) {
      index = this.visibleSteps.length - 1;
    }

    this.hoveredMessageIndex = index;
    const hoveredStep = index !== null && index >= 0 ? this.visibleSteps[index] : null;
    this.agentService.setHoveredMessage(this.agentInfo.id, hoveredStep);
  }

  public showResponseDetails(response: ReActStep): void {
    this.selectedResponse = response;
    this.isDetailsModalVisible = true;
  }

  public closeDetailsModal(): void {
    this.isDetailsModalVisible = false;
    this.selectedResponse = null;
  }

  public getToolResult(response: ReActStep, toolCallIndex: number): any {
    if (!response.toolResults || toolCallIndex >= response.toolResults.length) {
      return null;
    }
    const toolResult = response.toolResults[toolCallIndex];
    return toolResult.output || toolResult.result || toolResult;
  }

  public getToolOperatorAccess(
    response: ReActStep,
    toolCallIndex: number
  ): { viewedOperatorIds: string[]; modifiedOperatorIds: string[] } | null {
    if (!response.operatorAccess) {
      return null;
    }
    return response.operatorAccess.get(toolCallIndex) || null;
  }

  public hasOperatorAccess(response: ReActStep): boolean {
    return !!response.operatorAccess && response.operatorAccess.size > 0;
  }

  public sendMessage(): void {
    if (!this.currentMessage.trim() || !this.canSendMessage()) {
      return;
    }

    const userMessage = this.currentMessage.trim();
    this.currentMessage = "";

    if (!this.agentInfo) {
      this.createAgentAndSendMessage(userMessage);
      return;
    }

    this.agentService.sendMessage(this.agentInfo.id, userMessage);
  }

  public sendSuggestedQuestion(question: string): void {
    if (!this.canSendMessage()) {
      return;
    }
    this.currentMessage = question;
    this.sendMessage();
  }

  public showSuggestedQuestions(): boolean {
    return this.visibleSteps.length === 0 && !this.isLoadingSteps && !this.isCreatingAgent;
  }

  public onModelTypeChange(modelType: string | null): void {
    this.selectedModelType = modelType;
    const agentInfo = this.agentInfo;
    if (!agentInfo || !modelType || modelType === agentInfo.modelType) {
      return;
    }

    const previousModelType = agentInfo.modelType;
    this.isUpdatingModel = true;
    this.agentService
      .updateAgent(agentInfo.id, { modelType })
      .pipe(
        finalize(() => {
          this.isUpdatingModel = false;
          this.cdr.detectChanges();
        }),
        untilDestroyed(this)
      )
      .subscribe({
        next: updatedAgent => {
          this.agentInfo = updatedAgent;
          this.selectedModelType = updatedAgent.modelType;
          this.agentUpdated.emit(updatedAgent);
        },
        error: () => {
          this.selectedModelType = previousModelType;
        },
      });
  }

  private createAgentAndSendMessage(userMessage: string): void {
    if (!this.selectedModelType) {
      this.currentMessage = userMessage;
      this.notificationService.error("No models available. Please check the LiteLLM configuration.");
      return;
    }

    this.isCreatingAgent = true;
    this.isLoadingSteps = true;

    this.agentService
      .createAgent(this.selectedModelType)
      .pipe(
        switchMap(agentInfo => {
          this.agentInfo = agentInfo;
          this.agentCreated.emit(agentInfo);
          this.attachAgent(agentInfo);
          return this.agentService.connectAgent(agentInfo.id).pipe(map(connected => ({ agentInfo, connected })));
        }),
        finalize(() => {
          this.isCreatingAgent = false;
          this.cdr.detectChanges();
        }),
        untilDestroyed(this)
      )
      .subscribe({
        next: ({ agentInfo, connected }) => {
          if (!connected) {
            this.currentMessage = userMessage;
            this.notificationService.error("Agent connection not available");
            return;
          }
          this.agentService.sendMessage(agentInfo.id, userMessage);
        },
        error: () => {
          this.currentMessage = userMessage;
          this.isLoadingSteps = false;
        },
      });
  }

  /**
   * Check if messages can be sent (only when agent is available).
   */
  public canSendMessage(): boolean {
    if (this.isCreatingAgent || this.isLoadingModels || this.isUpdatingModel) {
      return false;
    }
    if (!this.agentInfo) {
      return !!this.selectedModelType;
    }
    return this.agentState === AgentState.AVAILABLE;
  }

  /**
   * Get the NG-ZORRO icon type based on current agent state.
   */
  public getStateIcon(): string {
    if (!this.agentInfo) {
      return "clock-circle";
    }
    if (this.isConnectionBusy()) {
      return "sync";
    }
    switch (this.agentState) {
      case AgentState.AVAILABLE:
        return "check-circle";
      case AgentState.GENERATING:
      case AgentState.STOPPING:
        return "sync";
      case AgentState.UNAVAILABLE:
      default:
        return "sync";
    }
  }

  /**
   * Get the icon color based on current agent state.
   */
  public getStateIconColor(): string {
    if (!this.agentInfo || this.isConnectionBusy()) {
      return "#1890ff";
    }
    switch (this.agentState) {
      case AgentState.AVAILABLE:
        return "#52c41a";
      case AgentState.GENERATING:
      case AgentState.STOPPING:
        return "#1890ff";
      case AgentState.UNAVAILABLE:
      default:
        return "#1890ff";
    }
  }

  /**
   * Get the tooltip text for the state icon.
   */
  public getStateTooltip(): string {
    if (!this.agentInfo) {
      return "Pending first message";
    }
    if (this.isLoadingSteps) {
      return "Connecting to agent...";
    }
    switch (this.agentState) {
      case AgentState.AVAILABLE:
        return "Agent is ready";
      case AgentState.GENERATING:
        return "Agent is generating response...";
      case AgentState.STOPPING:
        return "Agent is stopping...";
      case AgentState.UNAVAILABLE:
        return "Connecting to agent...";
      default:
        return "Agent status unknown";
    }
  }

  public getChatTitle(): string {
    return this.agentInfo?.name ?? "New chat";
  }

  public getModelIconType(modelType: ModelType): string {
    return this.getModelIconTypeById(modelType.icon || modelType.id);
  }

  public getModelIconTypeById(modelIdOrIcon: string | null | undefined): string {
    if (this.getModelIconImageSrc(modelIdOrIcon)) {
      return "";
    }
    return "cloud";
  }

  public getModelIconImageSrc(modelIdOrIcon: string | null | undefined): string | null {
    const normalized = (modelIdOrIcon ?? "").toLowerCase();
    if (normalized === "gpt-image" || normalized.startsWith("gpt")) {
      return "assets/svg/gpt.png";
    }
    if (normalized === "claude-image" || normalized.startsWith("claude")) {
      return "assets/svg/claude.png";
    }
    return null;
  }

  public onEnterPress(event: KeyboardEvent): void {
    if (!event.shiftKey) {
      event.preventDefault();
      this.sendMessage();
    }
  }

  private scrollToBottom(): void {
    if (this.messageContainer) {
      const element = this.messageContainer.nativeElement;
      element.scrollTop = element.scrollHeight;
    }
  }

  public stopGeneration(): void {
    if (this.agentInfo) {
      this.agentService.stopGeneration(this.agentInfo.id);
    }
  }

  public clearMessages(): void {
    if (this.agentInfo) {
      this.agentService.clearMessages(this.agentInfo.id);
    }
  }

  public getWorkspaceContextTooltip(): string {
    if (!this.workspaceContextBadge) {
      return "";
    }

    const workflowText = `workflow ID ${this.workspaceContextBadge.workflowId}`;
    if (this.workspaceContextBadge.computingUnitId === undefined) {
      return `Next message will include ${workflowText}. No computing unit is currently selected.`;
    }

    const unitName = this.workspaceContextBadge.computingUnitName
      ? ` (${this.workspaceContextBadge.computingUnitName})`
      : "";
    return `Next message will include ${workflowText} and computing unit ID ${this.workspaceContextBadge.computingUnitId}${unitName}.`;
  }

  private registerWorkspaceContextBadge(): void {
    this.currentUrl = this.router.url;
    this.refreshWorkspaceContextBadge();

    this.router.events
      .pipe(
        filter((event): event is NavigationEnd => event instanceof NavigationEnd),
        untilDestroyed(this)
      )
      .subscribe(event => {
        this.currentUrl = event.urlAfterRedirects;
        this.refreshWorkspaceContextBadge();
      });

    this.workflowActionService
      .workflowMetaDataChanged()
      .pipe(untilDestroyed(this))
      .subscribe(() => {
        this.refreshWorkspaceContextBadge();
      });

    this.computingUnitStatusService
      .getSelectedComputingUnit()
      .pipe(untilDestroyed(this))
      .subscribe(unit => {
        this.selectedComputingUnit = unit;
        this.refreshWorkspaceContextBadge();
      });
  }

  private refreshWorkspaceContextBadge(): void {
    if (!this.isWorkspacePage(this.currentUrl)) {
      this.workspaceContextBadge = null;
      return;
    }

    const workflowId = this.getWorkspaceWorkflowId();
    if (workflowId === undefined) {
      this.workspaceContextBadge = null;
      return;
    }

    this.workspaceContextBadge = {
      workflowId,
      computingUnitId: this.selectedComputingUnit?.computingUnit.cuid,
      computingUnitName: this.selectedComputingUnit?.computingUnit.name,
    };
  }

  private getWorkspaceWorkflowId(): number | undefined {
    const routeWorkflowId = this.getRouteWorkflowId(this.currentUrl);
    if (routeWorkflowId !== undefined) {
      return routeWorkflowId;
    }

    const metadataWorkflowId = this.workflowActionService.getWorkflowMetadata()?.wid;
    return metadataWorkflowId !== undefined && metadataWorkflowId > 0 ? metadataWorkflowId : undefined;
  }

  private getRouteWorkflowId(url: string): number | undefined {
    const match = url.match(/^\/dashboard\/user\/workflow\/(\d+)(?:[/?#]|$)/);
    if (!match) {
      return undefined;
    }
    const workflowId = Number(match[1]);
    return Number.isFinite(workflowId) && workflowId > 0 ? workflowId : undefined;
  }

  private isWorkspacePage(url: string): boolean {
    return this.getRouteWorkflowId(url) !== undefined;
  }

  /**
   * Export the ReAct steps as a JSON file.
   * Fetches steps from the backend to get clean JSON (without Map objects).
   */
  public exportReActSteps(): void {
    const agentInfo = this.agentInfo;
    if (!agentInfo) {
      this.notificationService.warning("No ReAct steps to export");
      return;
    }
    if (this.visibleSteps.length === 0) {
      this.notificationService.warning("No ReAct steps to export");
      return;
    }

    this.agentService
      .getReActSteps(agentInfo.id)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: (steps: ReActStep[]) => {
          // Convert steps to plain objects (handle Map -> object for operatorAccess)
          const exportSteps = steps.map(step => {
            const plain: any = { ...step };
            if (step.operatorAccess) {
              const accessObj: Record<string, any> = {};
              step.operatorAccess.forEach((value, key) => {
                accessObj[key] = value;
              });
              plain.operatorAccess = accessObj;
            }
            return plain;
          });

          const exportData = {
            agentId: agentInfo.id,
            agentName: agentInfo.name,
            modelType: agentInfo.modelType,
            exportedAt: new Date().toISOString(),
            stepCount: exportSteps.length,
            steps: exportSteps,
          };

          const jsonString = JSON.stringify(exportData, null, 2);
          const blob = new Blob([jsonString], { type: "application/json" });
          const url = URL.createObjectURL(blob);

          const link = document.createElement("a");
          link.href = url;
          link.download = `${agentInfo.name}-react-steps-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.json`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          URL.revokeObjectURL(url);

          this.notificationService.success(`Exported ${exportSteps.length} ReAct steps`);
        },
        error: (err: unknown) => {
          console.error("Failed to export ReAct steps:", err);
          this.notificationService.error("Failed to export ReAct steps");
        },
      });
  }

  public isGenerating(): boolean {
    return this.agentState === AgentState.GENERATING;
  }

  public isAvailable(): boolean {
    return this.agentState === AgentState.AVAILABLE;
  }

  public isConnected(): boolean {
    return !this.agentInfo || this.agentState !== AgentState.UNAVAILABLE;
  }

  public isStopping(): boolean {
    return this.agentState === AgentState.STOPPING;
  }

  public isConnectionBusy(): boolean {
    return !!this.agentInfo && (this.isLoadingSteps || this.agentState === AgentState.UNAVAILABLE);
  }

  public isInputDisabled(): boolean {
    return (
      this.isCreatingAgent ||
      this.isLoadingModels ||
      this.isUpdatingModel ||
      (!!this.agentInfo && !this.canSendMessage())
    );
  }

  public hasSelectedModelOption(): boolean {
    return !!this.selectedModelType && this.modelTypes.some(model => model.id === this.selectedModelType);
  }

  public getLoadingText(): string {
    if (this.isCreatingAgent) {
      return "Starting agent...";
    }
    return "Loading conversation...";
  }

  public showConnectionStatus(): boolean {
    return !!this.agentInfo && (this.isLoadingSteps || this.agentState === AgentState.UNAVAILABLE);
  }

  public getConnectionStatusText(): string {
    return this.isLoadingSteps ? "Connecting to agent..." : "Reconnecting to agent...";
  }

  /**
   * Recompute visibleSteps: only steps on the ancestor path from root to HEAD.
   */
  private updateVisibleSteps(): void {
    if (!this.currentHeadId || this.agentResponses.length === 0) {
      this.visibleSteps = this.agentResponses;
      return;
    }
    const stepMap = new Map(this.agentResponses.map(s => [s.id, s]));
    const ancestorIds = new Set<string>();
    let current: string | undefined = this.currentHeadId;
    while (current) {
      ancestorIds.add(current);
      current = stepMap.get(current)?.parentId;
    }
    this.visibleSteps = this.agentResponses.filter(s => ancestorIds.has(s.id));
  }

  /**
   * Scroll chat messages to a specific step index.
   */
  private scrollToMessage(stepIndex: number): void {
    if (!this.messageContainer) {
      return;
    }

    const container = this.messageContainer.nativeElement;
    const messages = container.querySelectorAll(".message");

    if (stepIndex >= 0 && stepIndex < messages.length) {
      messages[stepIndex].scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  /**
   * Scroll to a specific step in the chat by messageId and stepId.
   */
  private scrollToStep(messageId: string, stepId: number): void {
    // Find the step index in visibleSteps
    const stepIndex = this.visibleSteps.findIndex(step => step.messageId === messageId && step.stepId === stepId);

    if (stepIndex >= 0) {
      this.scrollToMessage(stepIndex);
      // Highlight the message briefly
      this.setHoveredMessage(stepIndex);
    }
  }
}
