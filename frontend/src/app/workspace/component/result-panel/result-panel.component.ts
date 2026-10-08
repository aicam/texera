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

import { ChangeDetectorRef, Component, ElementRef, HostListener, OnInit, Type, ViewChild } from "@angular/core";
import { merge } from "rxjs";
import { ExecuteWorkflowService } from "../../service/execute-workflow/execute-workflow.service";
import { WorkflowActionService } from "../../service/workflow-graph/model/workflow-action.service";
import { ExecutionState, ExecutionStateInfo } from "../../types/execute-workflow.interface";
import { ResultTableFrameComponent } from "./result-table-frame/result-table-frame.component";
import { ConsoleFrameComponent } from "./console-frame/console-frame.component";
import { WorkflowResultService } from "../../service/workflow-result/workflow-result.service";
import { PanelResizeService } from "../../service/workflow-result/panel-resize/panel-resize.service";
import { filter } from "rxjs/operators";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { isPythonUdf, isSink } from "../../service/workflow-graph/model/workflow-graph";
import { WorkflowVersionService } from "../../../dashboard/service/user/workflow-version/workflow-version.service";
import { ErrorFrameComponent } from "./error-frame/error-frame.component";
import { WorkflowConsoleService } from "../../service/workflow-console/workflow-console.service";
import { NzResizeEvent, NzResizableDirective, NzResizeHandlesComponent } from "ng-zorro-antd/resizable";
import { VisualizationFrameContentComponent } from "../visualization-panel-content/visualization-frame-content.component";
import { isDefined } from "../../../common/util/predicate";
import { CdkDragEnd, CdkDrag, CdkDragHandle } from "@angular/cdk/drag-drop";
import { PanelService } from "../../service/panel/panel.service";
import { WorkflowCompilingService } from "../../service/compile-workflow/workflow-compiling.service";
import { CompilationState } from "../../types/workflow-compiling.interface";
import { WorkflowFatalError } from "../../types/workflow-websocket.interface";
import { NzMenuDirective, NzMenuItemComponent, NzMenuDividerDirective } from "ng-zorro-antd/menu";
import { NgClass, NgIf, NgFor, NgComponentOutlet, KeyValuePipe } from "@angular/common";
import { ɵNzTransitionPatchDirective } from "ng-zorro-antd/core/transition-patch";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { NzSpaceCompactItemDirective } from "ng-zorro-antd/space";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzTabsComponent, NzTabComponent } from "ng-zorro-antd/tabs";
import { ReviewFrameComponent } from "./review-frame/review-frame.component";

export const DEFAULT_WIDTH = 800;
export const DEFAULT_HEIGHT = 500;
export const CLOSED_HEIGHT = 32.5;
/** The container sits this far above the canvas's bottom edge before any drag (see `top` in the scss). */
const NATURAL_TOP_OFFSET = 300;
const LEGACY_STYLE_KEY = "result-panel-style";
/**
 * ResultPanelComponent is the bottom level area that displays the
 *  execution result of a workflow after the execution finishes.
 */
@UntilDestroy()
@Component({
  selector: "texera-result-panel",
  templateUrl: "./result-panel.component.html",
  styleUrls: ["./result-panel.component.scss"],
  imports: [
    NzMenuDirective,
    NgClass,
    NgIf,
    NzMenuItemComponent,
    ɵNzTransitionPatchDirective,
    NzTooltipDirective,
    NzIconDirective,
    NzMenuDividerDirective,
    CdkDrag,
    NzResizableDirective,
    NzSpaceCompactItemDirective,
    NzButtonComponent,
    CdkDragHandle,
    NzTabsComponent,
    NzTabComponent,
    NgFor,
    NgComponentOutlet,
    NzResizeHandlesComponent,
    KeyValuePipe,
  ],
})
export class ResultPanelComponent implements OnInit {
  @ViewChild("dynamicComponent")
  componentOutlets!: ElementRef;
  frameComponentConfigs: Map<string, { component: Type<any>; componentInputs: {} }> = new Map();
  protected readonly window = window;
  id = -1;
  width = DEFAULT_WIDTH;
  height = DEFAULT_HEIGHT;
  operatorTitle = "";
  dragPosition = { x: 0, y: 0 };
  returnPosition = { x: 0, y: 0 };
  /**
   * A docked panel follows the canvas's bottom-left corner as it opens and resizes; a dragged one
   * stays where it was dropped until it is closed, which always docks it, so its open button is
   * always at the bottom-left.
   */
  docked = true;

  // the highlighted operator ID for display result table / visualization / breakpoint
  currentOperatorId?: string | undefined;

  previewWorkflowVersion: boolean = false;

  constructor(
    private executeWorkflowService: ExecuteWorkflowService,
    private workflowActionService: WorkflowActionService,
    private workflowCompilingService: WorkflowCompilingService,
    private workflowResultService: WorkflowResultService,
    private workflowVersionService: WorkflowVersionService,
    private changeDetectorRef: ChangeDetectorRef,
    private workflowConsoleService: WorkflowConsoleService,
    private resizeService: PanelResizeService,
    private panelService: PanelService
  ) {
    // The panel starts closed, and a closed panel is a bar at the canvas's bottom-left. Restoring
    // the last open height here left a closed panel 500px tall, with its open button floating
    // far above the corner where people click.
    this.width = 0;
    this.height = CLOSED_HEIGHT;
    this.resizeService.changePanelSize(this.width, this.height);
  }

  ngOnInit(): void {
    // The container's whole cssText used to be saved and restored; the drag library prepends its
    // own transform to whatever it finds, so that string grew on every visit until the panel opened
    // off-screen. A page now always starts docked, and the old key is dropped.
    localStorage.removeItem(LEGACY_STYLE_KEY);
    this.returnPosition = this.dockedPosition(this.height);
    this.dragPosition = { ...this.returnPosition };
    this.registerAutoRerenderResultPanel();
    this.registerAutoOpenResultPanel();
    this.registerResultClearedHandler();
    this.handleResultPanelForVersionPreview();
    this.panelService.closePanelStream.pipe(untilDestroyed(this)).subscribe(() => this.closePanel());
    this.panelService.resetPanelStream.pipe(untilDestroyed(this)).subscribe(() => {
      this.resetPanelPosition();
      this.openPanel();
    });
    this.workflowActionService.resultPanelOpen$.pipe(untilDestroyed(this)).subscribe(open => {
      if (open) {
        this.openPanel();
      } else {
        this.closePanel();
      }
    });
    // Once, for what is already there. Every re-render above waits for an event -- a state change,
    // a highlight, a result arriving -- and none of those follows a hand-over between a workflow's
    // two views: the highlight and the results are kept in root-provided services, so this panel
    // would come up empty beside an operator that is still shown selected, until the next event.
    this.rerenderResultPanel();
  }

  handleResultPanelForVersionPreview() {
    this.workflowVersionService
      .getDisplayParticularVersionStream()
      .pipe(untilDestroyed(this))
      .subscribe(displayVersionFlag => {
        this.previewWorkflowVersion = displayVersionFlag;
      });
  }

  registerAutoOpenResultPanel() {
    this.executeWorkflowService
      .getExecutionStateStream()
      .pipe(untilDestroyed(this))
      .subscribe(event => {
        const currentlyHighlighted = this.workflowActionService
          .getJointGraphWrapper()
          .getCurrentHighlightedOperatorIDs();

        // display panel when execution is completed and highlight sink to show results
        // condition must be (Running -> Completed) to prevent cases like
        //   (Uninitialized -> Completed) (a completed workflow is reloaded)
        if (event.previous.state === ExecutionState.Running && event.current.state === ExecutionState.Completed) {
          const activeSinkOperators = this.workflowActionService
            .getTexeraGraph()
            .getAllOperators()
            .filter(op => isSink(op))
            .filter(op => !op.isDisabled)
            .map(op => op.operatorID);

          if (activeSinkOperators.length > 0) {
            if (!(currentlyHighlighted.length == 1 && activeSinkOperators.includes(currentlyHighlighted[0]))) {
              this.workflowActionService.getJointGraphWrapper().unhighlightOperators(...currentlyHighlighted);
              this.workflowActionService.getJointGraphWrapper().highlightOperators(activeSinkOperators[0]);
            }
          }
        }

        // display panel and highlight a python UDF operator when workflow starts running
        if (event.current.state === ExecutionState.Running) {
          const activePythonUDFOperators = this.workflowActionService
            .getTexeraGraph()
            .getAllOperators()
            .filter(op => isPythonUdf(op))
            .filter(op => !op.isDisabled)
            .map(op => op.operatorID);

          if (activePythonUDFOperators.length > 0) {
            if (!(currentlyHighlighted.length == 1 && activePythonUDFOperators.includes(activePythonUDFOperators[0]))) {
              this.workflowActionService.getJointGraphWrapper().unhighlightOperators(...currentlyHighlighted);
              this.workflowActionService.getJointGraphWrapper().highlightOperators(activePythonUDFOperators[0]);
            }
          }
        }
      });
  }

  /**
   * Wipe the panel when results are dropped (e.g. switching computing units): a
   * still-highlighted operator isn't re-rendered, so its stale frames would linger.
   */
  registerResultClearedHandler() {
    this.workflowResultService
      .getResultClearedStream()
      .pipe(untilDestroyed(this))
      .subscribe(() => {
        this.clearResultPanel();
        this.currentOperatorId = undefined;
        this.operatorTitle = "";
        this.changeDetectorRef.detectChanges();
      });
  }

  registerAutoRerenderResultPanel() {
    merge(
      this.executeWorkflowService
        .getExecutionStateStream()
        .pipe(filter(event => ResultPanelComponent.needRerenderOnStateChange(event))),
      this.workflowCompilingService.getCompilationStateInfoChangedStream(),
      this.workflowActionService.getJointGraphWrapper().getJointOperatorHighlightStream(),
      this.workflowActionService.getJointGraphWrapper().getJointOperatorUnhighlightStream(),
      this.workflowResultService.getResultInitiateStream()
    )
      .pipe(untilDestroyed(this))
      .subscribe(_ => {
        this.rerenderResultPanel();
        this.changeDetectorRef.detectChanges();
        this.registerOperatorDisplayNameChangeHandler();
      });
  }

  rerenderResultPanel(): void {
    // if the workflow on the paper is a version preview then this is a temporary workaround until a future PR
    // TODO: let the results be tied with an execution ID instead of a workflow ID
    if (this.previewWorkflowVersion) {
      return;
    }
    // update highlighted operator
    const highlightedOperators = this.workflowActionService.getJointGraphWrapper().getCurrentHighlightedOperatorIDs();
    const currentHighlightedOperator = highlightedOperators.length === 1 ? highlightedOperators[0] : undefined;

    if (this.currentOperatorId !== currentHighlightedOperator) {
      // clear everything, prepare for state change
      this.clearResultPanel();
      this.currentOperatorId = currentHighlightedOperator;

      if (!this.currentOperatorId) {
        this.operatorTitle = "";
      }
    }

    if (
      this.executeWorkflowService.getExecutionState().state === ExecutionState.Failed ||
      this.workflowCompilingService.getWorkflowCompilationState() === CompilationState.Failed
    ) {
      if (this.currentOperatorId == null) {
        this.displayError(this.currentOperatorId);
      } else {
        const errorMessages = this.getWorkflowFatalErrors(this.currentOperatorId);
        if (errorMessages.length > 0) {
          this.displayError(this.currentOperatorId);
        } else {
          this.frameComponentConfigs.delete("Static Error");
        }
      }
    } else {
      this.frameComponentConfigs.delete("Static Error");
    }

    if (this.currentOperatorId) {
      this.displayResult(this.currentOperatorId);
      const operator = this.workflowActionService.getTexeraGraph().getOperator(this.currentOperatorId);
      if (this.workflowConsoleService.hasConsoleMessages(this.currentOperatorId) || isPythonUdf(operator)) {
        this.displayConsole(this.currentOperatorId, isPythonUdf(operator));
      }
      if (operator.operatorType === "ReviewAndCorrect") {
        // Its rows are browsed in Records, so an empty Result tab would only hide the Review tab.
        this.frameComponentConfigs.delete("Result");
        this.frameComponentConfigs.set("Review", {
          component: ReviewFrameComponent,
          componentInputs: { operatorId: this.currentOperatorId },
        });
      }
    }
  }

  clearResultPanel(): void {
    this.frameComponentConfigs.clear();
  }

  displayConsole(operatorId: string, consoleInputEnabled: boolean) {
    this.frameComponentConfigs.set("Console", {
      component: ConsoleFrameComponent,
      componentInputs: { operatorId, consoleInputEnabled },
    });
  }

  displayError(operatorId: string | undefined) {
    this.frameComponentConfigs.set("Static Error", {
      component: ErrorFrameComponent,
      componentInputs: { operatorId },
    });
  }

  displayResult(operatorId: string) {
    const resultService = this.workflowResultService.getResultService(operatorId);
    const paginatedResultService = this.workflowResultService.getPaginatedResultService(operatorId);
    if (paginatedResultService) {
      // display table result if it has paginated results
      this.frameComponentConfigs.set("Result", {
        component: ResultTableFrameComponent,
        componentInputs: { operatorId },
      });
    } else if (resultService) {
      // display visualization result
      this.frameComponentConfigs.set("Result", {
        component: VisualizationFrameContentComponent,
        componentInputs: { operatorId },
      });
    }
  }

  private getWorkflowFatalErrors(operatorId?: string): readonly WorkflowFatalError[] {
    // first fetch the error messages from the execution state store
    let errorMessages = this.executeWorkflowService.getErrorMessages();
    // then fetch error from the compilation state store
    errorMessages = errorMessages.concat(Object.values(this.workflowCompilingService.getWorkflowCompilationErrors()));
    // finally, if any operatorId is given, filter out those with matched Id
    if (operatorId) {
      errorMessages = errorMessages.filter(err => err.operatorId === operatorId);
    }
    return errorMessages;
  }

  private registerOperatorDisplayNameChangeHandler(): void {
    if (this.currentOperatorId) {
      const operator = this.workflowActionService.getTexeraGraph().getOperator(this.currentOperatorId);
      this.operatorTitle = operator.customDisplayName ?? "";
      this.workflowActionService
        .getTexeraGraph()
        .getOperatorDisplayNameChangedStream()
        .pipe(untilDestroyed(this))
        .subscribe(({ operatorID, newDisplayName }) => {
          if (operatorID === this.currentOperatorId) {
            this.operatorTitle = newDisplayName;
          }
        });
    }
  }

  private static needRerenderOnStateChange(event: {
    previous: ExecutionStateInfo;
    current: ExecutionStateInfo;
  }): boolean {
    // transitioning from any state to failed state
    if (event.current.state === ExecutionState.Failed) {
      return true;
    }

    // force refresh after fixing all editing-time errors
    if (event.previous.state === ExecutionState.Failed) {
      return true;
    }

    // transition from uninitialized / completed to anything else indicates a new execution of the workflow
    return event.previous.state === ExecutionState.Uninitialized || event.previous.state === ExecutionState.Completed;
  }

  openPanel() {
    this.height = DEFAULT_HEIGHT;
    this.width = DEFAULT_WIDTH;
    this.resizeService.changePanelSize(this.width, this.height);
    this.place();
  }

  closePanel() {
    this.height = CLOSED_HEIGHT;
    this.width = 0;
    this.docked = true;
    this.place();
  }

  resetPanelPosition() {
    this.docked = true;
    this.dragPosition = { x: this.returnPosition.x, y: this.returnPosition.y };
  }

  @HostListener("window:resize")
  onWindowResize(): void {
    if (!this.docked) {
      this.dragPosition = this.clamp(this.dragPosition);
    }
  }

  /** Where the drag offset puts a panel of `height` flush with the canvas's bottom-left corner. */
  dockedPosition(height: number): { x: number; y: number } {
    return { x: 0, y: NATURAL_TOP_OFFSET - height };
  }

  /** After a size change: a docked panel re-docks, a dragged one is pulled back inside the canvas. */
  private place(): void {
    this.returnPosition = this.dockedPosition(this.height);
    this.dragPosition = this.docked ? { ...this.returnPosition } : this.clamp(this.dragPosition);
  }

  /** Keeps the whole panel inside the canvas, so no window size or old position can hide it. */
  clamp(position: { x: number; y: number }): { x: number; y: number } {
    const canvas = document.querySelector("texera-workspace")?.getBoundingClientRect();
    if (!canvas || canvas.height === 0) {
      return position;
    }
    const minY = NATURAL_TOP_OFFSET - canvas.height;
    const maxY = NATURAL_TOP_OFFSET - this.height;
    const maxX = Math.max(0, canvas.width - this.width);
    return {
      x: Math.min(Math.max(position.x, 0), maxX),
      y: Math.min(Math.max(position.y, minY), Math.max(minY, maxY)),
    };
  }

  isPanelDocked() {
    return this.returnPosition.x === this.dragPosition.x && this.returnPosition.y === this.dragPosition.y;
  }

  handleStartDrag() {
    let visualizationResult = this.componentOutlets.nativeElement.querySelector("#html-content");
    if (visualizationResult !== null) {
      visualizationResult.style.zIndex = -1;
    }
  }

  handleEndDrag({ source }: CdkDragEnd) {
    /**
     * records the most recent panel location, updating dragPosition when dragging is over
     */
    const { x, y } = source.getFreeDragPosition();
    this.dragPosition = { x: x, y: y };
    this.docked = this.isPanelDocked();
    let visualizationResult = this.componentOutlets.nativeElement.querySelector("#html-content");
    if (visualizationResult !== null) {
      visualizationResult.style.zIndex = 0;
    }
  }

  onResize({ width, height }: NzResizeEvent) {
    cancelAnimationFrame(this.id);
    this.updateReturnPosition(this.height, height);
    if (this.docked) {
      this.dragPosition = { ...this.returnPosition };
    }
    this.id = requestAnimationFrame(() => {
      this.width = width!;
      this.height = height!;
      this.resizeService.changePanelSize(this.width, this.height);
    });
  }

  updateReturnPosition(prevHeight: number, newHeight: number | undefined) {
    /**
     * Updating returnPosition ensures that even if the panel gets resized,it can be docked correctly to the left-bottom corner of the canvas.
     */
    if (!isDefined(newHeight)) return;
    this.returnPosition = { x: this.returnPosition.x, y: this.returnPosition.y + prevHeight - newHeight };
  }
}
