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

import { ChangeDetectorRef, Component, OnInit, NgZone, TemplateRef, ViewChild } from "@angular/core";
import { Subscription, interval } from "rxjs";
import { filter, switchMap, take } from "rxjs/operators";
import { WorkflowWebsocketService } from "../../service/workflow-websocket/workflow-websocket.service";
import { WorkflowComputingUnitManagingService } from "../../../common/service/computing-unit/workflow-computing-unit/workflow-computing-unit-managing.service";
import {
  DashboardWorkflowComputingUnit,
  WorkflowComputingUnitType,
} from "../../../common/type/workflow-computing-unit";
import { NotificationService } from "../../../common/service/notification/notification.service";
import { DEFAULT_WORKFLOW, WorkflowActionService } from "../../service/workflow-graph/model/workflow-action.service";
import { isDefined } from "../../../common/util/predicate";
import { UntilDestroy, untilDestroyed } from "@ngneat/until-destroy";
import { extractErrorMessage } from "../../../common/util/error";
import { ComputingUnitStatusService } from "../../../common/service/computing-unit/computing-unit-status/computing-unit-status.service";
import { NzModalService, NzModalComponent, NzModalContentDirective } from "ng-zorro-antd/modal";
import { WorkflowExecutionsService } from "../../../dashboard/service/user/workflow-executions/workflow-executions.service";
import { WorkflowExecutionsEntry } from "../../../dashboard/type/workflow-executions-entry";
import { ExecutionState } from "../../types/execute-workflow.interface";
import { ShareAccessComponent } from "../../../dashboard/component/user/share-access/share-access.component";
import { GuiConfigService } from "../../../common/service/gui-config.service";
import { ComputingUnitActionsService } from "../../../common/service/computing-unit/computing-unit-actions/computing-unit-actions.service";
import {
  ComputingUnitMetadataComponent,
  parseResourceUnit,
  parseResourceNumber,
  findNearestValidStep,
  unitTypeMessageTemplate,
  cpuResourceConversion,
  memoryResourceConversion,
  cpuPercentage,
  memoryPercentage,
  validateName,
  getComputingUnitBadgeColor,
  getComputingUnitStatusTooltip,
  getComputingUnitCpuStatus,
  getComputingUnitMemoryStatus,
  getComputingUnitCpuLimitUnit,
  isComputingUnitShmTooLarge,
  getJvmMemorySliderConfig,
  computingUnitTypeLabel,
  isComputingUnitTypeSelectable,
  creationPhaseLabel,
} from "../../../common/util/computing-unit.util";
import { PvePackageResponse, WorkflowPveService } from "../../service/virtual-environment/virtual-environment.service";
import { NgClass, NgIf, NgFor, DecimalPipe, TitleCasePipe } from "@angular/common";
import { ɵNzTransitionPatchDirective } from "ng-zorro-antd/core/transition-patch";
import { NzPopoverDirective } from "ng-zorro-antd/popover";
import { NzProgressComponent } from "ng-zorro-antd/progress";
import { NzSpaceCompactItemDirective } from "ng-zorro-antd/space";
import { NzButtonComponent } from "ng-zorro-antd/button";
import { NzWaveDirective } from "ng-zorro-antd/core/wave";
import { NzDropdownDirective, NzDropdownMenuComponent } from "ng-zorro-antd/dropdown";
import { UserAvatarComponent } from "../../../dashboard/component/user/user-avatar/user-avatar.component";
import { NzBadgeComponent } from "ng-zorro-antd/badge";
import { NzTooltipDirective } from "ng-zorro-antd/tooltip";
import { NzIconDirective } from "ng-zorro-antd/icon";
import { NzMenuDirective, NzMenuItemComponent, NzMenuDividerDirective } from "ng-zorro-antd/menu";
import { NzInputDirective } from "ng-zorro-antd/input";
import { NzSelectComponent, NzOptionComponent } from "ng-zorro-antd/select";
import { FormsModule } from "@angular/forms";
import { NzSliderComponent } from "ng-zorro-antd/slider";
import { NzAlertComponent } from "ng-zorro-antd/alert";
import { NzCollapseComponent, NzCollapsePanelComponent } from "ng-zorro-antd/collapse";
import { NzStepsComponent, NzStepComponent } from "ng-zorro-antd/steps";

type PveUserPackageRow = {
  name: string;
  versionOp?: "==" | ">=" | "<=";
  version?: string;
  deleteToggle?: boolean;
};

type PveDraft = {
  name: string;
  userPackages: PveUserPackageRow[];
  newPackages: PveUserPackageRow[];
  deletingPackages: { name: string; version: string }[];
  pipOutput: string;
  prettyPipOutput: string;
  expanded: boolean;
  socket?: WebSocket;
  isInstalling: boolean;
  isLocked: boolean;
};

@UntilDestroy()
@Component({
  selector: "texera-computing-unit-selection",
  templateUrl: "./computing-unit-selection.component.html",
  styleUrls: ["./computing-unit-selection.component.scss"],
  imports: [
    NgClass,
    NgIf,
    ɵNzTransitionPatchDirective,
    NzPopoverDirective,
    NzProgressComponent,
    NzSpaceCompactItemDirective,
    NzButtonComponent,
    NzWaveDirective,
    NzDropdownDirective,
    UserAvatarComponent,
    NzBadgeComponent,
    NzTooltipDirective,
    NzIconDirective,
    NzDropdownMenuComponent,
    NzMenuDirective,
    NgFor,
    NzMenuItemComponent,
    NzInputDirective,
    NzMenuDividerDirective,
    NzModalComponent,
    NzSelectComponent,
    FormsModule,
    NzOptionComponent,
    NzSliderComponent,
    NzAlertComponent,
    NzModalContentDirective,
    NzCollapseComponent,
    NzCollapsePanelComponent,
    NzStepsComponent,
    NzStepComponent,
    DecimalPipe,
    TitleCasePipe,
  ],
})
export class ComputingUnitSelectionComponent implements OnInit {
  @ViewChild("awsTerminateContent", { static: true }) awsTerminateContent!: TemplateRef<void>;

  // variables for creating a virtual environment
  pves: PveDraft[] = [];
  systemPackages: { name: string; version: string }[] = [];
  pveModalVisible = false;

  // current workflow's Id, will change with wid in the workflowActionService.metadata
  protected readonly unitTypeMessageTemplate = unitTypeMessageTemplate;
  protected readonly computingUnitTypeLabel = computingUnitTypeLabel;
  protected readonly isComputingUnitTypeSelectable = isComputingUnitTypeSelectable;
  protected readonly creationPhaseLabel = creationPhaseLabel;
  workflowId: number | undefined;

  lastSelectedCuid?: number;
  selectedComputingUnit: DashboardWorkflowComputingUnit | null = null;
  allComputingUnits: DashboardWorkflowComputingUnit[] = [];

  // variables for creating a computing unit
  addComputeUnitModalVisible = false;
  // ── progressive creation state shown inside the modal after "Create" ──
  // The full ordered phase list the UI walks through. The first 6 phases
  // come from the backend's /creation-status endpoint; "Connected" is set
  // by the frontend once the workflow WebSocket to the new CU is open.
  readonly creationPhases = [
    "Submitted",
    "Scheduling",
    "Pulling",
    "Starting",
    "Initializing",
    "Ready",
    "Connected",
  ];
  creationInProgress = false;
  creationFailed = false;
  creationCurrentPhase: string = "Submitted";
  creationCurrentMessage: string = "";
  creationCreatedCuid?: number;
  private creationPollSubscription?: Subscription;
  private creationWsSubscription?: Subscription;
  newComputingUnitName: string = "";
  selectedMemory: string = "";
  selectedCpu: string = "";
  selectedGpu: string = "0"; // Default to no GPU
  selectedJvmMemorySize: string = "1G"; // Initial JVM memory size
  selectedComputingUnitType?: WorkflowComputingUnitType; // Selected computing unit type
  selectedShmSize: string = "64Mi"; // Shared memory size
  shmSizeValue: number = 64; // default to 64
  shmSizeUnit: "Mi" | "Gi" = "Mi"; // default unit
  availableComputingUnitTypes: WorkflowComputingUnitType[] = [];
  localComputingUnitUri: string = ""; // URI for local computing unit

  // AWS-specific variables
  awsAccessKeyId: string = "";
  awsSecretAccessKey: string = "";
  awsRegion: string = "us-west-2";
  awsInstanceType: string = "t2.micro";
  awsInstanceTypeOptions: string[] = [
    "t2.micro",
    "t2.small",
    "t2.medium",
    "t2.large",
    "t2.xlarge",
    "t3.micro",
    "t3.small",
    "t3.medium",
    "t3.large",
    "t3.xlarge",
    "m5.large",
    "m5.xlarge",
  ];
  awsRegionOptions: string[] = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
  ];

  // variables for renaming a computing unit
  editingNameOfUnit: number | null = null;
  editingUnitName: string = "";

  // JVM memory slider configuration
  jvmMemorySliderValue: number = 1; // Initial value in GB
  jvmMemoryMarks: { [key: number]: string } = { 1: "1G" };
  jvmMemoryMax: number = 1;
  jvmMemorySteps: number[] = [1]; // Available steps in binary progression (1,2,4,8...)
  showJvmMemorySlider: boolean = false; // Whether to show the slider

  // cpu&memory limit options from backend
  cpuOptions: string[] = [];
  memoryOptions: string[] = [];
  gpuOptions: string[] = []; // Add GPU options array

  constructor(
    private computingUnitService: WorkflowComputingUnitManagingService,
    private notificationService: NotificationService,
    protected config: GuiConfigService,
    private workflowActionService: WorkflowActionService,
    private computingUnitStatusService: ComputingUnitStatusService,
    private workflowExecutionsService: WorkflowExecutionsService,
    private modalService: NzModalService,
    private cdr: ChangeDetectorRef,
    private computingUnitActionsService: ComputingUnitActionsService,
    private workflowWebsocketService: WorkflowWebsocketService,
    private workflowPveService: WorkflowPveService,
    private ngZone: NgZone
  ) {}

  ngOnInit(): void {
    // Fetch available computing unit types
    this.localComputingUnitUri = `${window.location.protocol}//${window.location.hostname}${window.location.port ? `:${window.location.port}` : ""}/wsapi`;
    this.newComputingUnitName = "My Computing Unit";
    this.computingUnitService
      .getComputingUnitTypes()
      .pipe(untilDestroyed(this))
      .subscribe({
        next: ({ typeOptions }) => {
          this.availableComputingUnitTypes = typeOptions;
          // Set default selected type if available
          if (typeOptions.includes("kubernetes")) {
            this.selectedComputingUnitType = "kubernetes";
          } else if (typeOptions.length > 0) {
            this.selectedComputingUnitType = typeOptions[0];
          }
        },
        error: (err: unknown) =>
          this.notificationService.error(`Failed to fetch computing unit types: ${extractErrorMessage(err)}`),
      });

    this.computingUnitService
      .getComputingUnitLimitOptions()
      .pipe(untilDestroyed(this))
      .subscribe({
        next: ({ cpuLimitOptions, memoryLimitOptions, gpuLimitOptions }) => {
          this.cpuOptions = cpuLimitOptions;
          this.memoryOptions = memoryLimitOptions;
          this.gpuOptions = gpuLimitOptions;

          // fallback defaults
          this.selectedCpu = this.cpuOptions[0] ?? "1";
          this.selectedMemory = this.memoryOptions[0] ?? "1Gi";
          this.selectedGpu = this.gpuOptions[0] ?? "0";

          // Initialize JVM memory slider based on selected memory
          this.updateJvmMemorySlider();
        },
        error: (err: unknown) =>
          this.notificationService.error(`Failed to fetch resource options: ${extractErrorMessage(err)}`),
      });

    // Subscribe to the current selected unit from the status service
    this.computingUnitStatusService
      .getSelectedComputingUnit()
      .pipe(untilDestroyed(this))
      .subscribe(unit => {
        const wid = this.workflowActionService.getWorkflowMetadata()?.wid;

        // ── compare with the *previous* cuid, not the one we are just about to store ──
        if (isDefined(wid) && unit?.computingUnit.cuid !== this.lastSelectedCuid) {
          this.updateWorkflowModificationStatus(wid);
        }

        // update local caches **after** the comparison
        this.lastSelectedCuid = unit?.computingUnit.cuid;
        this.selectedComputingUnit = unit;
      });

    this.computingUnitStatusService
      .getAllComputingUnits()
      .pipe(untilDestroyed(this))
      .subscribe(units => {
        this.allComputingUnits = units;
      });

    this.registerWorkflowMetadataSubscription();
  }

  /**
   * Helper to query backend and (de)activate modification status.
   */
  private updateWorkflowModificationStatus(wid: number): void {
    this.workflowExecutionsService
      .retrieveWorkflowExecutions(wid, [ExecutionState.Running, ExecutionState.Initializing])
      .pipe(take(1), untilDestroyed(this))
      .subscribe(execList => {
        if (execList.length > 0) {
          this.notificationService.info(
            "There are ongoing executions on this workflow. Modification of the workflow is currently disabled."
          );
          this.workflowActionService.disableWorkflowModification();
        } else {
          this.workflowActionService.enableWorkflowModification();
        }
      });
  }

  /**
   * utility function used for displaying the computing unit
   */
  public trackByCuid(_idx: number, unit: DashboardWorkflowComputingUnit): number {
    return unit.computingUnit.cuid;
  }

  /**
   * Registers a subscription to listen for workflow metadata changes;
   * Calls `selectComputingUnit` when the `wid` changes;
   * The wid can change by time because of the workspace rendering;
   */
  private registerWorkflowMetadataSubscription(): void {
    this.workflowActionService
      .workflowMetaDataChanged()
      .pipe(untilDestroyed(this))
      .subscribe(() => {
        const wid = this.workflowActionService.getWorkflowMetadata()?.wid;
        if (wid !== this.workflowId) {
          this.workflowId = wid;
          if (isDefined(this.workflowId) && this.workflowId !== DEFAULT_WORKFLOW.wid) {
            this.workflowExecutionsService
              .retrieveLatestWorkflowExecution(this.workflowId)
              .pipe(untilDestroyed(this))
              .subscribe({
                next: (latestWorkflowExecution: WorkflowExecutionsEntry) => {
                  this.selectComputingUnit(this.workflowId, latestWorkflowExecution.cuId);
                },
                error: (err: unknown) => {
                  const runningUnit = this.allComputingUnits.find(unit => unit.status === "Running");
                  if (runningUnit) {
                    this.selectComputingUnit(this.workflowId, runningUnit.computingUnit.cuid);
                  }
                },
              });
          }
        }
      });
  }

  /**
   * Called whenever the selected computing unit changes.
   */
  selectComputingUnit(wid: number | undefined, cuid: number | undefined): void {
    if (isDefined(cuid) && wid !== DEFAULT_WORKFLOW.wid) {
      this.computingUnitStatusService.selectComputingUnit(wid, cuid);
    }
  }

  isComputingUnitRunning(): boolean {
    return this.selectedComputingUnit != null && this.selectedComputingUnit.status === "Running";
  }

  getButtonText(): string {
    if (!this.selectedComputingUnit) {
      return "Connect";
    } else {
      return this.selectedComputingUnit.computingUnit.name;
    }
  }

  computeStatus(): string {
    if (!this.selectedComputingUnit) {
      return "processing";
    }

    const status = this.selectedComputingUnit.status;
    if (status === "Running") {
      return "success";
    } else if (status === "Pending" || status === "Terminating") {
      return "warning";
    } else {
      return "error";
    }
  }

  /**
   * Determines if a unit cannot be selected (disabled in the dropdown)
   */
  cannotSelectUnit(unit: DashboardWorkflowComputingUnit): boolean {
    // Only allow selecting units that are in the Running state
    return unit.status !== "Running";
  }

  isSelectedUnit(unit: DashboardWorkflowComputingUnit): boolean {
    return unit.computingUnit.uri === this.selectedComputingUnit?.computingUnit.uri;
  }

  // Determines if the GPU selection dropdown should be shown
  showGpuSelection(): boolean {
    // Don't show GPU selection if there are no options or only "0" option
    return this.gpuOptions.length > 1 || (this.gpuOptions.length === 1 && this.gpuOptions[0] !== "0");
  }

  showAddComputeUnitModalVisible(): void {
    this.resetCreationProgress();
    this.addComputeUnitModalVisible = true;
  }

  handleAddComputeUnitModalOk(): void {
    // Stay open and switch to the progress view; startComputingUnit() handles
    // closing once the WebSocket to the new CU is connected (or on error).
    this.startComputingUnit();
  }

  handleAddComputeUnitModalCancel(): void {
    // Cancel during creation only dismisses the modal — the CU keeps coming
    // up in the background and shows up in the dashboard list when ready.
    this.creationPollSubscription?.unsubscribe();
    this.creationWsSubscription?.unsubscribe();
    this.addComputeUnitModalVisible = false;
  }

  private resetCreationProgress(): void {
    this.creationInProgress = false;
    this.creationFailed = false;
    this.creationCurrentPhase = "Submitted";
    this.creationCurrentMessage = "";
    this.creationCreatedCuid = undefined;
    this.creationPollSubscription?.unsubscribe();
    this.creationWsSubscription?.unsubscribe();
  }

  // True for phases that are at or before the currently active phase, used
  // by the template to mark step bullets in nz-steps as completed/active.
  isPhaseReached(phase: string): boolean {
    const currentIdx = this.creationPhases.indexOf(this.creationCurrentPhase);
    const phaseIdx = this.creationPhases.indexOf(phase);
    return phaseIdx >= 0 && currentIdx >= phaseIdx;
  }

  creationProgressPercent(): number {
    const idx = this.creationPhases.indexOf(this.creationCurrentPhase);
    if (idx < 0) return 0;
    return Math.round(((idx + 1) / this.creationPhases.length) * 100);
  }

  isShmTooLarge(): boolean {
    return isComputingUnitShmTooLarge(this.selectedMemory, this.shmSizeValue, this.shmSizeUnit);
  }

  /**
   * Start a new computing unit.
   */
  startComputingUnit(): void {
    if (!this.selectedComputingUnitType) {
      this.notificationService.error("Please select a valid computing unit type");
      return;
    }

    if (this.selectedComputingUnitType === "kubernetes" && this.newComputingUnitName.trim() === "") {
      this.notificationService.error("Name of the computing unit cannot be empty");
      return;
    }

    if (this.selectedComputingUnitType === "local" && this.localComputingUnitUri.trim() === "") {
      this.notificationService.error("URI for local computing unit cannot be empty");
      return;
    }

    if (this.selectedComputingUnitType === "aws") {
      if (this.newComputingUnitName.trim() === "") {
        this.notificationService.error("Name of the computing unit cannot be empty");
        return;
      }
      if (!this.awsAccessKeyId || this.awsAccessKeyId.trim() === "") {
        this.notificationService.error("AWS Access Key ID cannot be empty");
        return;
      }
      if (!this.awsSecretAccessKey || this.awsSecretAccessKey.trim() === "") {
        this.notificationService.error("AWS Secret Access Key cannot be empty");
        return;
      }

      this.computingUnitService
        .createAwsComputingUnit(
          this.newComputingUnitName,
          this.awsAccessKeyId,
          this.awsSecretAccessKey,
          this.awsRegion,
          this.awsInstanceType
        )
        .pipe(untilDestroyed(this))
        .subscribe({
          next: (unit: DashboardWorkflowComputingUnit) => {
            this.notificationService.success("Successfully created the new AWS EC2 compute unit");
            this.selectComputingUnit(this.workflowId, unit.computingUnit.cuid);
            // Clear credentials from memory after creation
            this.awsAccessKeyId = "";
            this.awsSecretAccessKey = "";
          },
          error: (err: unknown) =>
            this.notificationService.error(`Failed to create AWS EC2 computing unit: ${extractErrorMessage(err)}`),
        });
      return;
    }

    const request = {
      type: this.selectedComputingUnitType,
      name: this.newComputingUnitName,
      cpu: this.selectedCpu,
      memory: this.selectedMemory,
      gpu: this.selectedGpu,
      jvmMemorySize: this.selectedJvmMemorySize,
      shmSize: `${this.shmSizeValue}${this.shmSizeUnit}`,
      localUri: this.localComputingUnitUri,
    };

    this.creationInProgress = true;
    this.creationFailed = false;
    this.creationCurrentPhase = "Submitted";
    this.creationCurrentMessage = "Submitting request to the manager…";

    this.computingUnitActionsService
      .create(request)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: (unit: DashboardWorkflowComputingUnit) => {
          this.creationCreatedCuid = unit.computingUnit.cuid;
          this.startCreationProgressTracking(unit);
        },
        error: (err: unknown) => {
          this.creationFailed = true;
          this.creationCurrentMessage = extractErrorMessage(err);
          this.notificationService.error(`Failed to start computing unit: ${extractErrorMessage(err)}`);
        },
      });
  }

  /**
   * Drives the progressive modal once the manager has accepted the create
   * request. Polls /creation-status every second until phase==Ready, then
   * triggers selectComputingUnit (which opens the workflow WebSocket) and
   * waits for the WS to connect before marking "Connected" and closing the
   * modal. Errors from any step surface as a "Failed" phase.
   */
  private startCreationProgressTracking(unit: DashboardWorkflowComputingUnit): void {
    const cuid = unit.computingUnit.cuid;

    this.creationPollSubscription = interval(1000)
      .pipe(
        switchMap(() => this.computingUnitService.getCreationStatus(cuid)),
        untilDestroyed(this)
      )
      .subscribe({
        next: ({ phase, message }) => {
          this.creationCurrentPhase = phase;
          this.creationCurrentMessage = message ?? "";
          if (phase === "Failed") {
            this.creationFailed = true;
            this.creationPollSubscription?.unsubscribe();
            return;
          }
          if (phase === "Ready") {
            this.creationPollSubscription?.unsubscribe();
            this.selectComputingUnit(this.workflowId, cuid);
            this.waitForWebsocketConnection(cuid);
          }
        },
        error: (err: unknown) => {
          // Transient backend errors during polling — keep the user informed
          // but don't tear down the flow; next tick may recover.
          this.creationCurrentMessage = `Status check failed: ${extractErrorMessage(err)}`;
        },
      });
  }

  private waitForWebsocketConnection(cuid: number): void {
    // Step the UI through "Connected" once the workflow WS is up. We close
    // the modal a beat later so the user sees the full progress complete.
    this.creationWsSubscription = this.workflowWebsocketService
      .getConnectionStatusStream()
      .pipe(
        filter(connected => connected),
        take(1),
        untilDestroyed(this)
      )
      .subscribe(() => {
        this.creationCurrentPhase = "Connected";
        this.creationCurrentMessage = "Connected to the new computing unit";
        setTimeout(() => {
          this.notificationService.success("Successfully created the new compute unit");
          this.addComputeUnitModalVisible = false;
          this.creationInProgress = false;
        }, 600);
      });
  }

  openComputingUnitMetadataModal(unit: DashboardWorkflowComputingUnit) {
    this.modalService.create({
      nzTitle: "Computing Unit Information",
      nzContent: ComputingUnitMetadataComponent,
      nzData: unit,
      nzFooter: null,
      nzMaskClosable: true,
      nzWidth: "600px",
    });
  }

  /**
   * Terminate a computing unit.
   * @param cuid The CUID of the unit to terminate.
   */
  // AWS credentials for terminate flow (bound to template)
  terminateAwsAccessKeyId: string = "";
  terminateAwsSecretAccessKey: string = "";
  awsTerminateUnitName: string = "";

  terminateComputingUnit(cuid: number): void {
    const unit = this.allComputingUnits.find(u => u.computingUnit.cuid === cuid);

    if (!unit) {
      this.notificationService.error("Invalid computing unit.");
      return;
    }

    // For AWS units, show a credentials prompt modal first (template lives in this component)
    if (unit.computingUnit.type === "aws") {
      const unitName = unit.computingUnit.name;
      const templates = this.unitTypeMessageTemplate.aws;
      this.terminateAwsAccessKeyId = "";
      this.terminateAwsSecretAccessKey = "";
      this.awsTerminateUnitName = unitName;
      this.modalService.confirm({
        nzTitle: templates.terminateTitle,
        nzContent: this.awsTerminateContent,
        nzOkText: "Terminate",
        nzOkType: "primary",
        nzOnOk: () => {
          if (!this.terminateAwsAccessKeyId.trim() || !this.terminateAwsSecretAccessKey.trim()) {
            this.notificationService.error("AWS credentials are required to terminate an AWS computing unit");
            return false; // keep modal open
          }

          this.computingUnitStatusService
            .terminateComputingUnit(cuid, this.terminateAwsAccessKeyId, this.terminateAwsSecretAccessKey)
            .pipe(untilDestroyed(this))
            .subscribe({
              next: (success: boolean) => {
                if (success) {
                  this.notificationService.success(`Terminated Computing Unit: ${unitName}`);
                } else {
                  this.notificationService.error("Failed to terminate computing unit");
                }
              },
              error: (err: unknown) => {
                this.notificationService.error(`Failed to terminate computing unit: ${extractErrorMessage(err)}`);
              },
            });
          return true;
        },
        nzCancelText: "Cancel",
      });
      return;
    }

    this.computingUnitActionsService.confirmAndTerminate(cuid, unit);

    if (this.selectedComputingUnit?.computingUnit.type === "local") {
      this.workflowPveService
        .deleteEnvironments(cuid)
        .pipe(untilDestroyed(this))
        .subscribe({
          error: (err: unknown) => {
            console.error("Failed to delete PVE environments", err);
          },
        });
    }
  }

  /**
   * Start editing the name of a computing unit.
   */
  startEditingUnitName(unit: DashboardWorkflowComputingUnit): void {
    if (!unit.isOwner) {
      this.notificationService.error("Only owners can rename computing units");
      return;
    }

    this.editingNameOfUnit = unit.computingUnit.cuid;
    this.editingUnitName = unit.computingUnit.name;

    // Force change detection and focus the input
    this.cdr.detectChanges();
    setTimeout(() => {
      const input = document.querySelector(".unit-name-edit-input") as HTMLInputElement;
      if (input) {
        input.focus();
        input.select();
      }
    }, 0);
  }

  /**
   * Confirm the new name and update the computing unit.
   */
  confirmUpdateUnitName(cuid: number, newName: string): void {
    const trimmedName = newName.trim();

    const validationError = validateName(trimmedName);
    if (validationError) {
      this.notificationService.error(validationError);
      this.cancelEditingUnitName();
      return;
    }

    this.computingUnitService
      .renameComputingUnit(cuid, trimmedName)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: () => {
          this.notificationService.success("Successfully renamed computing unit");
          // Update the local unit name immediately for better UX
          const unit = this.allComputingUnits.find(u => u.computingUnit.cuid === cuid);
          if (unit) {
            unit.computingUnit.name = trimmedName;
          }
          // Also update the selected unit if it's the one being renamed
          if (this.selectedComputingUnit?.computingUnit.cuid === cuid) {
            this.selectedComputingUnit.computingUnit.name = trimmedName;
          }
          // Refresh the computing units list
          this.computingUnitStatusService.refreshComputingUnitList();
        },
        error: (err: unknown) => {
          this.notificationService.error(`Failed to rename computing unit: ${extractErrorMessage(err)}`);
        },
      })
      .add(() => {
        this.editingNameOfUnit = null;
        this.editingUnitName = "";
      });
  }

  /**
   * Cancel editing the computing unit name.
   */
  cancelEditingUnitName(): void {
    this.editingNameOfUnit = null;
    this.editingUnitName = "";
  }

  getCurrentComputingUnitCpuUsage(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.metrics.cpuUsage : "NaN";
  }

  getCurrentComputingUnitMemoryUsage(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.metrics.memoryUsage : "NaN";
  }

  getCurrentComputingUnitCpuLimit(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.computingUnit.resource.cpuLimit : "NaN";
  }

  getCurrentComputingUnitMemoryLimit(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.computingUnit.resource.memoryLimit : "NaN";
  }

  getCurrentComputingUnitGpuLimit(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.computingUnit.resource.gpuLimit : "NaN";
  }

  getCurrentComputingUnitJvmMemorySize(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.computingUnit.resource.jvmMemorySize : "NaN";
  }

  getCurrentSharedMemorySize(): string {
    return this.selectedComputingUnit ? this.selectedComputingUnit.computingUnit.resource.shmSize : "NaN";
  }

  /**
   * Returns the badge color based on computing unit status
   */
  getBadgeColor(status: string): string {
    return getComputingUnitBadgeColor(status);
  }

  getCpuLimit(): number {
    return parseResourceNumber(this.getCurrentComputingUnitCpuLimit());
  }

  getGpuLimit(): string {
    return this.getCurrentComputingUnitGpuLimit();
  }

  getJvmMemorySize(): string {
    return this.getCurrentComputingUnitJvmMemorySize();
  }

  getSharedMemorySize(): string {
    return this.getCurrentSharedMemorySize();
  }

  getCpuLimitUnit(): string {
    return getComputingUnitCpuLimitUnit(parseResourceUnit(this.getCurrentComputingUnitCpuLimit()));
  }

  getMemoryLimit(): number {
    return parseResourceNumber(this.getCurrentComputingUnitMemoryLimit());
  }

  getMemoryLimitUnit(): string {
    return parseResourceUnit(this.getCurrentComputingUnitMemoryLimit());
  }

  getCpuValue(): number {
    const usage = this.getCurrentComputingUnitCpuUsage();
    const limit = this.getCurrentComputingUnitCpuLimit();
    if (usage === "N/A" || limit === "N/A") return 0;
    const displayUnit = this.getCpuLimitUnit() === "CPU" ? "" : this.getCpuLimitUnit();
    const usageValue = cpuResourceConversion(usage, displayUnit);
    return parseFloat(usageValue);
  }

  getMemoryValue(): number {
    const usage = this.getCurrentComputingUnitMemoryUsage();
    const limit = this.getCurrentComputingUnitMemoryLimit();
    if (usage === "N/A" || limit === "N/A") return 0;
    const displayUnit = this.getMemoryLimitUnit();
    const usageValue = memoryResourceConversion(usage, displayUnit);
    return parseFloat(usageValue);
  }

  getCpuPercentage(): number {
    return cpuPercentage(this.getCurrentComputingUnitCpuUsage(), this.getCurrentComputingUnitCpuLimit());
  }

  getMemoryPercentage(): number {
    return memoryPercentage(this.getCurrentComputingUnitMemoryUsage(), this.getCurrentComputingUnitMemoryLimit());
  }

  getCpuStatus(): "success" | "exception" | "active" | "normal" {
    return getComputingUnitCpuStatus(this.getCpuPercentage());
  }

  getMemoryStatus(): "success" | "exception" | "active" | "normal" {
    return getComputingUnitMemoryStatus(this.getMemoryPercentage());
  }

  getCpuUnit(): string {
    return this.getCpuLimitUnit() === "CPU" ? "Cores" : this.getCpuLimitUnit();
  }

  getMemoryUnit(): string {
    return this.getMemoryLimitUnit() === "" ? "B" : this.getMemoryLimitUnit();
  }

  /**
   * Returns a descriptive tooltip for a specific unit's status
   */
  getUnitStatusTooltip(unit: DashboardWorkflowComputingUnit): string {
    return getComputingUnitStatusTooltip(unit);
  }

  // Called when the component initializes
  updateJvmMemorySlider(): void {
    this.resetJvmMemorySlider();
  }

  onJvmMemorySliderChange(value: number): void {
    // Ensure the value is one of the valid steps
    const validStep = findNearestValidStep(value, this.jvmMemorySteps);
    this.jvmMemorySliderValue = validStep;
    this.selectedJvmMemorySize = `${validStep}G`;
  }

  // Check if the maximum JVM memory value is selected
  isMaxJvmMemorySelected(): boolean {
    // Only show warning for larger memory sizes (>=4GB) where the slider is shown
    // AND when the maximum value is selected
    return this.showJvmMemorySlider && this.jvmMemorySliderValue === this.jvmMemoryMax && this.jvmMemoryMax >= 4;
  }

  // Completely reset the JVM memory slider based on the selected CU memory
  resetJvmMemorySlider(): void {
    const config = getJvmMemorySliderConfig(this.selectedMemory);

    this.jvmMemoryMax = config.jvmMemoryMax;
    this.showJvmMemorySlider = config.showJvmMemorySlider;
    this.jvmMemorySteps = config.jvmMemorySteps;
    this.jvmMemoryMarks = config.jvmMemoryMarks;
    this.jvmMemorySliderValue = config.jvmMemorySliderValue;
    this.selectedJvmMemorySize = config.selectedJvmMemorySize;
  }

  // Listen for memory selection changes
  onMemorySelectionChange(): void {
    // Store current JVM memory value for potential reuse
    const previousJvmMemory = this.jvmMemorySliderValue;

    // Reset slider configuration based on the new memory selection
    this.resetJvmMemorySlider();

    // For CU memory > 3GB, preserve previous value if valid and >= 2GB
    // Get the current memory in GB
    const memoryValue = parseResourceNumber(this.selectedMemory);
    const memoryUnit = parseResourceUnit(this.selectedMemory);
    let cuMemoryInGb = memoryUnit === "Gi" ? memoryValue : memoryUnit === "Mi" ? Math.floor(memoryValue / 1024) : 1;

    // Only try to preserve previous value for larger memory sizes where slider is shown
    if (
      cuMemoryInGb > 3 &&
      previousJvmMemory >= 2 &&
      previousJvmMemory <= this.jvmMemoryMax &&
      this.jvmMemorySteps.includes(previousJvmMemory)
    ) {
      this.jvmMemorySliderValue = previousJvmMemory;
      this.selectedJvmMemorySize = `${previousJvmMemory}G`;
    }
  }

  getCreateModalTitle(): string {
    if (!this.selectedComputingUnitType) return "Create Computing Unit";
    return unitTypeMessageTemplate[this.selectedComputingUnitType].createTitle;
  }

  public async onClickOpenShareAccess(cuid: number): Promise<void> {
    this.computingUnitActionsService.openShareAccessModal(cuid, true);
  }

  onDropdownVisibilityChange(visible: boolean): void {
    if (visible) {
      this.computingUnitStatusService.refreshComputingUnitList();
    }
  }

  trackByIndex(index: number): number {
    return index;
  }

  addPackage(index: number): void {
    const env = this.pves[index];
    env.newPackages.push({ name: "", version: "", versionOp: undefined, deleteToggle: false });
  }

  togglePackageDelete(index: number, pkg: PveUserPackageRow): void {
    const env = this.pves[index];

    pkg.deleteToggle = !pkg.deleteToggle;

    const version = pkg.version ?? "";

    env.deletingPackages = env.deletingPackages.filter(p => !(p.name === pkg.name && p.version === version));

    if (pkg.deleteToggle) {
      env.deletingPackages.push({ name: pkg.name, version });
    }
  }

  addEnvironment(): void {
    this.pves.push({
      name: "",
      userPackages: [],
      newPackages: [],
      deletingPackages: [],
      pipOutput: "",
      prettyPipOutput: "",
      expanded: true,
      isInstalling: false,
      isLocked: false,
    });
  }

  showPVEmodalVisible(): void {
    this.pveModalVisible = true;
    this.getPVEs();
  }

  closePveModal(): void {
    this.pves.forEach(pve => {
      pve.socket?.close();
      pve.socket = undefined;
      pve.isInstalling = false;
    });

    this.pveModalVisible = false;
  }

  getPVEs(): void {
    const cuId = this.selectedComputingUnit!.computingUnit.cuid;

    this.workflowPveService
      .fetchPVEs(cuId)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: (resp: PvePackageResponse[]) => {
          this.pves = resp.map(pve => ({
            name: pve.pveName,
            userPackages: this.parsePackageRows(pve.userPackages),
            newPackages: [],
            deletingPackages: [],
            expanded: false,
            isInstalling: false,
            pipOutput: "",
            prettyPipOutput: "",
            isLocked: true,
          }));

          this.workflowPveService
            .getSystemPackages(cuId)
            .pipe(untilDestroyed(this))
            .subscribe({
              next: installedResp => {
                this.systemPackages = installedResp.system.map(pkgStr => {
                  const [name, version] = pkgStr.split("==");
                  return {
                    name: name.trim(),
                    version: (version ?? "").trim(),
                  };
                });
              },
              error: (err: unknown) => {
                console.error("Failed to fetch system packages:", err);
                this.systemPackages = [];
              },
            });
        },
        error: (err: unknown) => {
          console.error("Failed to fetch PVEs:", err);
          this.pves = [];
          this.systemPackages = [];
        },
      });
  }

  scrollToBottomOfPipModal(index: number) {
    setTimeout(() => {
      const pre = document.getElementById(`pip-log-${index}`) as HTMLElement | null;
      if (pre) {
        pre.scrollTop = pre.scrollHeight;
      }
    }, 50);
  }

  // Converts raw pip output for UI rendering by escaping unsafe characters and
  // applying styling to exit codes, errors, warnings, and common success messages.
  updatePrettyPipOutput(index: number) {
    const env = this.pves[index];

    const escapeHtml = (s: string) =>
      s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");

    const raw = env.pipOutput ?? "";
    const safe = escapeHtml(raw);

    env.prettyPipOutput = safe
      .replace(/^(\[pip\] Successfully installed.*)$/gm, '<span class="pip-exit ok"><strong>$1</strong></span>')

      .replace(
        /^(\[(?:PVE|pip|pve)\].*finished with exit code\s+0.*)$/gm,
        '<span class="pip-exit ok"><strong>$1</strong></span>'
      )

      .replace(/^(\[PVE\] Running pip freeze.*)$/gm, '<span class="pip-exit ok"><strong>$1</strong></span>')

      .replace(/^(\[(?:PVE|pip|pve)\]\[ERR\].*)$/gm, '<span class="pip-exit err"><strong>$1</strong></span>')

      .replace(/^(\[PVE\] Skipped.*)$/gm, '<span class="pip-exit err"><strong>$1</strong></span>')

      .replace(/\n/g, "<br/>");
  }

  private runPveWebSocket(
    index: number,
    action: "create" | "install",
    initialMessage: string,
    packages: string[] = [],
    onDone?: () => void
  ): void {
    const cuId = this.selectedComputingUnit!.computingUnit.cuid;
    const env = this.pves[index];
    const trimmedName = env.name.trim();

    env.socket?.close();

    const websocketUrl = this.workflowPveService.getPveWebSocketUrl(cuId, trimmedName, action, packages);

    const socket = new WebSocket(websocketUrl);

    this.pves[index] = {
      ...env,
      name: trimmedName,
      socket,
      pipOutput: initialMessage,
      isInstalling: true,
      isLocked: true,
    };

    this.updatePrettyPipOutput(index);
    this.scrollToBottomOfPipModal(index);

    socket.onmessage = event => {
      this.ngZone.run(() => {
        const currentEnv = this.pves[index];

        if (event.data === "__DONE__") {
          this.pves[index] = {
            ...currentEnv,
            socket: undefined,
            isInstalling: false,
            isLocked: true,
          };

          socket.close();
          onDone?.();

          this.cdr.detectChanges();
          return;
        }

        this.pves[index] = {
          ...currentEnv,
          pipOutput: `${currentEnv.pipOutput ?? ""}${event.data}\n`,
        };

        this.updatePrettyPipOutput(index);
        this.scrollToBottomOfPipModal(index);
        this.cdr.detectChanges();
      });
    };

    socket.onerror = () => {
      this.ngZone.run(() => {
        const currentEnv = this.pves[index];

        this.pves[index] = {
          ...currentEnv,
          pipOutput: `${currentEnv.pipOutput ?? ""}\n[WebSocket error]\n`,
          socket: undefined,
          isInstalling: false,
          isLocked: true,
        };

        socket.close();
        this.updatePrettyPipOutput(index);
        this.cdr.detectChanges();
      });
    };
  }

  private refreshUserPackages(index: number): void {
    const env = this.pves[index];

    this.workflowPveService
      .getUserPackages(this.selectedComputingUnit!.computingUnit.cuid, env.name)
      .pipe(untilDestroyed(this))
      .subscribe({
        next: pkgs => {
          env.userPackages = env.userPackages = this.parsePackageRows(pkgs);
          this.cdr.detectChanges();
        },
        error: (e: unknown) => console.error("Failed to refresh user packages", e),
      });
  }

  createVirtualEnvironment(index: number): void {
    const env = this.pves[index];
    const trimmedName = env.name.trim();

    if (!/^[a-zA-Z0-9]+$/.test(trimmedName)) {
      this.notificationService.error("Environment name must contain only letters and numbers.");
      return;
    }

    if (env.isLocked) {
      this.deleteUserPackages(index, () => {
        this.installUserPackages(index);
      });
      return;
    }

    const duplicateExists = this.pves.some((pve, i) => i !== index && (pve.name ?? "").trim() === trimmedName);

    if (duplicateExists) {
      this.notificationService.error("An environment with this name already exists.");
      return;
    }

    this.runPveWebSocket(index, "create", "Creating virtual environment...\n", [], () => {
      this.deleteUserPackages(index, () => {
        this.installUserPackages(index);
      });
    });
  }

  private installUserPackages(index: number): void {
    const env = this.pves[index];

    const missingVersionPackage = env.newPackages?.find(
      pkg => pkg.name?.trim() && (!pkg.versionOp?.trim() || !pkg.version?.trim())
    );

    if (missingVersionPackage) {
      this.notificationService.error("Please specify an operator and version for each package.");
      return;
    }

    const systemPackageNames = new Set(this.systemPackages.map(pkg => pkg.name.trim().toLowerCase()));

    const userPackageNames = new Set(env.userPackages.map(pkg => pkg.name.trim().toLowerCase()));

    const skippedMessages: string[] = [];

    const packageArray =
      env.newPackages
        ?.filter(pkg => pkg.name?.trim())
        .filter(pkg => {
          const packageName = pkg.name.trim().toLowerCase();

          if (systemPackageNames.has(packageName)) {
            this.notificationService.error(`Skipped ${pkg.name}: already installed as a system package.`);
            return false;
          }

          if (userPackageNames.has(packageName)) {
            this.notificationService.error(`Skipped ${pkg.name}: already installed in this environment.`);
            return false;
          }

          return true;
        })
        .map(pkg => `${pkg.name.trim()}${pkg.versionOp}${(pkg.version ?? "").trim()}`) ?? [];

    if (skippedMessages.length > 0) {
      this.pves[index].pipOutput = `${this.pves[index].pipOutput ?? ""}` + skippedMessages.join("\n") + "\n";

      this.updatePrettyPipOutput(index);
      this.scrollToBottomOfPipModal(index);
    }

    if (packageArray.length === 0) {
      this.pves[index].newPackages = [];
      this.pves[index].isInstalling = false;
      this.refreshUserPackages(index);
      return;
    }

    this.runPveWebSocket(index, "install", "Installing user packages...\n", packageArray, () => {
      this.pves[index].newPackages = [];
      this.refreshUserPackages(index);
    });
  }

  private parsePackageRows(packages: string[]): PveUserPackageRow[] {
    return packages.map(pkgStr => {
      const [name, version] = pkgStr.split("==");
      return {
        name: name.trim(),
        versionOp: "==" as const,
        version: (version ?? "").trim(),
      };
    });
  }

  private deleteUserPackages(index: number, onDone?: () => void): void {
    const cuId = this.selectedComputingUnit!.computingUnit.cuid;
    const pveName = this.pves[index].name.trim();
    const packagesToDelete = [...this.pves[index].deletingPackages];

    if (packagesToDelete.length === 0) {
      onDone?.();
      return;
    }

    this.pves[index] = {
      ...this.pves[index],
      pipOutput: `${this.pves[index].pipOutput ?? ""}Deleting user packages...\n`,
      isInstalling: true,
    };

    let deleteIndex = 0;

    const deleteNext = (): void => {
      if (deleteIndex >= packagesToDelete.length) {
        this.pves[index].deletingPackages = [];
        this.refreshUserPackages(index);
        onDone?.();
        return;
      }

      const pkg = packagesToDelete[deleteIndex];

      this.workflowPveService
        .deletePackage(cuId, pveName, pkg.name)
        .pipe(untilDestroyed(this))
        .subscribe({
          next: messages => {
            this.pves[index].pipOutput = `${this.pves[index].pipOutput ?? ""}${messages.join("\n")}\n`;

            this.updatePrettyPipOutput(index);
            this.scrollToBottomOfPipModal(index);

            deleteIndex++;
            deleteNext();
          },
          error: () => {
            this.pves[index].pipOutput =
              `${this.pves[index].pipOutput ?? ""}[PVE][ERR] Failed to delete package: ${pkg.name}\n`;

            this.updatePrettyPipOutput(index);
            this.scrollToBottomOfPipModal(index);

            deleteIndex++;
            deleteNext();
          },
        });
    };

    deleteNext();
  }
}
