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

import { generateText, type ModelMessage, type LanguageModel, stepCountIs } from "ai";
import { WorkflowState } from "./workflow-state";
import { WorkflowSystemMetadata } from "./util/workflow-system-metadata";
import { WorkflowResultState } from "./workflow-result-state";
import { formatOperatorResult } from "./tools/result-formatting";
import type {
  AgentPersistedConfig,
  AgentSettings,
  AgentSettingsApi,
  AgentTaskContext,
  ReActStep,
  TokenUsage,
} from "../types/agent";
import {
  AgentState as AgentStateEnum,
  DEFAULT_AGENT_SETTINGS,
  DEFAULT_AGENT_NAME,
  OperatorResultSerializationMode,
  INITIAL_STEP_ID,
} from "../types/agent";
import { buildSystemPrompt } from "./prompts";
import {
  createAddOperatorTool,
  createModifyOperatorTool,
  createDeleteOperatorTool,
  TOOL_NAME_ADD_OPERATOR,
  TOOL_NAME_MODIFY_OPERATOR,
  TOOL_NAME_DELETE_OPERATOR,
  type ToolContext,
} from "./tools/workflow-crud-tools";
import {
  createGetOperatorDefinitionTool,
  createListOperatorTypesTool,
  TOOL_NAME_GET_OPERATOR_DEFINITION,
  TOOL_NAME_LIST_OPERATOR_TYPES,
} from "./tools/operator-metadata-tools";
import {
  createExecuteOperatorTool,
  executeOperatorAndFormat,
  TOOL_NAME_EXECUTE_OPERATOR,
  type ExecutionConfig,
} from "./tools/workflow-execution-tools";
import {
  createListDatasetFilesTool,
  createListDatasetsTool,
  createListDatasetVersionsTool,
  TOOL_NAME_LIST_DATASET_FILES,
  TOOL_NAME_LIST_DATASET_VERSIONS,
  TOOL_NAME_LIST_DATASETS,
  type DatasetToolConfig,
} from "./tools/dataset-tools";
import { RemoteMcpToolRegistry } from "./mcp/mcp-client-manager";
import { createRemoteMcpTools } from "./tools/mcp-remote-tools";
import { assembleContext } from "./util/context-utils";
import { windowEvents, detectRepeatedToolCalls, appendSystemNotice } from "./react-loop-guards";
import { env } from "../config/env";
import { compileWorkflowAsync, type WorkflowCompilationResponse } from "../api/compile-api";
import { persistWorkflow, retrieveWorkflow } from "../api/workflow-api";
import { createLogger } from "../logger";
import type { Logger } from "pino";

export interface TexeraAgentConfig {
  model: LanguageModel;
  modelType: string;
  agentId: string;
  agentName?: string;
  systemPrompt?: string;
  createdAt?: Date;
  persistedConfig?: AgentPersistedConfig;
  reactSteps?: ReActStep[];
}

export interface AgentMessageResult {
  response: string;
  messages: ModelMessage[];
  usage: TokenUsage;
  stopped: boolean;
  error?: string;
}

type ReActStepCallback = (step: ReActStep) => void;

/**
 * A single Texera agent instance.
 *
 * Owns the conversation (ReAct step tree with HEAD/checkout semantics), the
 * workflow being edited (`WorkflowState`), cached operator execution results
 * (`WorkflowResultState`), and the tool surface exposed to the LLM. Each call
 * to `sendMessage` drives one multi-step generation via the Vercel AI SDK,
 * streaming step updates to subscribed websockets.
 */
export class TexeraAgent {
  readonly agentId: string;
  agentName: string;
  modelType: string;
  readonly createdAt: Date;

  private state: AgentStateEnum = AgentStateEnum.AVAILABLE;
  private workflowState: WorkflowState;
  private metadataStore: WorkflowSystemMetadata;
  private mcpToolRegistry: RemoteMcpToolRegistry;
  private head: string = INITIAL_STEP_ID;
  private stepsById: Map<string, ReActStep> = new Map();
  private stepCounter = 0;
  private workflowResultState: WorkflowResultState;

  private websockets: Set<any> = new Set();

  private model: LanguageModel;
  private systemPrompt: string;
  private settings: AgentSettings;

  private reActStepsByMessageId: Map<string, ReActStep[]> = new Map();

  private currentMessageId: string | undefined = undefined;
  private currentTaskContext?: AgentTaskContext;

  private stepCallback: ReActStepCallback | null = null;

  private messageCounter = 0;

  private tools: Record<string, any>;

  private abortController: AbortController | null = null;

  private log: Logger;

  constructor(config: TexeraAgentConfig) {
    this.agentId = config.agentId;
    this.agentName = config.agentName || DEFAULT_AGENT_NAME;
    this.modelType = config.modelType;
    this.createdAt = config.createdAt ?? new Date();
    this.model = config.model;
    this.systemPrompt = config.persistedConfig?.systemPrompt || config.systemPrompt || "";
    this.log = createLogger("TexeraAgent", { agentId: this.agentId });

    this.workflowState = new WorkflowState();
    this.metadataStore = WorkflowSystemMetadata.getInstance();
    this.mcpToolRegistry = RemoteMcpToolRegistry.getInstance();
    this.workflowResultState = new WorkflowResultState(() => this.getAncestorPath());

    const initialStep: ReActStep = {
      id: INITIAL_STEP_ID,
      messageId: "initial",
      stepId: -1,
      timestamp: Date.now(),
      role: "user",
      content: "",
      isBegin: true,
      isEnd: true,
      parentId: undefined,
    };
    this.stepsById.set(INITIAL_STEP_ID, initialStep);

    this.settings = {
      ...DEFAULT_AGENT_SETTINGS,
      systemPrompt: this.systemPrompt,
    };
    // Precedence: built-in defaults < deployment env overrides < persisted per-agent config.
    this.applyEnvSettingOverrides();
    if (config.persistedConfig?.settings) {
      this.applySettingsApi(config.persistedConfig.settings);
    }

    this.tools = this.createTools();
    if (config.reactSteps && config.reactSteps.length > 0) {
      this.restoreReActSteps(config.reactSteps);
    }
  }

  // Deployment-level overrides of the hardcoded agent defaults, set via AGENT_* env vars
  // (see config/env.ts) so behavior is tunable in k8s without a rebuild.
  private applyEnvSettingOverrides(): void {
    if (env.AGENT_MAX_OPERATOR_RESULT_CHAR_LIMIT !== undefined) {
      this.settings.maxOperatorResultCharLimit = env.AGENT_MAX_OPERATOR_RESULT_CHAR_LIMIT;
    }
    if (env.AGENT_MAX_OPERATOR_RESULT_CELL_CHAR_LIMIT !== undefined) {
      this.settings.maxOperatorResultCellCharLimit = env.AGENT_MAX_OPERATOR_RESULT_CELL_CHAR_LIMIT;
    }
    if (env.AGENT_EXECUTION_TIMEOUT_MS !== undefined) {
      this.settings.executionTimeoutMs = env.AGENT_EXECUTION_TIMEOUT_MS;
    }
    if (env.AGENT_MAX_STEPS !== undefined) {
      this.settings.maxSteps = env.AGENT_MAX_STEPS;
    }
  }

  async initialize(): Promise<void> {
    try {
      if (!this.metadataStore.isInitialized()) {
        await this.metadataStore.initializeFromBackend();
      }
      await this.mcpToolRegistry.initialize();

      this.rebuildSystemPrompt();

      this.tools = this.createTools();
      this.log.info(
        {
          operatorCount: this.metadataStore.getOperatorCount(),
          remoteMcpToolCount: this.mcpToolRegistry.getTools().length,
        },
        "agent initialized"
      );
    } catch (error) {
      this.log.error({ err: error }, "failed to initialize metadata");
    }
  }

  private rebuildSystemPrompt(): void {
    this.systemPrompt = buildSystemPrompt(this.metadataStore);
    this.settings.systemPrompt = this.systemPrompt;
  }

  private applySettingsApi(settings: AgentSettingsApi): void {
    if (settings.maxOperatorResultCharLimit !== undefined) {
      this.settings.maxOperatorResultCharLimit = settings.maxOperatorResultCharLimit;
    }
    if (settings.maxOperatorResultCellCharLimit !== undefined) {
      this.settings.maxOperatorResultCellCharLimit = settings.maxOperatorResultCellCharLimit;
    }
    if (settings.operatorResultSerializationMode !== undefined) {
      this.settings.operatorResultSerializationMode =
        settings.operatorResultSerializationMode as OperatorResultSerializationMode;
    }
    if (settings.executionTimeoutMinutes !== undefined) {
      this.settings.executionTimeoutMs = settings.executionTimeoutMinutes * 60000;
    }
    if (settings.disabledTools !== undefined) {
      this.settings.disabledTools = new Set(settings.disabledTools);
    }
    if (settings.maxSteps !== undefined) {
      this.settings.maxSteps = settings.maxSteps;
    }
  }

  private restoreReActSteps(steps: ReActStep[]): void {
    this.reActStepsByMessageId.clear();
    this.stepsById.clear();

    const initialStep: ReActStep = {
      id: INITIAL_STEP_ID,
      messageId: "initial",
      stepId: -1,
      timestamp: Date.now(),
      role: "user",
      content: "",
      isBegin: true,
      isEnd: true,
      parentId: undefined,
    };
    this.stepsById.set(INITIAL_STEP_ID, initialStep);

    for (const step of steps) {
      this.addRestoredStep(step);
    }

    this.stepCounter = steps.length;
    this.messageCounter = new Set(steps.map(step => step.messageId)).size;
    const lastStep = steps[steps.length - 1];
    if (lastStep) {
      this.head = lastStep.id;
      if (lastStep.afterWorkflowContent) {
        this.workflowState.setWorkflowContent(lastStep.afterWorkflowContent);
      }
    }
  }

  private addRestoredStep(step: ReActStep): void {
    let steps = this.reActStepsByMessageId.get(step.messageId);
    if (!steps) {
      steps = [];
      this.reActStepsByMessageId.set(step.messageId, steps);
    }
    steps.push(step);
    this.stepsById.set(step.id, step);
  }

  private buildExecutionConfig(): ExecutionConfig | undefined {
    // Executing requires both a workflow and a connected computing unit. Without a computing unit
    // there is nothing to run on, so no execution config is produced (the execute tool and the
    // post-step auto-execution are skipped, and the model guides the user to connect one instead).
    if (
      !this.currentTaskContext ||
      this.currentTaskContext.workflowId === undefined ||
      this.currentTaskContext.computingUnitId === undefined
    ) {
      return undefined;
    }
    return {
      userToken: this.currentTaskContext.userToken,
      workflowId: this.currentTaskContext.workflowId,
      computingUnitId: this.currentTaskContext.computingUnitId,
      maxOperatorResultCharLimit: this.settings.maxOperatorResultCharLimit,
      maxOperatorResultCellCharLimit: this.settings.maxOperatorResultCellCharLimit,
      executionTimeoutMs: this.settings.executionTimeoutMs,
    };
  }

  private buildDatasetToolConfig(): DatasetToolConfig | undefined {
    if (!this.currentTaskContext) return undefined;
    return {
      userToken: this.currentTaskContext.userToken,
    };
  }

  private createTools(): Record<string, any> {
    const operatorSchemas = new Map<string, any>();
    for (const type of Object.keys(this.metadataStore.getAllOperatorTypes())) {
      const jsonSchema = this.metadataStore.getSchema(type);
      const additionalMetadata = this.metadataStore.getAdditionalMetadata(type);
      if (jsonSchema) {
        operatorSchemas.set(type, { jsonSchema, additionalMetadata });
      }
    }

    const getExecutionConfig =
      this.currentTaskContext?.workflowId !== undefined && this.currentTaskContext?.computingUnitId !== undefined
        ? () => this.buildExecutionConfig()!
        : undefined;
    const getDatasetToolConfig = this.currentTaskContext ? () => this.buildDatasetToolConfig()! : undefined;

    const context: ToolContext = {
      metadataStore: this.metadataStore,
    };

    const tools: Record<string, any> = {
      [TOOL_NAME_LIST_OPERATOR_TYPES]: createListOperatorTypesTool(this.metadataStore),
      [TOOL_NAME_GET_OPERATOR_DEFINITION]: createGetOperatorDefinitionTool(this.metadataStore),
      [TOOL_NAME_DELETE_OPERATOR]: createDeleteOperatorTool(this.workflowState, context),
      [TOOL_NAME_ADD_OPERATOR]: createAddOperatorTool(this.workflowState, operatorSchemas, context),
      [TOOL_NAME_MODIFY_OPERATOR]: createModifyOperatorTool(this.workflowState, context),
    };

    if (getExecutionConfig) {
      tools[TOOL_NAME_EXECUTE_OPERATOR] = createExecuteOperatorTool(
        this.workflowState,
        getExecutionConfig,
        (opId, operatorInfo) => {
          this.workflowResultState.set(opId, this.head, operatorInfo);
        }
      );
    }

    if (getDatasetToolConfig) {
      tools[TOOL_NAME_LIST_DATASETS] = createListDatasetsTool(getDatasetToolConfig);
      tools[TOOL_NAME_LIST_DATASET_VERSIONS] = createListDatasetVersionsTool(getDatasetToolConfig);
      tools[TOOL_NAME_LIST_DATASET_FILES] = createListDatasetFilesTool(getDatasetToolConfig);
    }

    Object.assign(tools, createRemoteMcpTools(this.mcpToolRegistry));

    return tools;
  }

  getState(): AgentStateEnum {
    return this.state;
  }

  getWorkflowState(): WorkflowState {
    return this.workflowState;
  }

  getMetadataStore(): WorkflowSystemMetadata {
    return this.metadataStore;
  }

  setTaskContext(taskContext?: AgentTaskContext): void {
    this.currentTaskContext = taskContext;
    this.tools = this.createTools();
  }

  getHead(): string {
    return this.head;
  }

  getAncestorPath(stepId?: string): string[] {
    const target = stepId ?? this.head;
    const chain: string[] = [];
    let current: string | undefined = target;
    while (current) {
      chain.unshift(current);
      current = this.stepsById.get(current)?.parentId;
    }
    return chain;
  }

  getStepsById(): Map<string, ReActStep> {
    return this.stepsById;
  }

  getWorkflowResultState(): WorkflowResultState {
    return this.workflowResultState;
  }

  getWebsockets(): Set<any> {
    return this.websockets;
  }

  addWebsocket(ws: any): void {
    this.websockets.add(ws);
  }

  removeWebsocket(ws: any): void {
    this.websockets.delete(ws);
  }

  getReActSteps(): ReActStep[] {
    const all: ReActStep[] = [];
    for (const steps of this.reActStepsByMessageId.values()) {
      all.push(...steps);
    }
    return all;
  }

  getVisibleReActSteps(): ReActStep[] {
    const path = this.getAncestorPath();
    return path
      .filter(id => id !== INITIAL_STEP_ID)
      .map(id => this.stepsById.get(id)!)
      .filter(Boolean);
  }

  getAllSteps(): ReActStep[] {
    return Array.from(this.stepsById.values()).filter(s => s.id !== INITIAL_STEP_ID);
  }

  checkout(stepId: string): boolean {
    const step = this.stepsById.get(stepId);
    if (!step && stepId !== INITIAL_STEP_ID) return false;
    this.head = stepId;
    if (step?.afterWorkflowContent) {
      this.workflowState.setWorkflowContent(step.afterWorkflowContent);
    }
    return true;
  }

  setStepCallback(callback: ReActStepCallback | null): void {
    this.stepCallback = callback;
  }

  private generateStepId(): string {
    return `step-${this.agentId}-${++this.stepCounter}-${Date.now()}`;
  }

  private addStep(step: ReActStep): void {
    let steps = this.reActStepsByMessageId.get(step.messageId);
    if (!steps) {
      steps = [];
      this.reActStepsByMessageId.set(step.messageId, steps);
    }
    steps.push(step);
    this.stepsById.set(step.id, step);
    if (this.stepCallback) {
      this.stepCallback(step);
    }
  }

  getSystemInfo(): {
    systemPrompt: string;
    tools: Array<{ name: string; description: string; inputSchema: any; enabled: boolean }>;
  } {
    const toolsInfo = Object.entries(this.tools).map(([name, toolDef]) => {
      const description = toolDef.description || "";
      const inputSchema = toolDef.parameters || {};
      const enabled = !this.settings.disabledTools.has(name);

      return {
        name,
        description,
        inputSchema,
        enabled,
      };
    });

    return {
      systemPrompt: this.systemPrompt,
      tools: toolsInfo,
    };
  }

  getSettings(): AgentSettings {
    return { ...this.settings };
  }

  getSettingsApi(): AgentSettingsApi {
    return {
      maxOperatorResultCharLimit: this.settings.maxOperatorResultCharLimit,
      maxOperatorResultCellCharLimit: this.settings.maxOperatorResultCellCharLimit,
      operatorResultSerializationMode: this.settings.operatorResultSerializationMode,
      executionTimeoutMinutes: Math.round(this.settings.executionTimeoutMs / 60000),
      disabledTools: Array.from(this.settings.disabledTools),
      maxSteps: this.settings.maxSteps,
    };
  }

  getPersistedConfig(): AgentPersistedConfig {
    return {
      systemPrompt: this.systemPrompt,
      tools: this.getSystemInfo().tools,
      settings: this.getSettingsApi(),
    };
  }

  updateAgentMetadata(updates: { name?: string; modelType?: string; model?: LanguageModel }): void {
    if (updates.name !== undefined) {
      this.agentName = updates.name;
    }
    if (updates.modelType !== undefined) {
      this.modelType = updates.modelType;
    }
    if (updates.model !== undefined) {
      this.model = updates.model;
    }
  }

  updateSettings(updates: {
    maxOperatorResultCharLimit?: number;
    maxOperatorResultCellCharLimit?: number;
    operatorResultSerializationMode?: OperatorResultSerializationMode;
    executionTimeoutMs?: number;
    disabledTools?: Set<string>;
    maxSteps?: number;
  }): void {
    if (updates.maxOperatorResultCharLimit !== undefined) {
      this.settings.maxOperatorResultCharLimit = updates.maxOperatorResultCharLimit;
    }
    if (updates.maxOperatorResultCellCharLimit !== undefined) {
      this.settings.maxOperatorResultCellCharLimit = updates.maxOperatorResultCellCharLimit;
    }
    if (updates.operatorResultSerializationMode !== undefined) {
      this.settings.operatorResultSerializationMode = updates.operatorResultSerializationMode;
    }
    if (updates.executionTimeoutMs !== undefined) {
      this.settings.executionTimeoutMs = updates.executionTimeoutMs;
    }
    if (updates.disabledTools !== undefined) {
      this.settings.disabledTools = updates.disabledTools;
    }
    if (updates.maxSteps !== undefined) {
      this.settings.maxSteps = updates.maxSteps;
    }

    this.tools = this.createTools();
    this.log.info(
      {
        maxOperatorResultCharLimit: this.settings.maxOperatorResultCharLimit,
        maxOperatorResultCellCharLimit: this.settings.maxOperatorResultCellCharLimit,
      },
      "settings updated"
    );
  }

  private async loadWorkflowForTask(taskContext: AgentTaskContext): Promise<string> {
    if (taskContext.workflowContent !== undefined) {
      this.workflowState.setWorkflowContent(taskContext.workflowContent);
      this.log.debug(
        { workflowId: taskContext.workflowId, operators: taskContext.workflowContent.operators.length },
        "loaded live workflow content for agent task"
      );
      return taskContext.workflowName || "Agent Workflow";
    }
    if (taskContext.workflowId === undefined) {
      return taskContext.workflowName || "Agent Workflow";
    }
    const workflow = await retrieveWorkflow(taskContext.userToken, taskContext.workflowId);
    this.workflowState.setWorkflowContent(workflow.content);
    this.log.debug({ workflowId: taskContext.workflowId }, "loaded workflow for agent task");
    return workflow.name || taskContext.workflowName || "Agent Workflow";
  }

  private async persistWorkflowForTask(taskContext: AgentTaskContext, workflowName: string): Promise<void> {
    if (taskContext.workflowId === undefined) {
      return;
    }
    try {
      const workflowContent = this.workflowState.getWorkflowContent();
      await persistWorkflow(taskContext.userToken, taskContext.workflowId, workflowName, workflowContent);
      this.log.debug({ workflowId: taskContext.workflowId }, "persisted workflow after agent task");
    } catch (error) {
      this.log.error({ workflowId: taskContext.workflowId, err: error }, "failed to persist workflow after agent task");
    }
  }

  async sendMessage(
    userMessage: string,
    taskContext: AgentTaskContext,
    messageSource?: "chat" | "feedback"
  ): Promise<AgentMessageResult> {
    const messageId = `msg-${this.agentId}-${++this.messageCounter}-${Date.now()}`;
    let stepIndex = 0;
    let workflowLoaded = false;
    let workflowName = taskContext.workflowName || "Agent Workflow";

    this.abortController = new AbortController();

    this.state = AgentStateEnum.GENERATING;

    this.currentMessageId = messageId;
    this.setTaskContext(taskContext);

    try {
      if (taskContext.workflowId !== undefined || taskContext.workflowContent !== undefined) {
        workflowName = await this.loadWorkflowForTask(taskContext);
        workflowLoaded = true;
      }

      let beforeStepContent = this.workflowState.getWorkflowContent();

      const estimatedInputTokens = Math.ceil(userMessage.length / 4);
      const userStepId = this.generateStepId();
      const userStep: ReActStep = {
        id: userStepId,
        parentId: this.head,
        messageId,
        stepId: 0,
        timestamp: Date.now(),
        role: "user",
        content: userMessage,
        isBegin: true,
        isEnd: true,
        messageSource,
        beforeWorkflowContent: beforeStepContent,
        afterWorkflowContent: beforeStepContent,
        usage: {
          inputTokens: estimatedInputTokens,
          outputTokens: 0,
          totalTokens: estimatedInputTokens,
        },
      };
      this.addStep(userStep);
      this.head = userStepId;

      let isFirstStep = true;
      let lastPreparedMessages: ModelMessage[] | undefined;
      const includeWorkflowContext = taskContext.workflowId !== undefined || taskContext.workflowContent !== undefined;

      // Pass only the current user turn; prepareStep rebuilds full context each step
      // (historical interactions + DAG + this message).
      const currentUserMessage: ModelMessage[] = [{ role: "user", content: userMessage }];
      const result = await generateText({
        model: this.model,
        system: this.systemPrompt,
        messages: currentUserMessage,
        tools: this.tools,
        temperature: 0.2,
        stopWhen: stepCountIs(this.settings.maxSteps),
        prepareStep: async ({ stepNumber, messages: currentMessages }) => {
          let compilationResult: WorkflowCompilationResponse | null = null;
          if (includeWorkflowContext && this.workflowState.getAllOperators().length > 0) {
            try {
              const logicalPlan = this.workflowState.toLogicalPlan();
              compilationResult = await compileWorkflowAsync(logicalPlan, taskContext.userToken);
            } catch (e: any) {
              this.log.warn({ err: e?.message || e }, "compilation failed; proceeding without schemas");
            }
          }

          const visibleSteps = this.getVisibleReActSteps();
          // Bound the event context with a rolling window: keep the latest user request plus the
          // most recent events that fit the token budget; drop older ones. The current workflow is
          // always shown in full below, so the agent never loses the state it is working on.
          const { kept, omitted } = windowEvents(visibleSteps, env.AGENT_MAX_CONTEXT_TOKENS);
          let processed = assembleContext(kept, this.workflowState, this.getFormattedResultsForDAG(), {
            useRedact: false,
            compilationResult,
            includeWorkflowContext,
            maxResolvedCharLimit: this.settings.maxOperatorResultCharLimit,
            computingUnitConnected: taskContext.computingUnitId !== undefined,
            omittedEventCount: omitted,
          });

          // Guard: nudge the model out of loops when it keeps calling the same tool with the same
          // parameters (e.g. retrying a wrong dataset path). Computed over the full history so a
          // repeat is caught even if the earlier identical calls fell outside the window.
          const repeatWarning = detectRepeatedToolCalls(visibleSteps, env.AGENT_REPEATED_TOOL_CALL_THRESHOLD);
          if (repeatWarning) {
            processed = appendSystemNotice(processed, repeatWarning);
          }

          lastPreparedMessages = processed;
          return { messages: processed };
        },
        abortSignal: this.abortController?.signal,
        // reasoning_effort is configured per-model in litellm-config.yaml via extra_body
        // to bypass LiteLLM's param validation — do not pass it here.
        providerOptions: {
          openai: { parallelToolCalls: false },
          anthropic: { disableParallelToolUse: true },
          mistral: { parallelToolCalls: false },
        },
        onStepFinish: async ({ text, toolCalls, toolResults, usage }) => {
          stepIndex++;

          const formattedToolCalls = toolCalls?.map(tc => ({
            toolName: tc.toolName,
            toolCallId: tc.toolCallId,
            input: tc.input,
          }));

          const formattedToolResults = toolResults?.map(tr => ({
            toolCallId: tr.toolCallId,
            output: tr.output,
            isError: !!(tr.output as any)?.error,
          }));

          const afterStepContent = this.workflowState.getWorkflowContent();

          const agentStepId = this.generateStepId();
          const agentStep: ReActStep = {
            id: agentStepId,
            parentId: this.head,
            messageId,
            stepId: stepIndex,
            timestamp: Date.now(),
            role: "agent",
            content: text || "",
            isBegin: isFirstStep,
            isEnd: false,
            toolCalls: formattedToolCalls,
            toolResults: formattedToolResults,
            usage: usage
              ? {
                  inputTokens: usage.inputTokens,
                  outputTokens: usage.outputTokens,
                  totalTokens: usage.totalTokens,
                }
              : undefined,
            inputMessages: lastPreparedMessages,
            beforeWorkflowContent: beforeStepContent,
            afterWorkflowContent: afterStepContent,
          };
          lastPreparedMessages = undefined;
          this.addStep(agentStep);
          this.head = agentStepId;

          const execConfig = this.buildExecutionConfig();
          if (execConfig && toolCalls && toolResults) {
            const EXECUTE_AFTER_TOOLS = new Set([TOOL_NAME_ADD_OPERATOR, TOOL_NAME_MODIFY_OPERATOR]);

            for (let i = 0; i < toolCalls.length; i++) {
              const tc = toolCalls[i];
              const tr = toolResults[i];
              if (!EXECUTE_AFTER_TOOLS.has(tc.toolName)) continue;

              const resultText = typeof tr?.output === "string" ? tr.output : String(tr?.output ?? "");
              if (resultText.startsWith("[ERROR]")) continue;

              const operatorId = (tc.input as any)?.operatorId;
              if (!operatorId) continue;

              try {
                await executeOperatorAndFormat(this.workflowState, execConfig, operatorId, {
                  abortSignal: this.abortController?.signal,
                  onResult: (opId, operatorInfo) => {
                    this.workflowResultState.set(opId, this.head, operatorInfo);
                  },
                });
              } catch (e: any) {
                this.log.warn({ operatorId, err: e?.message || e }, "post-step execution failed");
              }
            }
          }

          beforeStepContent = afterStepContent;
          isFirstStep = false;
        },
      });

      const msgSteps = this.reActStepsByMessageId.get(messageId);
      if (msgSteps && msgSteps.length > 0) {
        const lastStep = msgSteps[msgSteps.length - 1];
        if (lastStep.role === "agent") {
          lastStep.isEnd = true;
        }
      }

      const finalUsage = (result as any).totalUsage || result.usage;
      const usage: TokenUsage = {
        inputTokens: finalUsage?.inputTokens ?? finalUsage?.promptTokens ?? 0,
        outputTokens: finalUsage?.outputTokens ?? finalUsage?.completionTokens ?? 0,
        totalTokens: finalUsage?.totalTokens ?? 0,
      };

      return {
        response: result.text,
        messages: result.response.messages,
        usage,
        stopped: false,
      };
    } catch (error: any) {
      const isAborted = error.name === "AbortError" || this.abortController?.signal.aborted;

      if (isAborted) {
        stepIndex++;
        const stoppedStepId = this.generateStepId();
        const stoppedStep: ReActStep = {
          id: stoppedStepId,
          parentId: this.head,
          messageId,
          stepId: stepIndex,
          timestamp: Date.now(),
          role: "agent",
          content: "Generation stopped by user.",
          isBegin: false,
          isEnd: true,
        };
        this.addStep(stoppedStep);
        this.head = stoppedStepId;

        return {
          response: "",
          messages: [],
          usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
          stopped: true,
        };
      }

      stepIndex++;
      const errorStepId = this.generateStepId();
      const errorStep: ReActStep = {
        id: errorStepId,
        parentId: this.head,
        messageId,
        stepId: stepIndex,
        timestamp: Date.now(),
        role: "agent",
        content: `Error: ${error.message || String(error)}`,
        isBegin: false,
        isEnd: true,
      };
      this.addStep(errorStep);
      this.head = errorStepId;

      return {
        response: "",
        messages: [],
        usage: { inputTokens: 0, outputTokens: 0, totalTokens: 0 },
        stopped: false,
        error: error.message || String(error),
      };
    } finally {
      // The frontend auto-persists the workflow whenever the canvas changes, and the agent's
      // edits are replayed onto that canvas, so the frontend is the single persistence writer
      // while a chat client is connected. Persist from here only when running headless (no
      // connected websocket) to avoid two writers racing on the same workflow.
      if (workflowLoaded && this.websockets.size === 0) {
        await this.persistWorkflowForTask(taskContext, workflowName);
      }
      this.abortController = null;
      this.currentMessageId = undefined;
      this.setTaskContext(undefined);
      this.state = AgentStateEnum.AVAILABLE;
    }
  }

  private getFormattedResultsForDAG(): Map<string, string> {
    const result = new Map<string, string>();
    const visible = this.workflowResultState.getAllVisible();
    for (const [operatorId, entry] of visible) {
      result.set(
        operatorId,
        formatOperatorResult(
          operatorId,
          entry.operatorInfo,
          this.workflowState,
          this.settings.maxOperatorResultCharLimit
        )
      );
    }
    return result;
  }

  stop(): void {
    this.state = AgentStateEnum.STOPPING;
    if (this.abortController) {
      this.abortController.abort();
    }
  }

  clearHistory(): void {
    this.reActStepsByMessageId.clear();
    this.stepsById.clear();
    this.currentMessageId = undefined;
    this.head = INITIAL_STEP_ID;
    const initialStep: ReActStep = {
      id: INITIAL_STEP_ID,
      messageId: "initial",
      stepId: -1,
      timestamp: Date.now(),
      role: "user",
      content: "",
      isBegin: true,
      isEnd: true,
    };
    this.stepsById.set(INITIAL_STEP_ID, initialStep);
  }

  private getOperatorIdsFromStep(step: ReActStep): { added: string[]; modified: string[] } {
    const added: string[] = [];
    const modified: string[] = [];

    if (!step.toolResults) {
      return { added, modified };
    }

    for (const result of step.toolResults) {
      if (result.isError || !result.output) continue;

      const toolCall = step.toolCalls?.find(tc => tc.toolCallId === result.toolCallId);
      const toolName = toolCall?.toolName || "";

      const outputStr = typeof result.output === "string" ? result.output : JSON.stringify(result.output);

      const addedMatch = outputStr.match(/Added operator ([a-zA-Z0-9_-]+)/);
      if (addedMatch && (toolName === "addOperator" || toolName.toLowerCase().includes("add"))) {
        added.push(addedMatch[1]);
        continue;
      }

      const modifiedMatch = outputStr.match(/Operator ([a-zA-Z0-9_-]+) modified/);
      if (modifiedMatch && (toolName === "modifyOperator" || toolName.toLowerCase().includes("modify"))) {
        modified.push(modifiedMatch[1]);
        continue;
      }

      try {
        const output = JSON.parse(outputStr);
        if (output.operatorId) {
          if (toolName === "addOperator" || toolName === "addCodeOperator") {
            added.push(output.operatorId);
          } else if (toolName === "modifyOperator" || toolName === "modifyCodeOperator") {
            modified.push(output.operatorId);
          }
        }
      } catch {}
    }

    return { added, modified };
  }

  public getReActStepsByOperatorIds(operatorIds: string[]): ReActStep[] {
    const allSteps = this.getReActSteps();
    if (!operatorIds || operatorIds.length === 0) {
      return allSteps;
    }

    const operatorIdSet = new Set(operatorIds);
    const relevantSteps: ReActStep[] = [];

    for (const step of allSteps) {
      const { added, modified } = this.getOperatorIdsFromStep(step);

      const affectsOperator = [...added, ...modified].some(id => operatorIdSet.has(id));

      if (affectsOperator) {
        relevantSteps.push(step);
      }
    }

    return relevantSteps;
  }

  destroy(): void {
    this.workflowState.destroy();

    this.websockets.clear();

    this.reActStepsByMessageId.clear();
    this.stepsById.clear();
    this.currentMessageId = undefined;
    this.currentTaskContext = undefined;
  }
}
