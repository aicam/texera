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

import type { WorkflowContent } from "./workflow";

export enum AgentState {
  UNAVAILABLE = "UNAVAILABLE",
  AVAILABLE = "AVAILABLE",
  GENERATING = "GENERATING",
  STOPPING = "STOPPING",
}

export interface TokenUsage {
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  cachedInputTokens?: number;
}

export const INITIAL_STEP_ID = "step-initial";
export const DEFAULT_AGENT_NAME = "dkNetAgent";

export interface ReActStep {
  id: string;
  parentId?: string;
  messageId: string;
  stepId: number;
  timestamp: number;
  role: "user" | "agent";
  content: string;
  isBegin: boolean;
  isEnd: boolean;
  toolCalls?: Array<{
    toolName: string;
    toolCallId: string;
    input: any;
  }>;
  toolResults?: Array<{
    toolCallId: string;
    output: any;
    isError?: boolean;
  }>;
  usage?: TokenUsage;
  inputMessages?: any[];
  messageSource?: "chat" | "feedback";
  beforeWorkflowContent?: WorkflowContent;
  afterWorkflowContent?: WorkflowContent;
}

export enum OperatorResultSerializationMode {
  TSV = "tsv",
}

export interface AgentSettings {
  systemPrompt: string;
  disabledTools: Set<string>;
  maxOperatorResultCharLimit: number;
  maxOperatorResultCellCharLimit: number;
  operatorResultSerializationMode: OperatorResultSerializationMode;
  executionTimeoutMs: number;
  maxSteps: number;
}

export const DEFAULT_AGENT_SETTINGS: Omit<AgentSettings, "systemPrompt"> = {
  disabledTools: new Set(),
  maxOperatorResultCharLimit: 10000,
  maxOperatorResultCellCharLimit: 10000,
  operatorResultSerializationMode: OperatorResultSerializationMode.TSV,
  executionTimeoutMs: 240000,
  maxSteps: 100,
};

export interface UserInfo {
  uid: number;
  name: string;
  email: string;
  role: string;
}

export interface AgentTaskContext {
  userToken: string;
  userInfo?: UserInfo;
  workflowId?: number;
  workflowName?: string;
  workflowContent?: WorkflowContent;
  computingUnitId?: number;
}

export interface AgentToolInfo {
  name: string;
  description: string;
  inputSchema: any;
  enabled: boolean;
}

export interface AgentPersistedConfig {
  systemPrompt: string;
  tools: AgentToolInfo[];
  settings: AgentSettingsApi;
}

export interface AgentSettingsApi {
  maxOperatorResultCharLimit?: number;
  maxOperatorResultCellCharLimit?: number;
  operatorResultSerializationMode?: "tsv";
  executionTimeoutMinutes?: number;
  disabledTools?: string[];
  maxSteps?: number;
}

export interface AgentInfo {
  id: string;
  name: string;
  modelType: string;
  state: AgentState;
  createdAt: Date;
}

export interface CreateAgentRequest {
  modelType: string;
  name?: string;
}

export interface UpdateAgentRequest {
  name?: string;
  modelType?: string;
}
