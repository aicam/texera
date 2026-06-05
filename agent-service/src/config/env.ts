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

import { z } from "zod";

const EnvSchema = z.object({
  PORT: z.coerce.number().default(3001),
  API_PREFIX: z.string().default("/api"),
  LLM_API_KEY: z.string().default("dummy"),
  TEXERA_SERVICE_LOG_LEVEL: z
    .enum(["ERROR", "WARN", "INFO", "DEBUG"])
    .transform(v => v.toLowerCase() as "error" | "warn" | "info" | "debug")
    .default("INFO"),
  LOG_PRETTY: z.coerce.boolean().default(false),

  TEXERA_DASHBOARD_SERVICE_ENDPOINT: z.string().url().default("http://localhost:8080"),
  FILE_SERVICE_ENDPOINT: z.string().url().default("http://localhost:9092"),
  LLM_ENDPOINT: z.string().url().default("http://localhost:9096"),
  WORKFLOW_COMPILING_SERVICE_ENDPOINT: z.string().url().default("http://localhost:9090"),
  WORKFLOW_EXECUTION_SERVICE_ENDPOINT: z.string().url().default("http://localhost:8085"),
  EXECUTION_ENDPOINT_TEMPLATE: z.string().optional(),

  MCP_SERVERS: z.string().default("[]"),
  MCP_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(30000),

  // Agent configuration. The system prompt can be overridden by a mounted file (k8s ConfigMap)
  // so it can change without rebuilding the image; the settings below override
  // DEFAULT_AGENT_SETTINGS when set. The two guard knobs are always active with these defaults.
  AGENT_SYSTEM_PROMPT_PATH: z.string().optional(),
  AGENT_MAX_OPERATOR_RESULT_CHAR_LIMIT: z.coerce.number().int().positive().optional(),
  AGENT_MAX_OPERATOR_RESULT_CELL_CHAR_LIMIT: z.coerce.number().int().positive().optional(),
  AGENT_EXECUTION_TIMEOUT_MS: z.coerce.number().int().positive().optional(),
  AGENT_MAX_STEPS: z.coerce.number().int().positive().optional(),
  // ReAct-loop guards: warn after this many identical (tool, params) calls in one run, and bound
  // the event log to roughly this estimated token budget (older events are dropped by a rolling
  // window; the current workflow state is always shown in full).
  AGENT_REPEATED_TOOL_CALL_THRESHOLD: z.coerce.number().int().positive().default(3),
  AGENT_MAX_CONTEXT_TOKENS: z.coerce.number().int().positive().default(80000),
  // Comma-separated operator types to hide from the agent IN ADDITION TO the built-in obsolete
  // list (which is always excluded — an empty value here still hides the built-ins). These stay
  // available to GUI users; this only narrows what the agent sees/suggests.
  AGENT_EXTRA_EXCLUDED_OPERATOR_TYPES: z.string().optional(),
  // In-memory agentStore eviction. Agents are cached per pod and never evicted on their own,
  // so a long-lived pod accumulates every agent it ever touched. A periodic sweep drops agents
  // that are idle past AGENT_IDLE_EVICTION_MS, have no live WebSockets, and are not running;
  // their state is in Postgres, so the next access rehydrates transparently. 0 disables eviction.
  AGENT_IDLE_EVICTION_MS: z.coerce.number().int().nonnegative().default(1_800_000), // 30 min
  AGENT_EVICTION_SWEEP_MS: z.coerce.number().int().positive().default(300_000), // 5 min

  STORAGE_JDBC_URL: z.string().default("jdbc:postgresql://localhost:5432/texera_db?currentSchema=texera_db,public"),
  STORAGE_JDBC_USERNAME: z.string().default("postgres"),
  STORAGE_JDBC_PASSWORD: z.string().default("postgres"),
});

export const env = EnvSchema.parse(process.env);
