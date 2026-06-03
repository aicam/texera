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

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { env } from "../../config/env";
import { createLogger } from "../../logger";

const log = createLogger("RemoteMcpToolRegistry");

const RemoteMcpServerConfigSchema = z.object({
  name: z.string().min(1),
  url: z.string().url(),
  toolPrefix: z.string().min(1).optional(),
  apiKey: z.string().optional(),
  apiKeyEnv: z.string().optional(),
  headers: z.record(z.string()).optional(),
  enabled: z.boolean().optional().default(true),
});

const RemoteMcpServerConfigsSchema = z.array(RemoteMcpServerConfigSchema);

export type RemoteMcpServerConfig = z.infer<typeof RemoteMcpServerConfigSchema>;

export interface RemoteMcpToolDefinition {
  toolName: string;
  serverName: string;
  remoteToolName: string;
  description?: string;
  inputSchema: Tool["inputSchema"];
}

interface RemoteMcpServerSession {
  config: RemoteMcpServerConfig;
  client: Client;
  transport: StreamableHTTPClientTransport;
}

function normalizeToolNameSegment(value: string): string {
  const normalized = value
    .replace(/[^A-Za-z0-9_]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (!normalized) return "mcp";
  return /^[A-Za-z_]/.test(normalized) ? normalized : `_${normalized}`;
}

function normalizeConfigPayload(parsed: unknown): unknown {
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === "object" && Array.isArray((parsed as { servers?: unknown }).servers)) {
    return (parsed as { servers: unknown }).servers;
  }
  return parsed;
}

function buildHeaders(config: RemoteMcpServerConfig): Record<string, string> | undefined {
  const headers: Record<string, string> = { ...(config.headers ?? {}) };
  const apiKey = config.apiKey ?? (config.apiKeyEnv ? process.env[config.apiKeyEnv] : undefined);
  if (apiKey && !headers["x-api-key"] && !headers.Authorization && !headers.authorization) {
    headers["x-api-key"] = apiKey;
  }
  return Object.keys(headers).length > 0 ? headers : undefined;
}

export function parseMcpServerConfigs(rawConfig: string | undefined): RemoteMcpServerConfig[] {
  const raw = rawConfig?.trim();
  if (!raw) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`MCP_SERVERS must be valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }

  const configs = RemoteMcpServerConfigsSchema.parse(normalizeConfigPayload(parsed));
  return configs.filter(config => config.enabled);
}

export class RemoteMcpToolRegistry {
  private static instance: RemoteMcpToolRegistry | undefined;

  private initialized = false;
  private initializing: Promise<void> | undefined;
  private sessions = new Map<string, RemoteMcpServerSession>();
  private toolDefinitions = new Map<string, RemoteMcpToolDefinition>();

  static getInstance(): RemoteMcpToolRegistry {
    if (!RemoteMcpToolRegistry.instance) {
      RemoteMcpToolRegistry.instance = new RemoteMcpToolRegistry();
    }
    return RemoteMcpToolRegistry.instance;
  }

  async initialize(configs?: RemoteMcpServerConfig[]): Promise<void> {
    if (this.initialized) return;
    if (this.initializing) return this.initializing;

    this.initializing = this.load(configs).finally(() => {
      this.initializing = undefined;
    });

    return this.initializing;
  }

  getTools(): RemoteMcpToolDefinition[] {
    return [...this.toolDefinitions.values()];
  }

  async callTool(toolName: string, args: Record<string, unknown>, abortSignal?: AbortSignal): Promise<CallToolResult> {
    const definition = this.toolDefinitions.get(toolName);
    if (!definition) {
      throw new Error(`Unknown remote MCP tool: ${toolName}`);
    }

    const session = this.sessions.get(definition.serverName);
    if (!session) {
      throw new Error(`Remote MCP server is not connected: ${definition.serverName}`);
    }

    return (await session.client.callTool(
      {
        name: definition.remoteToolName,
        arguments: args,
      },
      CallToolResultSchema,
      {
        signal: abortSignal,
        timeout: env.MCP_REQUEST_TIMEOUT_MS,
      }
    )) as CallToolResult;
  }

  async close(): Promise<void> {
    const sessions = [...this.sessions.values()];
    this.sessions.clear();
    this.toolDefinitions.clear();
    this.initialized = false;
    this.initializing = undefined;

    await Promise.allSettled(sessions.map(session => session.client.close()));
  }

  private async load(configsArg?: RemoteMcpServerConfig[]): Promise<void> {
    let configs = configsArg;
    if (!configs) {
      try {
        configs = parseMcpServerConfigs(env.MCP_SERVERS);
      } catch (error) {
        log.warn({ err: error }, "invalid MCP server configuration; skipping remote MCP tools");
        this.initialized = true;
        return;
      }
    }

    for (const config of configs) {
      await this.connectServer(config);
    }

    this.initialized = true;
    log.info({ serverCount: this.sessions.size, toolCount: this.toolDefinitions.size }, "remote MCP tools initialized");
  }

  private async connectServer(config: RemoteMcpServerConfig): Promise<void> {
    try {
      const client = new Client(
        {
          name: `texera-agent-service-${config.name}`,
          version: "0.1.0",
        },
        {
          capabilities: {},
        }
      );
      const transport = new StreamableHTTPClientTransport(new URL(config.url), {
        requestInit: {
          headers: buildHeaders(config),
        },
      });

      await client.connect(transport, { timeout: env.MCP_REQUEST_TIMEOUT_MS });
      const listedTools = await client.listTools(undefined, { timeout: env.MCP_REQUEST_TIMEOUT_MS });

      this.sessions.set(config.name, { config, client, transport });
      const prefix = normalizeToolNameSegment(config.toolPrefix ?? config.name);

      for (const toolDefinition of listedTools.tools) {
        const toolName = `${prefix}_${normalizeToolNameSegment(toolDefinition.name)}`;
        if (this.toolDefinitions.has(toolName)) {
          log.warn(
            {
              serverName: config.name,
              remoteToolName: toolDefinition.name,
              toolName,
            },
            "skipping duplicate remote MCP tool name"
          );
          continue;
        }

        this.toolDefinitions.set(toolName, {
          toolName,
          serverName: config.name,
          remoteToolName: toolDefinition.name,
          description: toolDefinition.description,
          inputSchema: toolDefinition.inputSchema,
        });
      }

      log.info({ serverName: config.name, toolCount: listedTools.tools.length }, "connected remote MCP server");
    } catch (error) {
      log.warn({ err: error, serverName: config.name, url: config.url }, "failed to connect remote MCP server");
    }
  }
}
