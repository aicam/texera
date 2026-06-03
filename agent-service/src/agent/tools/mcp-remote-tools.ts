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

import { jsonSchema, tool } from "ai";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { RemoteMcpToolDefinition } from "../mcp/mcp-client-manager";
import { createErrorResult, createToolResult } from "./tools-utility";

export interface RemoteMcpToolCaller {
  getTools(): RemoteMcpToolDefinition[];
  callTool(toolName: string, args: Record<string, unknown>, abortSignal?: AbortSignal): Promise<CallToolResult>;
}

function formatContentBlock(block: CallToolResult["content"][number]): string {
  switch (block.type) {
    case "text":
      return block.text;
    case "resource":
      if ("text" in block.resource) {
        return `Resource ${block.resource.uri}:\n${block.resource.text}`;
      }
      return `Resource ${block.resource.uri}: ${block.resource.blob}`;
    case "resource_link":
      return `Resource link ${block.name}: ${block.uri}`;
    case "image":
      return `[image: ${block.mimeType}, ${block.data.length} base64 chars]`;
    case "audio":
      return `[audio: ${block.mimeType}, ${block.data.length} base64 chars]`;
    default:
      return JSON.stringify(block);
  }
}

export function formatMcpToolResult(result: CallToolResult): string {
  const contentText = (result.content ?? []).map(formatContentBlock).filter(Boolean).join("\n");
  if (contentText) return contentText;
  if (result.structuredContent) return JSON.stringify(result.structuredContent);
  return "";
}

export function createRemoteMcpTools(registry: RemoteMcpToolCaller): Record<string, any> {
  const tools: Record<string, any> = {};

  for (const definition of registry.getTools()) {
    tools[definition.toolName] = tool<Record<string, unknown>, string>({
      description: `[${definition.serverName}] ${definition.description ?? definition.remoteToolName}`,
      inputSchema: jsonSchema<Record<string, unknown>>(definition.inputSchema as any),
      execute: async (args: Record<string, unknown> = {}, options: { abortSignal?: AbortSignal } = {}) => {
        try {
          const result = await registry.callTool(definition.toolName, args, options.abortSignal);
          const formatted = formatMcpToolResult(result);
          return result.isError ? createErrorResult(formatted) : createToolResult(formatted);
        } catch (error: any) {
          return createErrorResult(error.message || String(error));
        }
      },
    });
  }

  return tools;
}
