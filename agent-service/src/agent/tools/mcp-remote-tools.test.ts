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

import { describe, expect, test } from "bun:test";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { createRemoteMcpTools, formatMcpToolResult, type RemoteMcpToolCaller } from "./mcp-remote-tools";

function createFakeRegistry(result: CallToolResult | Error): {
  registry: RemoteMcpToolCaller;
  calls: Array<{ toolName: string; args: Record<string, unknown> }>;
} {
  const calls: Array<{ toolName: string; args: Record<string, unknown> }> = [];
  return {
    calls,
    registry: {
      getTools: () => [
        {
          toolName: "biomcp_search_pubmed",
          serverName: "biomcp",
          remoteToolName: "search_pubmed",
          description: "Search PubMed literature.",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string" },
            },
            required: ["query"],
          },
        },
      ],
      callTool: async (toolName, args) => {
        calls.push({ toolName, args });
        if (result instanceof Error) throw result;
        return result;
      },
    },
  };
}

describe("formatMcpToolResult", () => {
  test("joins text MCP content blocks", () => {
    expect(
      formatMcpToolResult({
        content: [
          { type: "text", text: "first" },
          { type: "text", text: "second" },
        ],
      })
    ).toBe("first\nsecond");
  });

  test("falls back to structured content when content is empty", () => {
    expect(formatMcpToolResult({ content: [], structuredContent: { id: 1 } })).toBe('{"id":1}');
  });
});

describe("createRemoteMcpTools", () => {
  test("creates AI SDK tools that delegate calls through MCP", async () => {
    const { registry, calls } = createFakeRegistry({
      content: [{ type: "text", text: "found 2 articles" }],
    });

    const tools = createRemoteMcpTools(registry);
    const output = await (tools.biomcp_search_pubmed as any).execute({ query: "BRCA1" });

    expect(output).toBe("found 2 articles");
    expect(calls).toEqual([{ toolName: "biomcp_search_pubmed", args: { query: "BRCA1" } }]);
  });

  test("preserves remote MCP tool errors in the Texera tool result format", async () => {
    const { registry } = createFakeRegistry({
      content: [{ type: "text", text: "remote failure" }],
      isError: true,
    });

    const tools = createRemoteMcpTools(registry);
    const output = await (tools.biomcp_search_pubmed as any).execute({ query: "BRCA1" });

    expect(output).toBe("[ERROR] remote failure");
  });

  test("formats thrown MCP client errors as Texera tool errors", async () => {
    const { registry } = createFakeRegistry(new Error("connection closed"));

    const tools = createRemoteMcpTools(registry);
    const output = await (tools.biomcp_search_pubmed as any).execute({ query: "BRCA1" });

    expect(output).toBe("[ERROR] connection closed");
  });
});
