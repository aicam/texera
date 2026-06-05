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
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { parseMcpServerConfigs, isSessionLostError, RemoteMcpToolRegistry } from "./mcp-client-manager";

describe("parseMcpServerConfigs", () => {
  test("returns an empty list when no MCP servers are configured", () => {
    expect(parseMcpServerConfigs(undefined)).toEqual([]);
    expect(parseMcpServerConfigs("")).toEqual([]);
  });

  test("parses enabled streamable HTTP MCP server configs", () => {
    const configs = parseMcpServerConfigs(
      JSON.stringify([
        {
          name: "biomcp",
          url: "http://localhost:3010/mcp",
          toolPrefix: "bio",
          apiKeyEnv: "BIOMCP_API_KEY",
        },
      ])
    );

    expect(configs).toEqual([
      {
        name: "biomcp",
        url: "http://localhost:3010/mcp",
        toolPrefix: "bio",
        apiKeyEnv: "BIOMCP_API_KEY",
        enabled: true,
      },
    ]);
  });

  test("accepts an object payload with a servers array and skips disabled servers", () => {
    const configs = parseMcpServerConfigs(
      JSON.stringify({
        servers: [
          { name: "enabled", url: "http://localhost:3000/mcp" },
          { name: "disabled", url: "http://localhost:3001/mcp", enabled: false },
        ],
      })
    );

    expect(configs.map(config => config.name)).toEqual(["enabled"]);
  });

  test("rejects invalid JSON with a clear error", () => {
    expect(() => parseMcpServerConfigs("{")).toThrow("MCP_SERVERS must be valid JSON");
  });

  test("rejects server configs without a URL", () => {
    expect(() => parseMcpServerConfigs(JSON.stringify([{ name: "missing-url" }]))).toThrow();
  });
});

describe("isSessionLostError", () => {
  test("matches an HTTP 404 from the MCP transport", () => {
    expect(isSessionLostError(new StreamableHTTPError(404, "Error POSTing to endpoint: anything"))).toBe(true);
  });

  test("matches a 'session not found' message regardless of error type", () => {
    expect(isSessionLostError(new Error('{"error":{"code":-32000,"message":"MCP session not found"}}'))).toBe(true);
    expect(isSessionLostError("Session not found")).toBe(true);
  });

  test("does not match other transport statuses or unrelated errors", () => {
    expect(isSessionLostError(new StreamableHTTPError(500, "Internal error"))).toBe(false);
    expect(isSessionLostError(new Error("boom"))).toBe(false);
    expect(isSessionLostError(undefined)).toBe(false);
  });
});

describe("RemoteMcpToolRegistry session recovery", () => {
  const CONFIG = { name: "biomcp", url: "http://localhost:3010/mcp", enabled: true };
  const OK = { content: [{ type: "text", text: "ok" }] };
  const lost = () => new StreamableHTTPError(404, "Error POSTing to endpoint: MCP session not found");

  function registryWith(deadClient: any, fresh: () => any) {
    const registry: any = new RemoteMcpToolRegistry();
    registry.sessions.set("biomcp", { config: CONFIG, client: deadClient, transport: {} });
    registry.toolDefinitions.set("bio_a", { toolName: "bio_a", serverName: "biomcp", remoteToolName: "a", inputSchema: {} });
    registry.toolDefinitions.set("bio_b", { toolName: "bio_b", serverName: "biomcp", remoteToolName: "b", inputSchema: {} });
    registry.openSessionCalls = 0;
    registry.openSession = async () => {
      registry.openSessionCalls++;
      await Promise.resolve();
      return { config: CONFIG, client: fresh(), transport: {} };
    };
    return registry;
  }

  test("reconnects once and retries the call when the session was lost", async () => {
    let deadCalls = 0;
    const deadClient = { callTool: async () => { deadCalls++; throw lost(); }, close: async () => {} };
    let freshCalls = 0;
    const freshClient = { callTool: async () => { freshCalls++; return OK; }, close: async () => {} };
    const registry = registryWith(deadClient, () => freshClient);

    expect(await registry.callTool("bio_a", { q: "x" })).toEqual(OK);
    expect(deadCalls).toBe(1); // dead session attempted once
    expect(registry.openSessionCalls).toBe(1); // reconnected once
    expect(freshCalls).toBe(1); // retried on the fresh session
  });

  test("does not reconnect on a non-session error", async () => {
    const client = { callTool: async () => { throw new Error("boom"); }, close: async () => {} };
    const registry = registryWith(client, () => client);
    await expect(registry.callTool("bio_a", {})).rejects.toThrow("boom");
    expect(registry.openSessionCalls).toBe(0);
  });

  test("retries at most once — a second session loss propagates instead of looping", async () => {
    const deadClient = { callTool: async () => { throw lost(); }, close: async () => {} };
    const stillDead = { callTool: async () => { throw lost(); }, close: async () => {} };
    const registry = registryWith(deadClient, () => stillDead);
    await expect(registry.callTool("bio_a", {})).rejects.toThrow(/session not found/i);
    expect(registry.openSessionCalls).toBe(1); // reconnected exactly once, no loop
  });

  test("concurrent lost-session calls share a single reconnect", async () => {
    const deadClient = { callTool: async () => { throw lost(); }, close: async () => {} };
    const freshClient = { callTool: async () => OK, close: async () => {} };
    const registry = registryWith(deadClient, () => freshClient);

    const [a, b] = await Promise.all([registry.callTool("bio_a", {}), registry.callTool("bio_b", {})]);
    expect(a).toEqual(OK);
    expect(b).toEqual(OK);
    expect(registry.openSessionCalls).toBe(1); // both shared ONE reconnect
  });
});
