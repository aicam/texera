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
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig } from "../config";
import { createContext, type McpContext } from "../context";
import { createServer } from "../server";
import type { FakeTexera } from "./fake-texera";
import { makeToken } from "./token";

export interface Harness {
  client: Client;
  context: McpContext;
  /** Calls a tool and returns its text content, asserting it did not error. */
  call(name: string, args?: Record<string, unknown>): Promise<string>;
  /** Calls a tool expecting failure, and returns the error text. */
  callExpectingError(name: string, args?: Record<string, unknown>): Promise<string>;
  close(): Promise<void>;
}

/**
 * Wires a real MCP client to a real MCP server over an in-memory transport,
 * with the deployment faked at the `fetch` boundary. Exercises the whole path a
 * chatbot takes: schema validation, dispatch, handler, error mapping.
 */
export async function startHarness(deployment: FakeTexera): Promise<Harness> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = deployment.fetch;

  const config = loadConfig({
    TEXERA_BASE_URL: deployment.origin,
    TEXERA_TOKEN: makeToken(),
  });
  const context = createContext(config);
  const server = createServer(context);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });

  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

  const callTool = async (name: string, args?: Record<string, unknown>) =>
    (await client.callTool({ name, arguments: args ?? {} })) as CallToolResult;

  const textOf = (result: CallToolResult) =>
    result.content
      .filter((block): block is { type: "text"; text: string } => block.type === "text")
      .map(block => block.text)
      .join("\n");

  return {
    client,
    context,
    async call(name, args) {
      const result = await callTool(name, args);
      if (result.isError) {
        throw new Error(`tool ${name} failed unexpectedly: ${textOf(result)}`);
      }
      return textOf(result);
    },
    async callExpectingError(name, args) {
      const result = await callTool(name, args);
      if (!result.isError) {
        throw new Error(`tool ${name} was expected to fail but returned: ${textOf(result)}`);
      }
      return textOf(result);
    },
    async close() {
      await client.close();
      await server.close();
      globalThis.fetch = originalFetch;
    },
  };
}
