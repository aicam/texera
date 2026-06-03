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
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createFetchHandler } from "./index.js";

describe("bio-mcp-service fetch handler", () => {
  test("returns service health and enabled tools", async () => {
    const response = await createFetchHandler()(new Request("http://localhost/healthcheck"));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.service).toBe("bio-mcp-service");
    expect(body.enabledTools).toContain("search_pubmed");
  });

  test("returns 404 for non-BioMCP paths", async () => {
    const response = await createFetchHandler()(new Request("http://localhost/unknown"));
    const body = await response.json();

    expect(response.status).toBe(404);
    expect(body.error).toBe("Not found");
  });

  test("rejects non-initialize MCP posts without a session id", async () => {
    const response = await createFetchHandler()(
      new Request("http://localhost/mcp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/list",
          params: {},
        }),
      })
    );
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error.message).toContain("Missing MCP session id");
  });
});

describe("bio-mcp-service MCP protocol", () => {
  test("lists tools through the official streamable HTTP MCP client", async () => {
    const service = Bun.serve({
      port: 0,
      fetch: createFetchHandler(),
    });
    const client = new Client(
      {
        name: "bio-mcp-service-test",
        version: "0.1.0",
      },
      {
        capabilities: {},
      }
    );

    try {
      const transport = new StreamableHTTPClientTransport(new URL(`http://localhost:${service.port}/mcp`));
      await client.connect(transport);
      const result = await client.listTools();

      expect(result.tools.map((tool) => tool.name)).toContain("search_pubmed");
      expect(result.tools.map((tool) => tool.name)).toContain("lookup_variant");
    } finally {
      await client.close();
      service.stop(true);
    }
  });
});
