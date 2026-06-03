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
import { parseMcpServerConfigs } from "./mcp-client-manager";

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
