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

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ConfigError, loadConfig } from "./config";
import { createContext } from "./context";
import { createServer } from "./server";

export { createServer } from "./server";
export { createContext } from "./context";
export { loadConfig, ConfigError } from "./config";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      // stderr, never stdout: stdout carries the JSON-RPC stream and any stray
      // byte there breaks the client's parser.
      process.stderr.write(`texera-mcp: ${error.message}\n`);
      process.exit(1);
    }
    throw error;
  }

  const context = createContext(config);
  const server = createServer(context);

  await server.connect(new StdioServerTransport());
  process.stderr.write(`texera-mcp: connected to ${config.baseUrl} as ${config.claims.sub ?? "unknown user"}\n`);
}

// Only run when executed directly, so tests can import the factories above.
if (import.meta.main) {
  main().catch(error => {
    process.stderr.write(
      `texera-mcp: fatal: ${error instanceof Error ? error.stack || error.message : String(error)}\n`
    );
    process.exit(1);
  });
}
