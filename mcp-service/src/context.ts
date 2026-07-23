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

import { TexeraClient, WorkflowSystemMetadata } from "@texera/sdk";
import type { McpConfig } from "./config";
import { EditSessionStore } from "./session";

/** Everything a tool handler needs, assembled once at startup. */
export interface McpContext {
  config: McpConfig;
  client: TexeraClient;
  sessions: EditSessionStore;
  /**
   * The operator catalogue, fetched on first use rather than at startup: an
   * MCP server must complete its initialize handshake promptly, and a slow or
   * unreachable deployment should surface on the tool call that needs it, not
   * as a failure to start.
   */
  operatorMetadata(): Promise<WorkflowSystemMetadata>;
}

export function createContext(config: McpConfig): McpContext {
  const client = new TexeraClient({
    baseUrl: config.baseUrl,
    token: config.token,
    defaultTimeoutMs: config.requestTimeoutMs,
  });

  const sessions = new EditSessionStore();

  let metadataPromise: Promise<WorkflowSystemMetadata> | undefined;
  const operatorMetadata = () => {
    if (!metadataPromise) {
      const store = new WorkflowSystemMetadata();
      metadataPromise = store.initializeFromBackend(client).then(
        () => store,
        error => {
          // Clear the memo so a later call can retry; caching a rejection
          // would make one transient blip poison the whole session.
          metadataPromise = undefined;
          throw error;
        }
      );
    }
    return metadataPromise;
  };

  return { config, client, sessions, operatorMetadata };
}
