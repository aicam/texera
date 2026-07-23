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

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ZodRawShape } from "zod";
import { tokenExpiryWarning } from "./config";
import type { McpContext } from "./context";
import { describeError } from "./errors";
import { joinSections, truncate } from "./format";

export interface ToolDefinition<Args extends ZodRawShape> {
  name: string;
  title: string;
  description: string;
  inputSchema?: Args;
  /**
   * MCP tool annotations. `readOnlyHint` lets a client auto-approve a tool;
   * `destructiveHint` makes it ask. Getting these right is the difference
   * between a usable server and one the user has to babysit.
   */
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
  handler: (args: any, context: McpContext) => Promise<string>;
}

/**
 * Wraps a handler with the concerns every tool shares: error translation,
 * result-size capping and the token-expiry nudge.
 *
 * Failures come back as `isError` results rather than protocol errors on
 * purpose — the model should see "access denied, ask the owner to share it"
 * and adapt, not have the call disappear into a transport-level error.
 */
export function registerTool<Args extends ZodRawShape>(
  server: McpServer,
  context: McpContext,
  definition: ToolDefinition<Args>
): void {
  server.registerTool(
    definition.name,
    {
      title: definition.title,
      description: definition.description,
      inputSchema: definition.inputSchema,
      annotations: { openWorldHint: true, ...definition.annotations },
    },
    (async (args: unknown): Promise<CallToolResult> => {
      try {
        const text = await definition.handler(args ?? {}, context);
        return {
          content: [
            {
              type: "text",
              text: joinSections(truncate(text, context.config.maxResultChars), tokenExpiryWarning(context.config)),
            },
          ],
        };
      } catch (error) {
        return {
          isError: true,
          content: [{ type: "text", text: describeError(error, context.config, definition.name) }],
        };
      }
    }) as never
  );
}
