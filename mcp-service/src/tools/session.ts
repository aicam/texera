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
import { getGuiConfig, getPreLoginConfig, healthcheck } from "@texera/sdk";
import type { McpContext } from "../context";
import { formatTimestamp, joinSections } from "../format";
import { registerTool } from "../register";

export function registerSessionTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "texera_whoami",
    title: "Show the connected Texera account and deployment",
    description:
      "Report which Texera deployment this server is connected to, which account the token belongs to, " +
      "when that token expires, and which optional features the deployment has enabled. " +
      "Call this first in a conversation to confirm the connection works before attempting anything else.",
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (_args, ctx) => {
      const { config, client } = ctx;
      const claims = config.claims;

      const identity = [
        `Deployment: ${config.baseUrl}`,
        `User:       ${claims.sub ?? "unknown"} (uid ${claims.userId ?? "?"}, ${claims.email ?? "no email"})`,
        `Role:       ${claims.role ?? "unknown"}`,
        `Token:      ${config.tokenExpiresAt ? `expires ${formatTimestamp(config.tokenExpiresAt)}` : "no expiry claim"}`,
      ].join("\n");

      const reachable = await healthcheck(client);
      if (!reachable) {
        return joinSections(
          identity,
          `WARNING: ${config.baseUrl}/api/healthcheck did not respond. The deployment may be down or ` +
            `TEXERA_BASE_URL may be wrong. Tool calls will likely fail.`
        );
      }

      // Both config calls are best-effort: an older deployment may not expose
      // them, and that should degrade the report rather than fail the tool.
      const [preLogin, gui] = await Promise.all([
        getPreLoginConfig(client).catch(() => undefined),
        getGuiConfig(client).catch(() => undefined),
      ]);

      const features: string[] = [];
      if (preLogin) {
        features.push(`local login: ${preLogin.localLogin ? "on" : "off"}`);
        features.push(`Google login: ${preLogin.googleLogin ? "on" : "off"}`);
      }
      if (gui) {
        if (typeof gui.sharingComputingUnitEnabled === "boolean") {
          features.push(`computing-unit sharing: ${gui.sharingComputingUnitEnabled ? "on" : "off"}`);
        }
        if (typeof gui.exportExecutionResultEnabled === "boolean") {
          features.push(`result export: ${gui.exportExecutionResultEnabled ? "on" : "off"}`);
        }
      }

      const openSessions = ctx.sessions.list();
      const sessionLine =
        openSessions.length === 0
          ? "No workflow is currently open for editing."
          : `Open for editing: ${openSessions
              .map(session => `${session.wid} ("${session.name}")${session.dirty ? " — unsaved changes" : ""}`)
              .join(", ")}`;

      return joinSections(
        identity,
        "Connection verified (healthcheck OK).",
        features.length > 0 ? `Deployment features: ${features.join(", ")}` : undefined,
        sessionLine
      );
    },
  });
}
