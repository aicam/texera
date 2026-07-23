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

import type { TexeraClient } from "../client";

/** Anonymous deployment facts, readable before authenticating. */
export interface PreLoginConfig {
  localLogin: boolean;
  googleLogin: boolean;
  defaultLocalUser?: { username?: string; password?: string };
  attributionEnabled?: boolean;
  deploymentVersionCheckEnabled?: boolean;
  inviteOnly?: boolean;
}

/** Feature flags, readable once authenticated. Shape varies by version. */
export type GuiConfig = Record<string, unknown> & {
  sharingComputingUnitEnabled?: boolean;
  exportExecutionResultEnabled?: boolean;
  expirationTimeInMinutes?: number;
};

export async function getPreLoginConfig(client: TexeraClient): Promise<PreLoginConfig> {
  return client.request<PreLoginConfig>("config", "/api/config/pre-login", { anonymous: true });
}

export async function getGuiConfig(client: TexeraClient): Promise<GuiConfig> {
  return client.request<GuiConfig>("config", "/api/config/gui");
}

/**
 * Liveness probe used to tell "wrong URL / unreachable deployment" apart from
 * "bad credentials" before any authenticated call is attempted.
 */
export async function healthcheck(client: TexeraClient): Promise<boolean> {
  try {
    await client.requestRaw("dashboard", "/api/healthcheck", { anonymous: true, timeoutMs: 15_000 });
    return true;
  } catch {
    return false;
  }
}
