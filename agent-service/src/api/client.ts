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

import { TexeraClient, setSdkLoggerFactory } from "@texera/sdk";
import { env } from "../config/env";
import { createLogger } from "../logger";

// Route the SDK's logging into this service's pino tree, so SDK lines carry the
// same structured fields as everything else.
setSdkLoggerFactory(module => createLogger(module));

/**
 * Anonymous client for this deployment. Endpoints are per-area because a
 * `bin/local-dev.sh` stack runs each service on its own localhost port; in a
 * Helm deployment they all resolve to the same gateway host.
 *
 * Requests made on behalf of a user must go through `texeraClient.withToken`
 * — this instance deliberately holds no token so a missing one fails loudly
 * rather than silently acting as someone else.
 */
export const texeraClient = new TexeraClient({
  endpoints: {
    dashboard: env.TEXERA_DASHBOARD_SERVICE_ENDPOINT,
    compile: env.WORKFLOW_COMPILING_SERVICE_ENDPOINT,
    execution: env.WORKFLOW_EXECUTION_SERVICE_ENDPOINT,
    file: env.TEXERA_DASHBOARD_SERVICE_ENDPOINT,
    computingUnit: env.TEXERA_DASHBOARD_SERVICE_ENDPOINT,
    config: env.TEXERA_DASHBOARD_SERVICE_ENDPOINT,
  },
  executionEndpointTemplate: env.EXECUTION_ENDPOINT_TEMPLATE,
});

/** A client authenticating as the holder of `token`. */
export function userClient(token: string): TexeraClient {
  return texeraClient.withToken(token);
}
