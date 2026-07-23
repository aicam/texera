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

import { TexeraApiError, TexeraConnectionError } from "@texera/sdk";
import { tokenHelp, type McpConfig } from "./config";

/**
 * A failure the model should read and act on, rather than a bug. Tool handlers
 * throw this and the registry turns it into an `isError` result.
 */
export class ToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolError";
  }
}

/**
 * Translates a backend failure into something a model can act on.
 *
 * Raw statuses are close to useless in a chat transcript — "403" does not say
 * whether to retry, ask the user for something, or give up. Each case here
 * names the cause *and* the next move.
 */
export function describeError(error: unknown, config: McpConfig, context: string): string {
  if (error instanceof ToolError) return error.message;

  if (error instanceof TexeraApiError) {
    if (error.isAuthError) {
      // Two signals, because neither alone is reliable. The RFC 6750
      // `error="invalid_token"` parameter is only emitted by newer
      // deployments — an older one answers with a bare `Bearer realm="…"`
      // challenge for an expired token just as it does for a missing one. So
      // fall back to the token's own `exp`, which we can read locally.
      const tokenLooksExpired = config.tokenExpiresAt !== undefined && Date.now() >= config.tokenExpiresAt;
      if (error.isExpiredOrInvalidToken || tokenLooksExpired) {
        return `${context}: your Texera token is expired or invalid. ${tokenHelp(config.baseUrl)}`;
      }
      return (
        `${context}: the deployment rejected the request as unauthenticated. The token may be for a ` +
        `different deployment, or may have been revoked. ${tokenHelp(config.baseUrl)}`
      );
    }
    if (error.isForbidden) {
      return (
        `${context}: access denied. You may not have write access to this resource, or it belongs to ` +
        `another user. ${detail(error)}`
      );
    }
    if (error.isNotFound) {
      return `${context}: not found. It may have been deleted, or the id may be wrong. ${detail(error)}`;
    }
    if (error.status === 400) {
      return `${context}: the deployment rejected the request as invalid. ${detail(error)}`;
    }
    return `${context}: the deployment returned ${error.status} ${error.statusText}. ${detail(error)}`;
  }

  if (error instanceof TexeraConnectionError) {
    return (
      `${context}: could not reach ${config.baseUrl} (${describeCause(error)}). ` +
      `Check that TEXERA_BASE_URL is correct and the deployment is up.`
    );
  }

  return `${context}: ${error instanceof Error ? error.message : String(error)}`;
}

function detail(error: TexeraApiError): string {
  const body = error.body.trim();
  if (!body) return "";
  // Backend errors arrive either as plain text or as a JSON envelope; surface
  // the human-readable part of both.
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    const message = parsed.message ?? parsed.error ?? parsed.errorMessage;
    if (typeof message === "string" && message.trim()) return `Server said: ${message.trim()}`;
  } catch {
    /* not JSON — fall through to the raw text */
  }
  return `Server said: ${body.length > 400 ? `${body.slice(0, 400)}…` : body}`;
}

function describeCause(error: TexeraConnectionError): string {
  return error.cause instanceof Error ? error.cause.message : String(error.cause);
}
