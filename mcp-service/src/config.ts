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

import { decodeJwtClaims, tokenExpiresAt, type TexeraJwtClaims } from "@texera/sdk";

/**
 * The MCP server is configured entirely from the environment, because that is
 * the only channel an MCP client config (`mcpServers.texera.env`) offers.
 */
export interface McpConfig {
  /** Deployment origin, e.g. `https://texera.dknet-ai.org`. */
  baseUrl: string;
  token: string;
  claims: TexeraJwtClaims;
  /** Epoch ms, or undefined for a token without `exp`. */
  tokenExpiresAt?: number;
  /** Ceiling on characters returned by a single tool result. */
  maxResultChars: number;
  /** Ceiling on a single `dataset_upload_file` payload. */
  maxUploadBytes: number;
  /** Default wall-clock budget for `workflow_run`. */
  defaultRunTimeoutSeconds: number;
  requestTimeoutMs: number;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const DEFAULTS = {
  maxResultChars: 40_000,
  maxUploadBytes: 25 * 1024 * 1024,
  defaultRunTimeoutSeconds: 120,
  requestTimeoutMs: 60_000,
};

function parsePositiveInt(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0 || !Number.isInteger(value)) {
    throw new ConfigError(`${name} must be a positive integer, got "${raw}"`);
  }
  return value;
}

/**
 * Rejects anything that is not an absolute http(s) URL. A bare hostname or a
 * `ws://` URL would otherwise fail much later with an unhelpful message.
 */
function parseBaseUrl(raw: string | undefined): string {
  if (!raw || raw.trim() === "") {
    throw new ConfigError(
      "TEXERA_BASE_URL is required — the origin of your Texera deployment, " +
        'e.g. "https://texera.dknet-ai.org" or "http://localhost:8080".'
    );
  }
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ConfigError(`TEXERA_BASE_URL is not a valid URL: "${raw}"`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ConfigError(`TEXERA_BASE_URL must be http(s), got "${url.protocol}//" in "${raw}"`);
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

/** Where to get a fresh token. Repeated in every auth-related message. */
export function tokenHelp(baseUrl: string): string {
  return (
    `Get a fresh token: sign in at ${baseUrl}, open your browser's developer console on that page, ` +
    `run localStorage.getItem("access_token"), and set the value as TEXERA_TOKEN in your MCP client config.`
  );
}

export function loadConfig(env: Record<string, string | undefined> = process.env): McpConfig {
  const baseUrl = parseBaseUrl(env.TEXERA_BASE_URL);

  const token = env.TEXERA_TOKEN?.trim();
  if (!token) {
    throw new ConfigError(`TEXERA_TOKEN is required. ${tokenHelp(baseUrl)}`);
  }

  let claims: TexeraJwtClaims;
  try {
    claims = decodeJwtClaims(token);
  } catch (error) {
    throw new ConfigError(
      `TEXERA_TOKEN is not a valid JWT (${error instanceof Error ? error.message : String(error)}). ` +
        `${tokenHelp(baseUrl)}`
    );
  }

  // Fail at startup rather than on the first tool call: an expired token is a
  // config problem the user must fix, and a clear message here beats an
  // opaque 401 in the middle of a conversation.
  const expiresAt = tokenExpiresAt(token);
  if (expiresAt !== undefined && Date.now() >= expiresAt) {
    throw new ConfigError(`TEXERA_TOKEN expired on ${new Date(expiresAt).toISOString()}. ${tokenHelp(baseUrl)}`);
  }

  return {
    baseUrl,
    token,
    claims,
    tokenExpiresAt: expiresAt,
    maxResultChars: parsePositiveInt(env.TEXERA_MAX_RESULT_CHARS, DEFAULTS.maxResultChars, "TEXERA_MAX_RESULT_CHARS"),
    maxUploadBytes: parsePositiveInt(env.TEXERA_MAX_UPLOAD_BYTES, DEFAULTS.maxUploadBytes, "TEXERA_MAX_UPLOAD_BYTES"),
    defaultRunTimeoutSeconds: parsePositiveInt(
      env.TEXERA_RUN_TIMEOUT_SECONDS,
      DEFAULTS.defaultRunTimeoutSeconds,
      "TEXERA_RUN_TIMEOUT_SECONDS"
    ),
    requestTimeoutMs: parsePositiveInt(
      env.TEXERA_REQUEST_TIMEOUT_MS,
      DEFAULTS.requestTimeoutMs,
      "TEXERA_REQUEST_TIMEOUT_MS"
    ),
  };
}

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

/**
 * A warning to append to tool results while the token is close to expiring, so
 * the user learns about it before a conversation breaks mid-task. Returns
 * undefined when there is nothing worth saying.
 */
export function tokenExpiryWarning(config: McpConfig, now: number = Date.now()): string | undefined {
  if (config.tokenExpiresAt === undefined) return undefined;
  const remainingMs = config.tokenExpiresAt - now;
  if (remainingMs > ONE_DAY_MS) return undefined;
  if (remainingMs <= 0) return `Your Texera token has expired. ${tokenHelp(config.baseUrl)}`;
  const hours = Math.max(1, Math.round(remainingMs / (60 * 60 * 1000)));
  return `Heads up: your Texera token expires in about ${hours} hour${hours === 1 ? "" : "s"}. ${tokenHelp(config.baseUrl)}`;
}
