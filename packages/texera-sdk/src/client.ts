/*
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

import { createSdkLogger } from "./logger";

const log = createSdkLogger("TexeraClient");

/**
 * Texera splits its REST surface across several services. A Kubernetes/Helm
 * deployment fronts all of them behind one Gateway hostname (see
 * `bin/k8s/templates/base/gateway/gateway-routes.yaml`), so a single `baseUrl`
 * is enough. A `bin/local-dev.sh` stack runs them on separate localhost ports,
 * so each area can be overridden individually.
 */
export interface TexeraEndpoints {
  /** webserver: /api/auth, /api/workflow, /api/version, /api/resources, /api/executions */
  dashboard: string;
  /** workflow-compiling-service: /api/compile */
  compile: string;
  /** sync execution: /api/execution/{wid}/{cuid}/run */
  execution: string;
  /** file-service: /api/dataset, /api/access/dataset */
  file: string;
  /** computing-unit-managing-service: /api/computing-unit, /api/access/computing-unit */
  computingUnit: string;
  /** config-service: /api/config */
  config: string;
}

export type TexeraServiceArea = keyof TexeraEndpoints;

export interface TexeraClientOptions {
  /** Deployment origin, e.g. `https://texera.dknet-ai.org`. Used for every area not overridden. */
  baseUrl?: string;
  /** Per-area overrides. Required for any area when `baseUrl` is absent. */
  endpoints?: Partial<TexeraEndpoints>;
  /** Bearer JWT sent on every request. */
  token?: string;
  /**
   * Per-computing-unit execution endpoint, with `{cuid}` substituted at call
   * time. On Kubernetes each computing unit is its own pod, so the sync
   * execution endpoint is not a fixed host.
   */
  executionEndpointTemplate?: string;
  /** Default per-request timeout. 0 disables. */
  defaultTimeoutMs?: number;
  /** Injectable for tests. Defaults to the global `fetch`. */
  fetch?: typeof fetch;
}

export interface TexeraRequestInit extends Omit<RequestInit, "signal"> {
  /** Appended as a query string; `undefined`/`null` values are dropped. */
  query?: Record<string, string | number | boolean | undefined | null>;
  /** JSON-serialized into the body with the matching Content-Type. Mutually exclusive with `body`. */
  json?: unknown;
  /** Overrides {@link TexeraClientOptions.defaultTimeoutMs} for this call. */
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Suppresses the Authorization header (public endpoints, e.g. /api/config/pre-login). */
  anonymous?: boolean;
}

/**
 * A non-2xx response from a Texera service.
 *
 * `authErrorCode` carries the RFC 6750 `error` parameter that `JwtAuthFilter`
 * puts in `WWW-Authenticate`: `invalid_token` means "this token is expired or
 * tampered with — discard it", while a bare challenge means "you sent no
 * credentials". Callers need to distinguish the two to give the user an
 * actionable message.
 */
export class TexeraApiError extends Error {
  constructor(
    readonly status: number,
    readonly statusText: string,
    readonly method: string,
    readonly url: string,
    readonly body: string,
    readonly authErrorCode?: string
  ) {
    super(`${method} ${url} failed: ${status} ${statusText}${body ? ` - ${truncate(body, 500)}` : ""}`);
    this.name = "TexeraApiError";
  }

  /** The request was rejected for lack of valid credentials. */
  get isAuthError(): boolean {
    return this.status === 401;
  }

  /** The credentials were understood but do not grant access to this resource. */
  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }

  /** The token itself is bad (expired/tampered), as opposed to simply missing. */
  get isExpiredOrInvalidToken(): boolean {
    return this.status === 401 && this.authErrorCode === "invalid_token";
  }
}

/** The request never reached the deployment (DNS, TLS, connection refused, timeout). */
export class TexeraConnectionError extends Error {
  constructor(
    readonly method: string,
    readonly url: string,
    override readonly cause: unknown
  ) {
    super(`${method} ${url} failed: ${describeCause(cause)}`);
    this.name = "TexeraConnectionError";
  }
}

function describeCause(cause: unknown): string {
  if (cause instanceof Error) {
    return cause.name === "TimeoutError" || cause.name === "AbortError" ? "request timed out" : cause.message;
  }
  return String(cause);
}

function truncate(text: string, limit: number): string {
  return text.length <= limit ? text : `${text.slice(0, limit)}… (${text.length} chars total)`;
}

/** Strips a trailing slash so `${base}${path}` never doubles up. */
export function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

/**
 * Parses the RFC 6750 `error` parameter out of a `WWW-Authenticate` challenge,
 * e.g. `Bearer realm="texera", error="invalid_token"` -> `invalid_token`.
 */
export function parseAuthErrorCode(wwwAuthenticate: string | null): string | undefined {
  if (!wwwAuthenticate) return undefined;
  return /error\s*=\s*"([^"]*)"/i.exec(wwwAuthenticate)?.[1];
}

export class TexeraClient {
  readonly endpoints: TexeraEndpoints;
  readonly executionEndpointTemplate?: string;
  private readonly defaultTimeoutMs: number;
  private readonly fetchImpl?: typeof fetch;
  private token?: string;

  constructor(options: TexeraClientOptions) {
    const base = options.baseUrl ? normalizeBaseUrl(options.baseUrl) : undefined;
    const overrides = options.endpoints ?? {};
    const areas: TexeraServiceArea[] = ["dashboard", "compile", "execution", "file", "computingUnit", "config"];

    const resolved = {} as TexeraEndpoints;
    for (const area of areas) {
      const endpoint = overrides[area] ?? base;
      if (!endpoint) {
        throw new Error(`TexeraClient: no endpoint for "${area}" — provide baseUrl or endpoints.${area}`);
      }
      resolved[area] = normalizeBaseUrl(endpoint);
    }

    this.endpoints = resolved;
    this.executionEndpointTemplate = options.executionEndpointTemplate;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 60_000;
    // Stored only when explicitly injected; otherwise `globalThis.fetch` is
    // resolved per call. Capturing it here would freeze the reference at
    // construction time and defeat any later instrumentation or test double —
    // and this client is typically a module-level singleton built at import.
    this.fetchImpl = options.fetch;
    this.token = options.token;
  }

  getToken(): string | undefined {
    return this.token;
  }

  setToken(token: string | undefined): void {
    this.token = token;
  }

  /** A copy of this client authenticating as a different user. Endpoints and fetch are shared. */
  withToken(token: string | undefined): TexeraClient {
    const clone = Object.create(TexeraClient.prototype) as TexeraClient;
    Object.assign(clone, this);
    clone.setToken(token);
    return clone;
  }

  /**
   * Resolves the sync-execution origin for a computing unit. On Kubernetes each
   * unit is a separate pod, so the endpoint is templated per `cuid`.
   */
  executionEndpointFor(computingUnitId: number): string {
    return this.executionEndpointTemplate
      ? normalizeBaseUrl(this.executionEndpointTemplate.replace("{cuid}", String(computingUnitId)))
      : this.endpoints.execution;
  }

  buildUrl(area: TexeraServiceArea, path: string, query?: TexeraRequestInit["query"], originOverride?: string): string {
    const origin = originOverride ? normalizeBaseUrl(originOverride) : this.endpoints[area];
    const url = new URL(`${origin}${path.startsWith("/") ? path : `/${path}`}`);
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
    }
    return url.toString();
  }

  /** Issues a request and returns the raw {@link Response}. Non-2xx throws {@link TexeraApiError}. */
  async requestRaw(
    area: TexeraServiceArea,
    path: string,
    init: TexeraRequestInit & { originOverride?: string } = {}
  ): Promise<Response> {
    const { query, json, timeoutMs, anonymous, originOverride, headers, ...rest } = init;
    const url = this.buildUrl(area, path, query, originOverride);
    const method = rest.method ?? "GET";

    const mergedHeaders = new Headers(headers as HeadersInit | undefined);
    if (!anonymous && this.token) mergedHeaders.set("Authorization", `Bearer ${this.token}`);
    if (json !== undefined && !mergedHeaders.has("Content-Type")) {
      mergedHeaders.set("Content-Type", "application/json");
    }

    const effectiveTimeout = timeoutMs ?? this.defaultTimeoutMs;
    const signal = init.signal ?? (effectiveTimeout > 0 ? AbortSignal.timeout(effectiveTimeout) : undefined);

    log.debug({ method, url }, "texera request");

    // Bound so implementations that check the receiver (undici, bun) don't see
    // the client as `this`.
    const fetchImpl = (this.fetchImpl ?? globalThis.fetch).bind(globalThis);

    let response: Response;
    try {
      response = await fetchImpl(url, {
        ...rest,
        headers: mergedHeaders,
        body: json !== undefined ? JSON.stringify(json) : rest.body,
        signal,
      });
    } catch (error) {
      // A cancellation is not a connection failure — the caller needs to tell
      // "I aborted this" apart from "the network broke", so an AbortError
      // propagates untouched. The client's own deadline is distinguishable:
      // `AbortSignal.timeout` rejects with a *TimeoutError*, which still
      // becomes a TexeraConnectionError below.
      if (error instanceof Error && error.name === "AbortError") throw error;
      throw new TexeraConnectionError(method, url, error);
    }

    if (!response.ok) {
      // Read the body before throwing: it usually carries the backend's own
      // message, which is far more useful than the status line alone.
      const body = await response.text().catch(() => "");
      throw new TexeraApiError(
        response.status,
        response.statusText,
        method,
        url,
        body,
        parseAuthErrorCode(response.headers.get("WWW-Authenticate"))
      );
    }

    return response;
  }

  /** Issues a request and parses a JSON body. `204`/empty bodies resolve to `undefined`. */
  async request<T>(
    area: TexeraServiceArea,
    path: string,
    init: TexeraRequestInit & { originOverride?: string } = {}
  ): Promise<T> {
    const response = await this.requestRaw(area, path, init);
    if (response.status === 204) return undefined as T;
    const text = await response.text();
    if (text.length === 0) return undefined as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      // Some endpoints (e.g. /api/workflow/owner_name) return bare strings.
      return text as unknown as T;
    }
  }
}
