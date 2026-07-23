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

/**
 * A stand-in for a Texera deployment, driven by route patterns.
 *
 * Tests assert against real HTTP semantics (status codes, `WWW-Authenticate`
 * challenges, JSON envelopes) rather than stubbing the SDK, so the error
 * translation and request shaping in the MCP layer are actually exercised.
 */

export interface RecordedRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body?: string;
}

type Handler = (request: RecordedRequest) => Response | Promise<Response>;

export interface Route {
  method: string;
  /** Path with `:param` placeholders, e.g. `/api/dataset/:did/upload`. */
  path: string;
  handler: Handler;
}

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

export function text(body: string, status = 200): Response {
  return new Response(body, { status });
}

export function unauthorized(invalidToken = true): Response {
  return new Response("", {
    status: 401,
    headers: {
      "WWW-Authenticate": invalidToken ? 'Bearer realm="texera", error="invalid_token"' : 'Bearer realm="texera"',
    },
  });
}

export class FakeTexera {
  readonly requests: RecordedRequest[] = [];
  private routes: Route[] = [];

  constructor(readonly origin = "https://texera.test") {}

  /** Re-registering a method+path replaces the handler, so a test can override a default. */
  on(method: string, path: string, handler: Handler): this {
    const route = { method: method.toUpperCase(), path, handler };
    const existing = this.routes.findIndex(candidate => candidate.method === route.method && candidate.path === path);
    if (existing >= 0) this.routes[existing] = route;
    else this.routes.push(route);
    return this;
  }

  get(path: string, handler: Handler): this {
    return this.on("GET", path, handler);
  }

  post(path: string, handler: Handler): this {
    return this.on("POST", path, handler);
  }

  put(path: string, handler: Handler): this {
    return this.on("PUT", path, handler);
  }

  delete(path: string, handler: Handler): this {
    return this.on("DELETE", path, handler);
  }

  /** Requests recorded for a route pattern, for asserting what was actually sent. */
  recorded(method: string, pathPattern: string): RecordedRequest[] {
    return this.requests.filter(
      request => request.method === method.toUpperCase() && matchPath(pathPattern, request.path) !== undefined
    );
  }

  /** A `fetch` implementation to install as `globalThis.fetch`. */
  get fetch(): typeof fetch {
    return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      const method = (init?.method ?? "GET").toUpperCase();
      const recorded: RecordedRequest = {
        method,
        path: url.pathname,
        query: url.searchParams,
        headers: new Headers(init?.headers as HeadersInit | undefined),
        body: typeof init?.body === "string" ? init.body : undefined,
      };
      this.requests.push(recorded);

      // Presigned download URLs point at object storage, not at Texera.
      if (url.origin !== this.origin && !url.pathname.startsWith("/presigned/")) {
        return text(`fake-texera: unexpected origin ${url.origin}`, 502);
      }

      // Most-literal route wins, so `/api/dataset/presign-download` is not
      // swallowed by `/api/dataset/:did` just because that was registered first.
      const candidates = this.routes
        .filter(route => route.method === method)
        .map(route => ({ route, params: matchPath(route.path, url.pathname) }))
        .filter(
          (candidate): candidate is { route: Route; params: Record<string, string> } => candidate.params !== undefined
        )
        .sort((a, b) => literalSegments(b.route.path) - literalSegments(a.route.path));

      const best = candidates[0];
      if (best) {
        return best.route.handler({
          ...recorded,
          query: new URLSearchParams([...url.searchParams, ...toEntries(best.params)]),
        });
      }

      return text(`fake-texera: no route for ${method} ${url.pathname}`, 404);
    }) as typeof fetch;
  }
}

function toEntries(params: Record<string, string>): [string, string][] {
  return Object.entries(params);
}

function literalSegments(pattern: string): number {
  return pattern.split("/").filter(part => part && !part.startsWith(":")).length;
}

/** Returns the captured `:param` values, or undefined when the path does not match. */
function matchPath(pattern: string, path: string): Record<string, string> | undefined {
  const patternParts = pattern.split("/").filter(Boolean);
  const pathParts = path.split("/").filter(Boolean);
  if (patternParts.length !== pathParts.length) return undefined;

  const params: Record<string, string> = {};
  for (const [index, patternPart] of patternParts.entries()) {
    if (patternPart.startsWith(":")) {
      params[patternPart.slice(1)] = decodeURIComponent(pathParts[index]);
    } else if (patternPart !== pathParts[index]) {
      return undefined;
    }
  }
  return params;
}
