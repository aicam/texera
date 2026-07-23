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

import { describe, expect, mock, test } from "bun:test";
import { TexeraApiError, TexeraClient, TexeraConnectionError, normalizeBaseUrl, parseAuthErrorCode } from "./client";

type FetchMock = ReturnType<typeof mock>;

function capturingClient(response: () => Response | Promise<Response>, options: Record<string, unknown> = {}) {
  const fetchMock = mock(async () => response());
  const client = new TexeraClient({
    baseUrl: "https://texera.example.org",
    token: "tok",
    fetch: fetchMock as unknown as typeof fetch,
    ...options,
  });
  return { client, fetchMock: fetchMock as FetchMock };
}

function lastCall(fetchMock: FetchMock): [string, RequestInit] {
  return fetchMock.mock.calls[fetchMock.mock.calls.length - 1] as unknown as [string, RequestInit];
}

describe("normalizeBaseUrl", () => {
  test("strips trailing slashes", () => {
    expect(normalizeBaseUrl("https://a.example.org/")).toBe("https://a.example.org");
    expect(normalizeBaseUrl("https://a.example.org///")).toBe("https://a.example.org");
  });

  test("leaves a clean url untouched", () => {
    expect(normalizeBaseUrl("https://a.example.org")).toBe("https://a.example.org");
  });
});

describe("parseAuthErrorCode", () => {
  test("extracts the RFC 6750 error parameter", () => {
    expect(parseAuthErrorCode('Bearer realm="texera", error="invalid_token"')).toBe("invalid_token");
  });

  test("returns undefined for a bare challenge or a missing header", () => {
    expect(parseAuthErrorCode('Bearer realm="texera"')).toBeUndefined();
    expect(parseAuthErrorCode(null)).toBeUndefined();
  });
});

describe("TexeraClient endpoint resolution", () => {
  test("defaults every area to baseUrl", () => {
    const client = new TexeraClient({ baseUrl: "https://texera.example.org/" });
    expect(client.endpoints.dashboard).toBe("https://texera.example.org");
    expect(client.endpoints.file).toBe("https://texera.example.org");
    expect(client.endpoints.compile).toBe("https://texera.example.org");
  });

  test("per-area overrides win over baseUrl", () => {
    const client = new TexeraClient({
      baseUrl: "http://localhost:8080",
      endpoints: { compile: "http://localhost:9090/" },
    });
    expect(client.endpoints.compile).toBe("http://localhost:9090");
    expect(client.endpoints.dashboard).toBe("http://localhost:8080");
  });

  test("throws when an area has no endpoint at all", () => {
    expect(() => new TexeraClient({ endpoints: { compile: "http://localhost:9090" } })).toThrow(
      /no endpoint for "dashboard"/
    );
  });

  test("executionEndpointFor substitutes {cuid} when a template is configured", () => {
    const templated = new TexeraClient({
      baseUrl: "https://texera.example.org",
      executionEndpointTemplate: "http://cu-{cuid}.svc:8085/",
    });
    expect(templated.executionEndpointFor(7)).toBe("http://cu-7.svc:8085");
  });

  test("executionEndpointFor falls back to the execution endpoint without a template", () => {
    const plain = new TexeraClient({ baseUrl: "https://texera.example.org" });
    expect(plain.executionEndpointFor(7)).toBe("https://texera.example.org");
  });
});

describe("TexeraClient.request", () => {
  test("sends the bearer token and parses JSON", async () => {
    const { client, fetchMock } = capturingClient(() => new Response(JSON.stringify({ ok: 1 }), { status: 200 }));

    const body = await client.request<{ ok: number }>("dashboard", "/api/workflow/list");

    expect(body).toEqual({ ok: 1 });
    const [url, init] = lastCall(fetchMock);
    expect(url).toBe("https://texera.example.org/api/workflow/list");
    expect(new Headers(init.headers).get("Authorization")).toBe("Bearer tok");
  });

  test("omits the Authorization header for anonymous requests", async () => {
    const { client, fetchMock } = capturingClient(() => new Response("{}", { status: 200 }));

    await client.request("config", "/api/config/pre-login", { anonymous: true });

    expect(new Headers(lastCall(fetchMock)[1].headers).has("Authorization")).toBe(false);
  });

  test("serializes `json` and sets the content type", async () => {
    const { client, fetchMock } = capturingClient(() => new Response("{}", { status: 200 }));

    await client.request("dashboard", "/api/workflow/create", { method: "POST", json: { name: "w" } });

    const [, init] = lastCall(fetchMock);
    expect(init.body).toBe('{"name":"w"}');
    expect(new Headers(init.headers).get("Content-Type")).toBe("application/json");
  });

  test("appends query params and drops undefined/null ones", async () => {
    const { client, fetchMock } = capturingClient(() => new Response("{}", { status: 200 }));

    await client.request("file", "/api/dataset/presign-download", {
      query: { filePath: "a b/c.csv", commitHash: undefined, repositoryName: null },
    });

    const [url] = lastCall(fetchMock);
    expect(url).toContain("filePath=a+b%2Fc.csv");
    expect(url).not.toContain("commitHash");
    expect(url).not.toContain("repositoryName");
  });

  test("returns undefined for 204 and for an empty body", async () => {
    const { client } = capturingClient(() => new Response(null, { status: 204 }));
    expect(await client.request("dashboard", "/api/workflow/delete", { method: "POST" })).toBeUndefined();

    const { client: emptyClient } = capturingClient(() => new Response("", { status: 200 }));
    expect(await emptyClient.request("dashboard", "/api/workflow/update/name", { method: "POST" })).toBeUndefined();
  });

  test("returns the raw text when the body is not JSON", async () => {
    const { client } = capturingClient(() => new Response("alice@example.com", { status: 200 }));
    expect(await client.request<string>("dashboard", "/api/access/workflow/owner/1")).toBe("alice@example.com");
  });

  test("throws TexeraApiError carrying status and body on a non-2xx", async () => {
    const { client } = capturingClient(() => new Response("No sufficient access privilege.", { status: 403 }));

    const error = (await client.request("dashboard", "/api/workflow/9").catch(e => e)) as TexeraApiError;

    expect(error).toBeInstanceOf(TexeraApiError);
    expect(error.status).toBe(403);
    expect(error.isForbidden).toBe(true);
    expect(error.isAuthError).toBe(false);
    expect(error.body).toBe("No sufficient access privilege.");
    expect(error.message).toContain("No sufficient access privilege.");
  });

  test("flags an expired token distinctly from missing credentials", async () => {
    const { client: expiredClient } = capturingClient(
      () =>
        new Response("", {
          status: 401,
          headers: { "WWW-Authenticate": 'Bearer realm="texera", error="invalid_token"' },
        })
    );
    const expired = (await expiredClient.request("dashboard", "/api/workflow/list").catch(e => e)) as TexeraApiError;
    expect(expired.isExpiredOrInvalidToken).toBe(true);

    const { client: missingClient } = capturingClient(
      () => new Response("", { status: 401, headers: { "WWW-Authenticate": 'Bearer realm="texera"' } })
    );
    const missing = (await missingClient.request("dashboard", "/api/workflow/list").catch(e => e)) as TexeraApiError;
    expect(missing.isAuthError).toBe(true);
    expect(missing.isExpiredOrInvalidToken).toBe(false);
  });

  test("truncates a huge error body in the message", async () => {
    const { client } = capturingClient(() => new Response("x".repeat(2000), { status: 500 }));
    const error = (await client.request("dashboard", "/api/workflow/list").catch(e => e)) as TexeraApiError;
    expect(error.message).toContain("2000 chars total");
    expect(error.message.length).toBeLessThan(700);
    // The untruncated body stays available for callers that want it.
    expect(error.body.length).toBe(2000);
  });

  test("wraps a transport failure in TexeraConnectionError", async () => {
    const fetchMock = mock(async () => {
      throw new TypeError("fetch failed");
    });
    const client = new TexeraClient({
      baseUrl: "https://texera.example.org",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const error = (await client.request("dashboard", "/api/healthcheck").catch(e => e)) as TexeraConnectionError;

    expect(error).toBeInstanceOf(TexeraConnectionError);
    expect(error.message).toContain("fetch failed");
    expect(error.url).toBe("https://texera.example.org/api/healthcheck");
  });

  test("reports a timeout as such rather than as an opaque abort", async () => {
    const fetchMock = mock(async () => {
      const timeout = new Error("The operation timed out.");
      timeout.name = "TimeoutError";
      throw timeout;
    });
    const client = new TexeraClient({
      baseUrl: "https://texera.example.org",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const error = (await client.request("dashboard", "/api/healthcheck").catch(e => e)) as TexeraConnectionError;
    expect(error.message).toContain("request timed out");
  });
});

describe("TexeraClient token handling", () => {
  test("withToken leaves the original client's token alone", async () => {
    const { client, fetchMock } = capturingClient(() => new Response("{}", { status: 200 }));
    const other = client.withToken("other-token");

    await other.request("dashboard", "/api/workflow/list");
    expect(new Headers(lastCall(fetchMock)[1].headers).get("Authorization")).toBe("Bearer other-token");

    await client.request("dashboard", "/api/workflow/list");
    expect(new Headers(lastCall(fetchMock)[1].headers).get("Authorization")).toBe("Bearer tok");
  });

  test("a client with no token sends no Authorization header", async () => {
    const fetchMock = mock(async () => new Response("{}", { status: 200 }));
    const client = new TexeraClient({
      baseUrl: "https://texera.example.org",
      fetch: fetchMock as unknown as typeof fetch,
    });

    await client.request("dashboard", "/api/resources/operator-metadata");

    expect(new Headers(lastCall(fetchMock as FetchMock)[1].headers).has("Authorization")).toBe(false);
  });
});

describe("TexeraClient cancellation", () => {
  test("re-throws an AbortError instead of wrapping it as a connection failure", async () => {
    const abortError = new Error("aborted");
    abortError.name = "AbortError";
    const fetchMock = mock(async () => {
      throw abortError;
    });
    const client = new TexeraClient({
      baseUrl: "https://texera.example.org",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const error = await client
      .request("execution", "/api/execution/1/0/run", { signal: new AbortController().signal })
      .catch(e => e);

    expect(error).toBe(abortError);
    expect(error).not.toBeInstanceOf(TexeraConnectionError);
  });
});
