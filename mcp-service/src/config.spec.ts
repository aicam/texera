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

import { describe, expect, test } from "bun:test";
import { ConfigError, loadConfig, tokenExpiryWarning } from "./config";
import { makeToken } from "./testing/token";

const validEnv = (overrides: Record<string, string | undefined> = {}) => ({
  TEXERA_BASE_URL: "https://texera.example.org",
  TEXERA_TOKEN: makeToken(),
  ...overrides,
});

describe("loadConfig — accepted input", () => {
  test("reads base url, token and claims", () => {
    const config = loadConfig(validEnv());
    expect(config.baseUrl).toBe("https://texera.example.org");
    expect(config.claims.sub).toBe("alice");
    expect(config.claims.userId).toBe(7);
    expect(config.claims.email).toBe("alice@example.org");
  });

  test("strips a trailing slash and any query/hash from the base url", () => {
    expect(loadConfig(validEnv({ TEXERA_BASE_URL: "https://texera.example.org/" })).baseUrl).toBe(
      "https://texera.example.org"
    );
    expect(loadConfig(validEnv({ TEXERA_BASE_URL: "https://texera.example.org/?x=1#y" })).baseUrl).toBe(
      "https://texera.example.org"
    );
  });

  test("keeps a path prefix, for deployments served under a sub-path", () => {
    expect(loadConfig(validEnv({ TEXERA_BASE_URL: "https://example.org/texera/" })).baseUrl).toBe(
      "https://example.org/texera"
    );
  });

  test("accepts a plain http localhost deployment", () => {
    expect(loadConfig(validEnv({ TEXERA_BASE_URL: "http://localhost:8080" })).baseUrl).toBe("http://localhost:8080");
  });

  test("tolerates surrounding whitespace in the token", () => {
    const token = makeToken();
    expect(loadConfig(validEnv({ TEXERA_TOKEN: `  ${token}  ` })).token).toBe(token);
  });

  test("applies documented defaults", () => {
    const config = loadConfig(validEnv());
    expect(config.maxResultChars).toBe(40_000);
    expect(config.maxUploadBytes).toBe(25 * 1024 * 1024);
    expect(config.defaultRunTimeoutSeconds).toBe(120);
  });

  test("honours numeric overrides", () => {
    const config = loadConfig(validEnv({ TEXERA_MAX_RESULT_CHARS: "1000", TEXERA_RUN_TIMEOUT_SECONDS: "30" }));
    expect(config.maxResultChars).toBe(1000);
    expect(config.defaultRunTimeoutSeconds).toBe(30);
  });

  test("accepts a token with no exp claim", () => {
    const config = loadConfig(validEnv({ TEXERA_TOKEN: makeToken({ exp: undefined }) }));
    expect(config.tokenExpiresAt).toBeUndefined();
  });
});

describe("loadConfig — rejected input", () => {
  test("missing base url names the variable and gives an example", () => {
    expect(() => loadConfig(validEnv({ TEXERA_BASE_URL: undefined }))).toThrow(ConfigError);
    expect(() => loadConfig(validEnv({ TEXERA_BASE_URL: "  " }))).toThrow(/TEXERA_BASE_URL is required/);
  });

  test("a bare hostname is rejected as not a URL", () => {
    expect(() => loadConfig(validEnv({ TEXERA_BASE_URL: "texera.example.org" }))).toThrow(/not a valid URL/);
  });

  test("a non-http scheme is rejected", () => {
    expect(() => loadConfig(validEnv({ TEXERA_BASE_URL: "ws://texera.example.org" }))).toThrow(/must be http/);
  });

  test("missing token explains where to get one", () => {
    const error = (() => {
      try {
        loadConfig(validEnv({ TEXERA_TOKEN: undefined }));
      } catch (e) {
        return e as Error;
      }
    })();
    expect(error).toBeInstanceOf(ConfigError);
    expect(error!.message).toContain("TEXERA_TOKEN is required");
    expect(error!.message).toContain("access_token");
  });

  test("a malformed token is rejected at startup, not on first use", () => {
    expect(() => loadConfig(validEnv({ TEXERA_TOKEN: "not-a-jwt" }))).toThrow(/not a valid JWT/);
    expect(() => loadConfig(validEnv({ TEXERA_TOKEN: "a.b.c" }))).toThrow(/not a valid JWT/);
  });

  test("an already-expired token is rejected with its expiry time", () => {
    const expired = makeToken({ exp: Math.floor(Date.now() / 1000) - 60 });
    expect(() => loadConfig(validEnv({ TEXERA_TOKEN: expired }))).toThrow(/expired on/);
  });

  test("non-numeric and non-positive limits are rejected", () => {
    expect(() => loadConfig(validEnv({ TEXERA_MAX_RESULT_CHARS: "lots" }))).toThrow(/positive integer/);
    expect(() => loadConfig(validEnv({ TEXERA_MAX_RESULT_CHARS: "0" }))).toThrow(/positive integer/);
    expect(() => loadConfig(validEnv({ TEXERA_MAX_RESULT_CHARS: "-5" }))).toThrow(/positive integer/);
    expect(() => loadConfig(validEnv({ TEXERA_MAX_RESULT_CHARS: "1.5" }))).toThrow(/positive integer/);
  });

  test("an empty numeric override falls back to the default instead of failing", () => {
    expect(loadConfig(validEnv({ TEXERA_MAX_RESULT_CHARS: "" })).maxResultChars).toBe(40_000);
  });
});

describe("tokenExpiryWarning", () => {
  const config = (expiresAt?: number) => ({ ...loadConfig(validEnv()), tokenExpiresAt: expiresAt });

  test("stays quiet while the token has more than a day left", () => {
    expect(tokenExpiryWarning(config(Date.now() + 5 * 24 * 3600_000))).toBeUndefined();
  });

  test("stays quiet for a token with no expiry", () => {
    expect(tokenExpiryWarning(config(undefined))).toBeUndefined();
  });

  test("warns inside the last day, with the remaining hours", () => {
    const warning = tokenExpiryWarning(config(Date.now() + 3 * 3600_000));
    expect(warning).toContain("expires in about 3 hours");
    expect(warning).toContain("access_token");
  });

  test("rounds up rather than saying zero hours", () => {
    expect(tokenExpiryWarning(config(Date.now() + 60_000))).toContain("about 1 hour");
  });

  test("reports an already-expired token as expired", () => {
    expect(tokenExpiryWarning(config(Date.now() - 1000))).toContain("has expired");
  });
});
