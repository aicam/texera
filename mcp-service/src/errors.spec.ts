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
import { TexeraApiError, TexeraConnectionError } from "@texera/sdk";
import { loadConfig, type McpConfig } from "./config";
import { describeError, ToolError } from "./errors";
import { makeToken } from "./testing/token";

const baseConfig = (): McpConfig => loadConfig({ TEXERA_BASE_URL: "https://texera.test", TEXERA_TOKEN: makeToken() });

function apiError(status: number, body = "", wwwAuthenticate?: string): TexeraApiError {
  return new TexeraApiError(
    status,
    "Status",
    "GET",
    "https://texera.test/api/workflow/list",
    body,
    wwwAuthenticate ? /error\s*=\s*"([^"]*)"/.exec(wwwAuthenticate)?.[1] : undefined
  );
}

describe("describeError — authentication", () => {
  test("names an expired token when the deployment says invalid_token", () => {
    const message = describeError(
      apiError(401, "", 'Bearer realm="texera", error="invalid_token"'),
      baseConfig(),
      "dataset_list"
    );
    expect(message).toContain("expired or invalid");
    expect(message).toContain("access_token");
  });

  test("still names an expired token when an older deployment sends only a bare challenge", () => {
    // texera.dknet-ai.org answers `Bearer realm="realm"` for an expired token,
    // so the local `exp` claim has to carry the diagnosis.
    const config = { ...baseConfig(), tokenExpiresAt: Date.now() - 1000 };
    const message = describeError(apiError(401, "", 'Bearer realm="realm"'), config, "dataset_list");
    expect(message).toContain("expired or invalid");
  });

  test("distinguishes a rejected-but-unexpired token from an expired one", () => {
    const message = describeError(apiError(401, "", 'Bearer realm="realm"'), baseConfig(), "dataset_list");
    expect(message).toContain("rejected the request as unauthenticated");
    expect(message).toContain("different deployment");
  });
});

describe("describeError — other statuses", () => {
  test("403 suggests the likely causes", () => {
    const message = describeError(apiError(403, "No sufficient access privilege."), baseConfig(), "workflow_save");
    expect(message).toContain("access denied");
    expect(message).toContain("No sufficient access privilege.");
  });

  test("404 suggests deletion or a wrong id", () => {
    expect(describeError(apiError(404), baseConfig(), "workflow_open")).toContain("not found");
  });

  test("400 is reported as an invalid request with the server's reason", () => {
    const message = describeError(apiError(400, "Dataset with the same name already exists"), baseConfig(), "x");
    expect(message).toContain("rejected the request as invalid");
    expect(message).toContain("same name already exists");
  });

  test("unwraps a JSON error envelope instead of dumping raw JSON", () => {
    const message = describeError(apiError(500, JSON.stringify({ message: "boom" })), baseConfig(), "x");
    expect(message).toContain("Server said: boom");
    expect(message).not.toContain("{");
  });

  test("truncates a very long body", () => {
    const message = describeError(apiError(500, "z".repeat(2000)), baseConfig(), "x");
    expect(message.length).toBeLessThan(600);
  });

  test("an empty body does not produce a dangling 'Server said:'", () => {
    expect(describeError(apiError(500, "   "), baseConfig(), "x")).not.toContain("Server said");
  });
});

describe("describeError — transport and internal", () => {
  test("a connection failure points at the base url setting", () => {
    const error = new TexeraConnectionError("GET", "https://texera.test/api/healthcheck", new Error("ECONNREFUSED"));
    const message = describeError(error, baseConfig(), "texera_whoami");
    expect(message).toContain("could not reach https://texera.test");
    expect(message).toContain("TEXERA_BASE_URL");
  });

  test("a ToolError is passed through verbatim, since it is already written for the model", () => {
    expect(describeError(new ToolError("Call workflow_open first."), baseConfig(), "workflow_save")).toBe(
      "Call workflow_open first."
    );
  });

  test("an unexpected error still names the tool", () => {
    expect(describeError(new Error("kaboom"), baseConfig(), "workflow_run")).toBe("workflow_run: kaboom");
  });

  test("a non-Error throwable is stringified rather than swallowed", () => {
    expect(describeError("plain string", baseConfig(), "x")).toContain("plain string");
  });
});
