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

import { afterEach, describe, expect, test } from "bun:test";
import { compileWorkflowAsync } from "./compile-api";
import type { LogicalPlan } from "../types/workflow";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function setMockFetch(handler: (url: string | URL | Request, init?: RequestInit) => Promise<Response>): void {
  globalThis.fetch = handler as unknown as typeof fetch;
}

describe("compile-api", () => {
  test("sends the user bearer token to the workflow compiling service", async () => {
    const calls: Array<[string, RequestInit | undefined]> = [];
    setMockFetch(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push([String(url), init]);
      return new Response(
        JSON.stringify({
          physicalPlan: {},
          operatorOutputSchemas: {},
          operatorErrors: {},
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    });

    const logicalPlan: LogicalPlan = {
      operators: [],
      links: [],
    };

    await compileWorkflowAsync(logicalPlan, "t.o.k");

    expect(calls).toHaveLength(1);
    expect(calls[0][0]).toBe("http://localhost:9090/api/compile");
    expect(calls[0][1]?.headers).toEqual({
      Authorization: "Bearer t.o.k",
      "Content-Type": "application/json",
    });
  });

  test("omits authorization when no user token is available", async () => {
    const calls: Array<[string, RequestInit | undefined]> = [];
    setMockFetch(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push([String(url), init]);
      return new Response(
        JSON.stringify({
          physicalPlan: {},
          operatorOutputSchemas: {},
          operatorErrors: {},
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    });

    await compileWorkflowAsync({ operators: [], links: [] });

    expect(calls[0][1]?.headers).toEqual({
      "Content-Type": "application/json",
    });
  });
});
