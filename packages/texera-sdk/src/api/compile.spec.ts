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
import { compileWorkflow, type WorkflowCompilationResponse } from "./compile";
import { TexeraClient } from "../client";
import type { LogicalPlan } from "../types/workflow";

const plan = {
  operators: [{ operatorID: "opX" }],
  links: [],
} as unknown as LogicalPlan;

function clientWith(fetchImpl: typeof fetch): TexeraClient {
  return new TexeraClient({ baseUrl: "https://texera.example.org", token: "tok", fetch: fetchImpl });
}

describe("compileWorkflow", () => {
  test("POSTs the plan to the compile endpoint and returns the parsed response on ok", async () => {
    const compilation: WorkflowCompilationResponse = { operatorOutputSchemas: {}, operatorErrors: {} };
    const fetchMock = mock(async () => new Response(JSON.stringify(compilation), { status: 200 }));

    const result = await compileWorkflow(clientWith(fetchMock as unknown as typeof fetch), plan);

    expect(result).toEqual(compilation);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/compile$/);
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("Content-Type")).toBe("application/json");
    expect(JSON.parse(init.body as string)).toEqual({
      operators: [{ operatorID: "opX" }],
      links: [],
      opsToReuseResult: [],
      opsToViewResult: [],
    });
  });

  test("returns null on a non-ok response", async () => {
    const fetchMock = mock(async () => new Response("boom", { status: 500 }));
    expect(await compileWorkflow(clientWith(fetchMock as unknown as typeof fetch), plan)).toBeNull();
  });

  test("returns null when fetch rejects", async () => {
    const fetchMock = mock(async () => {
      throw new Error("network down");
    });
    expect(await compileWorkflow(clientWith(fetchMock as unknown as typeof fetch), plan)).toBeNull();
  });
});
