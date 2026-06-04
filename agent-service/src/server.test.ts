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

import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { createHmac } from "crypto";
import { InMemoryAgentMetadataStore } from "./api/agent-metadata-store";
import {
  applyAgentRequestContext,
  buildApp,
  _getAgentForTests,
  _resetAgentStoreForTests,
  _setAgentMetadataStoreForTests,
} from "./server";
import { env } from "./config/env";
import { DEFAULT_AGENT_NAME } from "./types/agent";

const API = env.API_PREFIX;
const SECRET = "test-secret-key-for-agent-service-access-control";
const prevSecret = process.env.AUTH_JWT_SECRET;
const metadataStore = new InMemoryAgentMetadataStore();
const app = buildApp();

function url(path: string): string {
  return `http://localhost${path}`;
}

function b64url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function signJwt(payload: Record<string, unknown>, secret = SECRET): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(createHmac("sha256", secret).update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

function tokenFor(uid: number, secret = SECRET): string {
  return signJwt({ sub: `user-${uid}`, userId: uid, exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
}

function authHeaders(token: string | null, extra: Record<string, string> = {}): Record<string, string> {
  const headers = { ...extra };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function postJson(path: string, body: unknown, token: string | null = tokenFor(1)): Promise<Response> {
  return app.handle(
    new Request(url(path), {
      method: "POST",
      headers: authHeaders(token, { "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    })
  );
}

async function patchJson(path: string, body: unknown, token: string | null = tokenFor(1)): Promise<Response> {
  return app.handle(
    new Request(url(path), {
      method: "PATCH",
      headers: authHeaders(token, { "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    })
  );
}

async function getJson(path: string, token: string | null = tokenFor(1)): Promise<Response> {
  return app.handle(new Request(url(path), { headers: authHeaders(token) }));
}

async function del(path: string, token: string | null = tokenFor(1)): Promise<Response> {
  return app.handle(new Request(url(path), { method: "DELETE", headers: authHeaders(token) }));
}

async function readJson<T = unknown>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

beforeAll(() => {
  process.env.AUTH_JWT_SECRET = SECRET;
});

afterAll(() => {
  if (prevSecret === undefined) delete process.env.AUTH_JWT_SECRET;
  else process.env.AUTH_JWT_SECRET = prevSecret;
});

beforeEach(() => {
  metadataStore.clear();
  _setAgentMetadataStoreForTests(metadataStore);
  _resetAgentStoreForTests();
});

describe(`GET ${API}/healthcheck`, () => {
  test("returns 200 with status ok", async () => {
    const res = await getJson(`${API}/healthcheck`);
    expect(res.status).toBe(200);
    const body = await readJson<{ status: string; timestamp: string }>(res);
    expect(body.status).toBe("ok");
    expect(typeof body.timestamp).toBe("string");
  });
});

describe(`POST ${API}/agents`, () => {
  test("creates an agent without workflow binding", async () => {
    const res = await postJson(`${API}/agents`, { modelType: "test-model", name: "Tester" });
    expect(res.status).toBe(200);

    const agent = await readJson<{
      id: string;
      name: string;
      modelType: string;
      state: string;
      delegate?: unknown;
    }>(res);
    expect(agent.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(agent.name).toBe("Tester");
    expect(agent.modelType).toBe("test-model");
    expect(agent.state).toBe("AVAILABLE");
    expect(agent.delegate).toBeUndefined();
  });

  test("assigns a unique, non-guessable id to each agent", async () => {
    const a = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));
    const b = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));

    expect(a.id).not.toBe(b.id);
    // UUID-based ids are not enumerable, unlike the previous sequential counter.
    expect(a.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  test("defaults unnamed agents to dkNetAgent", async () => {
    const res = await postJson(`${API}/agents`, { modelType: "m" });
    expect(res.status).toBe(200);

    const agent = await readJson<{ id: string; name: string }>(res);
    expect(agent.name).toBe(DEFAULT_AGENT_NAME);
    expect(await metadataStore.getAgent(agent.id)).toMatchObject({ name: DEFAULT_AGENT_NAME });
  });

  test("persists ownership metadata for the creating user", async () => {
    const agent = await readJson<{ id: string }>(
      await postJson(`${API}/agents`, { modelType: "m", name: "owned" }, tokenFor(7))
    );

    expect(await metadataStore.getAgent(agent.id)).toMatchObject({
      id: agent.id,
      ownerUid: 7,
      name: "owned",
      modelType: "m",
      config: {
        settings: expect.objectContaining({
          maxSteps: 100,
        }),
        tools: expect.any(Array),
      },
      reactSteps: [],
    });
  });

  test("ignores request context fields at creation time", async () => {
    const res = await postJson(`${API}/agents`, {
      modelType: "m",
      userToken: "obviously-not-a-jwt",
      workflowId: 7,
      computingUnitId: 3,
    });
    expect(res.status).toBe(200);
    const created = await readJson<{ id: string }>(res);

    const agent = _getAgentForTests(created.id);
    expect(agent).toBeDefined();
    const toolNames = agent!.getSystemInfo().tools.map(tool => tool.name);
    expect(toolNames).not.toContain("listDatasets");
    expect(toolNames).not.toContain("listDatasetVersions");
    expect(toolNames).not.toContain("listDatasetFiles");
  });

  test("token-only request context exposes dataset tools", async () => {
    const createRes = await postJson(`${API}/agents`, { modelType: "m" });
    expect(createRes.status).toBe(200);
    const created = await readJson<{ id: string }>(createRes);

    const agent = _getAgentForTests(created.id);
    expect(agent).toBeDefined();
    await applyAgentRequestContext(created.id, agent!, { userToken: tokenFor(1) });

    const toolNames = agent!.getSystemInfo().tools.map(tool => tool.name);
    expect(toolNames).toContain("listDatasets");
    expect(toolNames).toContain("listDatasetVersions");
    expect(toolNames).toContain("listDatasetFiles");
    expect(toolNames).not.toContain("executeOperator");
  });

  test("executeOperator tool requires a connected computing unit", async () => {
    const createRes = await postJson(`${API}/agents`, { modelType: "m" });
    expect(createRes.status).toBe(200);
    const created = await readJson<{ id: string }>(createRes);
    const agent = _getAgentForTests(created.id)!;

    // Workflow present but no computing unit -> cannot execute, tool withheld.
    await applyAgentRequestContext(created.id, agent, { userToken: tokenFor(1), workflowId: 5 });
    expect(agent.getSystemInfo().tools.map(tool => tool.name)).not.toContain("executeOperator");

    // With a computing unit connected, the execute tool is exposed.
    await applyAgentRequestContext(created.id, agent, { userToken: tokenFor(1), workflowId: 5, computingUnitId: 3 });
    expect(agent.getSystemInfo().tools.map(tool => tool.name)).toContain("executeOperator");
  });

  test("does not expose settings in agent API responses", async () => {
    const created = await readJson<{ id: string; settings?: unknown }>(
      await postJson(`${API}/agents`, { modelType: "m", name: "public" })
    );
    expect(created.settings).toBeUndefined();

    const res = await getJson(`${API}/agents/${created.id}`);
    expect(res.status).toBe(200);
    const body = await readJson<{ settings?: unknown }>(res);
    expect(body.settings).toBeUndefined();
  });

  test("ignores attempted settings payloads during agent creation", async () => {
    const created = await readJson<{ id: string }>(
      await postJson(`${API}/agents`, {
        modelType: "m",
        settings: {
          maxSteps: 7,
          executionTimeoutMinutes: 1,
          allowedOperatorTypes: [],
        },
      })
    );

    const persisted = await metadataStore.getAgent(created.id);
    expect(persisted?.config.settings).toMatchObject({
      maxSteps: 100,
      executionTimeoutMinutes: 4,
    });
    expect(persisted?.config.settings).not.toHaveProperty("allowedOperatorTypes");
  });

  test("exposes operator discovery tools without fixed operator configuration", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));
    const agent = _getAgentForTests(created.id);
    expect(agent).toBeDefined();

    const systemInfo = agent!.getSystemInfo();
    const toolNames = systemInfo.tools.map(tool => tool.name);
    expect(toolNames).toContain("list_operator_types");
    expect(toolNames).toContain("get_operator_definition");
    expect(agent!.getSettingsApi()).not.toHaveProperty("allowedOperatorTypes");

    agent!.updateSettings({ maxOperatorResultCharLimit: 8 });
    const operatorTypes = await (agent as any).tools.list_operator_types.execute({});
    expect(operatorTypes).not.toContain("...[truncated]");
    expect(JSON.parse(operatorTypes).operatorTypes.length).toBeGreaterThan(0);
  });

  test("rejects invalid token", async () => {
    const res = await postJson(
      `${API}/agents`,
      {
        modelType: "m",
      },
      "obviously-not-a-jwt"
    );
    expect(res.status).toBe(401);
    const body = await readJson<{ error: string }>(res);
    expect(body.error).toBe("Invalid or expired token");
  });

  test("request context rejects invalid tokens", async () => {
    const createRes = await postJson(`${API}/agents`, { modelType: "m" });
    const created = await readJson<{ id: string }>(createRes);
    const agent = _getAgentForTests(created.id);
    expect(agent).toBeDefined();

    await expect(applyAgentRequestContext(created.id, agent!, { userToken: "obviously-not-a-jwt" })).rejects.toThrow(
      "Invalid or expired token"
    );
  });

  test("rejects missing modelType", async () => {
    const res = await postJson(`${API}/agents`, { name: "no-model" });
    // Body schema violation; the exact status depends on the Elysia version but
    // it is always a 4xx or 5xx, never a successful 2xx.
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

describe(`GET ${API}/agents`, () => {
  test("empty store returns no agents", async () => {
    const res = await getJson(`${API}/agents`);
    expect(res.status).toBe(200);
    const body = await readJson<{ agents: unknown[] }>(res);
    expect(body.agents).toEqual([]);
  });

  test("lists every created agent", async () => {
    await postJson(`${API}/agents`, { modelType: "m", name: "one" });
    await postJson(`${API}/agents`, { modelType: "m", name: "two" });

    const res = await getJson(`${API}/agents`);
    const body = await readJson<{ agents: { name: string }[] }>(res);
    expect(body.agents).toHaveLength(2);
    expect(body.agents.map(a => a.name).sort()).toEqual(["one", "two"]);
  });

  test("lists persisted agents after the runtime cache is cleared", async () => {
    const created = await readJson<{ id: string }>(
      await postJson(`${API}/agents`, { modelType: "m", name: "persisted" })
    );

    _resetAgentStoreForTests();

    const res = await getJson(`${API}/agents`);
    expect(res.status).toBe(200);
    const body = await readJson<{ agents: { id: string; name: string }[] }>(res);
    expect(body.agents).toHaveLength(1);
    expect(body.agents[0]).toMatchObject({ id: created.id, name: "persisted" });
  });
});

describe(`GET ${API}/agents/:id`, () => {
  test("returns the agent plus its workflow snapshot", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));

    const res = await getJson(`${API}/agents/${created.id}`);
    expect(res.status).toBe(200);
    const body = await readJson<{ id: string; workflow: unknown; stepCount: number }>(res);
    expect(body.id).toBe(created.id);
    expect(body.workflow).toBeDefined();
    expect(typeof body.stepCount).toBe("number");
  });

  test("returns 404 for an unknown id", async () => {
    const res = await getJson(`${API}/agents/agent-does-not-exist`);
    expect(res.status).toBe(404);
    const body = await readJson<{ error: string }>(res);
    expect(body.error).toBe("Agent not found");
  });
});

describe(`PATCH ${API}/agents/:id`, () => {
  test("updates agent name and model type in runtime state and persisted metadata", async () => {
    const created = await readJson<{ id: string }>(
      await postJson(`${API}/agents`, { modelType: "old-model", name: "Old name" })
    );

    const res = await patchJson(`${API}/agents/${created.id}`, {
      name: "Renamed agent",
      modelType: "new-model",
    });

    expect(res.status).toBe(200);
    const body = await readJson<{ id: string; name: string; modelType: string }>(res);
    expect(body).toMatchObject({
      id: created.id,
      name: "Renamed agent",
      modelType: "new-model",
    });

    expect(await metadataStore.getAgent(created.id)).toMatchObject({
      name: "Renamed agent",
      modelType: "new-model",
    });
    expect(_getAgentForTests(created.id)).toMatchObject({
      agentName: "Renamed agent",
      modelType: "new-model",
    });

    _resetAgentStoreForTests();

    const getRes = await getJson(`${API}/agents/${created.id}`);
    expect(getRes.status).toBe(200);
    expect(await readJson<{ name: string; modelType: string }>(getRes)).toMatchObject({
      name: "Renamed agent",
      modelType: "new-model",
    });
  });

  test("rejects empty update values", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));

    const res = await patchJson(`${API}/agents/${created.id}`, { name: "  " });

    expect(res.status).toBe(400);
    expect(await readJson<{ error: string }>(res)).toEqual({ error: "name must not be empty" });
  });

  test("keeps update access scoped to the owner", async () => {
    const created = await readJson<{ id: string }>(
      await postJson(`${API}/agents`, { modelType: "m", name: "mine" }, tokenFor(1))
    );

    const res = await patchJson(`${API}/agents/${created.id}`, { name: "not mine" }, tokenFor(2));

    expect(res.status).toBe(403);
    expect(await metadataStore.getAgent(created.id)).toMatchObject({ name: "mine" });
  });
});

describe(`DELETE ${API}/agents/:id`, () => {
  test("destroys the agent and a follow-up GET returns 404", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));

    const delRes = await del(`${API}/agents/${created.id}`);
    expect(delRes.status).toBe(200);
    expect(await readJson<unknown>(delRes)).toEqual({ deleted: true });

    const getRes = await getJson(`${API}/agents/${created.id}`);
    expect(getRes.status).toBe(404);
  });

  test("returns 404 when deleting an unknown agent", async () => {
    const res = await del(`${API}/agents/missing`);
    expect(res.status).toBe(404);
  });
});

describe("Agent control routes", () => {
  test("POST /:id/stop returns stopping", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));
    const res = await postJson(`${API}/agents/${created.id}/stop`, {});
    expect(res.status).toBe(200);
    expect(await readJson<unknown>(res)).toEqual({ status: "stopping" });
  });

  test("POST /:id/clear resets history", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));
    const res = await postJson(`${API}/agents/${created.id}/clear`, {});
    expect(res.status).toBe(200);
    expect(await readJson<unknown>(res)).toEqual({ status: "cleared" });
  });

  test("GET /:id/operator-results returns an empty map on the framework build", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));
    const res = await getJson(`${API}/agents/${created.id}/operator-results`);
    expect(res.status).toBe(200);
    expect(await readJson<unknown>(res)).toEqual({ results: {} });
  });

  test("GET /:id/react-steps restores persisted ReAct state", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));
    await metadataStore.updateAgentReActSteps(created.id, [
      {
        id: "step-persisted",
        messageId: "msg-persisted",
        stepId: 0,
        timestamp: Date.now(),
        role: "user",
        content: "persisted step",
        isBegin: true,
        isEnd: true,
      },
    ]);

    _resetAgentStoreForTests();

    const res = await getJson(`${API}/agents/${created.id}/react-steps`);
    expect(res.status).toBe(200);
    const body = await readJson<{ steps: { content: string }[] }>(res);
    expect(body.steps.map(step => step.content)).toEqual(["persisted step"]);
  });
});

describe("agent configuration endpoints", () => {
  test("does not expose system prompt or configuration endpoints", async () => {
    const created = await readJson<{ id: string }>(await postJson(`${API}/agents`, { modelType: "m" }));

    const systemInfo = await getJson(`${API}/agents/${created.id}/system-info`);
    expect(systemInfo.status).toBe(404);

    const settingsRead = await getJson(`${API}/agents/${created.id}/settings`);
    expect(settingsRead.status).toBe(404);

    const settingsWrite = await patchJson(`${API}/agents/${created.id}/settings`, {
      maxSteps: 7,
    });
    expect(settingsWrite.status).toBe(404);

    const operatorTypes = await getJson(`${API}/agents/${created.id}/operator-types`);
    expect(operatorTypes.status).toBe(404);
  });
});

describe("access control", () => {
  async function createOwnedAgent(uid: number): Promise<string> {
    const res = await postJson(`${API}/agents`, { modelType: "m" }, tokenFor(uid));
    expect(res.status).toBe(200);
    return (await readJson<{ id: string }>(res)).id;
  }

  test("rejects agent creation without a token", async () => {
    const res = await postJson(`${API}/agents`, { modelType: "m" }, null);
    expect(res.status).toBe(401);
  });

  test("rejects a forged token (bad signature) at creation", async () => {
    const forged = tokenFor(1, "the-wrong-secret");
    const res = await postJson(`${API}/agents`, { modelType: "m" }, forged);
    expect(res.status).toBe(401);
  });

  test("rejects an expired token at creation", async () => {
    const expired = signJwt({ sub: "user-1", userId: 1, exp: Math.floor(Date.now() / 1000) - 3600 });
    const res = await postJson(`${API}/agents`, { modelType: "m" }, expired);
    expect(res.status).toBe(401);
  });

  test("an owner can read its own agent", async () => {
    const id = await createOwnedAgent(1);
    const res = await getJson(`${API}/agents/${id}`, tokenFor(1));
    expect(res.status).toBe(200);
  });

  test("a different user cannot read someone else's agent (403)", async () => {
    const id = await createOwnedAgent(1);
    const res = await getJson(`${API}/agents/${id}`, tokenFor(2));
    expect(res.status).toBe(403);
  });

  test("a request without a token is rejected (401)", async () => {
    const id = await createOwnedAgent(1);
    const res = await getJson(`${API}/agents/${id}`, null);
    expect(res.status).toBe(401);
  });

  test("a control route is also guarded (stop -> 403 for non-owner)", async () => {
    const id = await createOwnedAgent(1);
    const res = await app.handle(
      new Request(url(`${API}/agents/${id}/stop`), {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokenFor(2)}` },
        body: "{}",
      })
    );
    expect(res.status).toBe(403);
  });

  test("listing is scoped to the caller's own agents", async () => {
    const mine = await createOwnedAgent(1);
    await createOwnedAgent(2);

    const res = await getJson(`${API}/agents`, tokenFor(1));
    expect(res.status).toBe(200);
    const body = await readJson<{ agents: { id: string }[] }>(res);
    expect(body.agents.map(a => a.id)).toEqual([mine]);
  });

  test("listing without a token is rejected (401)", async () => {
    const res = await getJson(`${API}/agents`, null);
    expect(res.status).toBe(401);
  });
});
