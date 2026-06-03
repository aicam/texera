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

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { CallToolRequestSchema, isInitializeRequest, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { MemoryCache } from "./utils/cache/memory-cache.js";
import { featureFlags } from "./utils/feature-flags.js";
import { getAvailableTools, isToolEnabled } from "./utils/tool-definitions.js";
import { ClinicalModule } from "./modules/clinical/index.js";
import { GenomicsModule } from "./modules/genomics/index.js";
import { LiteratureModule } from "./modules/literature/index.js";
import { ProteinsModule } from "./modules/proteins/index.js";
import { SequencesModule } from "./modules/sequences/index.js";

type BioToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

interface BioMcpRuntime {
  server: Server;
  transport: WebStandardStreamableHTTPServerTransport;
}

const PORT = Number(process.env.PORT || 3010);
const MCP_PATH = process.env.MCP_PATH || "/mcp";
const API_KEY = process.env.BIOMCP_API_KEY || process.env.API_KEY;

function errorResult(message: string): CallToolResult {
  return {
    content: [{ type: "text", text: message }],
    isError: true,
  };
}

function toCallToolResult(result: BioToolResult): CallToolResult {
  return {
    content: result.content,
    isError: result.isError,
  };
}

function authorize(request: Request): boolean {
  if (!API_KEY) {
    return true;
  }

  const xApiKey = request.headers.get("x-api-key")?.trim();
  const authorization = request.headers.get("authorization")?.trim();
  const bearer = authorization?.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  return xApiKey === API_KEY || authorization === API_KEY || bearer === API_KEY;
}

function createToolRuntime(): {
  callToolByName: (name: string, args: unknown) => Promise<BioToolResult>;
} {
  const cache = new MemoryCache(300000);
  const literatureModule = new LiteratureModule(cache);
  const genomicsModule = new GenomicsModule(cache);
  const proteinsModule = new ProteinsModule(cache);
  const clinicalModule = new ClinicalModule(cache);
  const sequencesModule = new SequencesModule(cache);

  return {
    async callToolByName(name: string, args: unknown): Promise<BioToolResult> {
      switch (name) {
        case "search_pubmed":
          return literatureModule.searchPubMed(args);
        case "get_citation_network":
          return literatureModule.getCitationNetwork(args as any);
        case "lookup_variant":
          return genomicsModule.lookupVariant(args);
        case "search_genes":
          return genomicsModule.searchGenes(args);
        case "get_population_frequency":
          return genomicsModule.getPopulationFrequency(args as any);
        case "search_proteins":
          return proteinsModule.searchProteins(args);
        case "analyze_protein_structure":
          return proteinsModule.analyzeProteinStructure(args as any);
        case "interpret_clinical_variant":
          return clinicalModule.interpretClinicalVariant(args);
        case "search_omim":
          return clinicalModule.searchOMIM(args as any);
        case "blast_sequence":
          return sequencesModule.blastSequence(args);
        case "align_sequences":
          return sequencesModule.alignSequences(args as any);
        default:
          return {
            content: [{ type: "text", text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    },
  };
}

export function createBioMcpServer(): Server {
  const server = new Server(
    {
      name: "texera-bio-mcp-service",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );
  const runtime = createToolRuntime();

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: getAvailableTools(),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    if (!isToolEnabled(name)) {
      return errorResult(
        `Tool '${name}' is not available. Check BioMCP feature flags and required environment variables.`
      );
    }

    try {
      return toCallToolResult(await runtime.callToolByName(name, args ?? {}));
    } catch (error) {
      return errorResult(`Error executing ${name}: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  });

  return server;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

async function parseJsonBody(request: Request): Promise<unknown> {
  try {
    return await request.clone().json();
  } catch {
    return undefined;
  }
}

function createRuntime(sessionId: string | undefined, sessions: Map<string, BioMcpRuntime>): BioMcpRuntime {
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: sessionId === undefined ? () => crypto.randomUUID() : undefined,
    onsessioninitialized: (initializedSessionId) => {
      sessions.set(initializedSessionId, runtime);
    },
    onsessionclosed: (closedSessionId) => {
      sessions.delete(closedSessionId);
    },
  });

  const runtime: BioMcpRuntime = {
    server: createBioMcpServer(),
    transport,
  };

  return runtime;
}

export function createFetchHandler(): (request: Request) => Promise<Response> {
  const sessions = new Map<string, BioMcpRuntime>();

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204 });
    }

    if (url.pathname === "/healthcheck" || url.pathname === "/health") {
      return jsonResponse(200, {
        status: "ok",
        service: "bio-mcp-service",
        enabledTools: getAvailableTools().map((tool) => tool.name),
      });
    }

    if (url.pathname !== MCP_PATH) {
      return jsonResponse(404, {
        error: "Not found",
        message: `${request.method} ${url.pathname} is not a BioMCP endpoint`,
      });
    }

    if (!authorize(request)) {
      return jsonResponse(401, { error: "Unauthorized" });
    }

    const sessionId = request.headers.get("mcp-session-id") ?? undefined;
    const existingRuntime = sessionId ? sessions.get(sessionId) : undefined;

    if (existingRuntime) {
      return existingRuntime.transport.handleRequest(request);
    }

    if (sessionId) {
      return jsonResponse(404, {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "MCP session not found",
        },
        id: null,
      });
    }

    if (request.method !== "POST") {
      return jsonResponse(400, {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Missing MCP session id",
        },
        id: null,
      });
    }

    const parsedBody = await parseJsonBody(request);
    if (!isInitializeRequest(parsedBody)) {
      return jsonResponse(400, {
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Missing MCP session id for non-initialize request",
        },
        id: null,
      });
    }

    const runtime = createRuntime(undefined, sessions);
    await runtime.server.connect(runtime.transport);
    return runtime.transport.handleRequest(request, { parsedBody });
  };
}

if (import.meta.main) {
  featureFlags.logConfiguration();
  Bun.serve({
    port: PORT,
    fetch: createFetchHandler(),
  });
  console.log(`BioMCP service listening on http://localhost:${PORT}${MCP_PATH}`);
}
