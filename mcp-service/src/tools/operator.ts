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

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "../context";
import { ToolError } from "../errors";
import { formatTable, joinSections } from "../format";
import { registerTool } from "../register";

/**
 * Ranks candidate operator types for a misspelled or guessed name, so an
 * unknown type comes back with "did you mean" instead of a bare rejection.
 */
export function suggestOperatorTypes(query: string, available: string[], limit = 8): string[] {
  const needle = query.toLowerCase();
  const scored = available
    .map(type => {
      const haystack = type.toLowerCase();
      let score = 0;
      if (haystack === needle) score = 100;
      else if (haystack.startsWith(needle)) score = 60;
      else if (haystack.includes(needle)) score = 40;
      else {
        // Shared word fragments: "csv scan" should find CSVFileScan even
        // though neither string contains the other.
        const fragments = needle.split(/[^a-z0-9]+/).filter(part => part.length >= 3);
        score = fragments.filter(fragment => haystack.includes(fragment)).length * 15;
        // Subsequence match catches the common abbreviation-style miss, where
        // the guess drops an inner word: "CSVScan" -> "CSVFileScan".
        if (score === 0 && isSubsequence(needle, haystack)) {
          score = 20;
        }
      }
      return { type, score };
    })
    .filter(entry => entry.score > 0)
    .sort((a, b) => b.score - a.score || a.type.localeCompare(b.type));
  return scored.slice(0, limit).map(entry => entry.type);
}

/** True when every character of `needle` appears in `haystack`, in order. */
function isSubsequence(needle: string, haystack: string): boolean {
  if (needle.length === 0) return false;
  let index = 0;
  for (const character of haystack) {
    if (character === needle[index]) index += 1;
    if (index === needle.length) return true;
  }
  return false;
}

export function registerOperatorTools(server: McpServer, context: McpContext): void {
  registerTool(server, context, {
    name: "operator_list_types",
    title: "List available operator types",
    description:
      "List the operator types this deployment offers, with a one-line description each. " +
      "Operator types differ between deployments and versions, so consult this rather than assuming — " +
      "then call operator_get_schema before configuring one.",
    inputSchema: {
      search: z
        .string()
        .optional()
        .describe('Filter by name or description, e.g. "csv", "filter", "python". Omit to list everything.'),
    },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { search?: string }, ctx) => {
      const metadata = await ctx.operatorMetadata();
      const all = metadata.getAllOperatorTypes();
      const needle = args.search?.trim().toLowerCase();

      const entries = Object.entries(all).filter(([type, description]) => {
        if (!needle) return true;
        return type.toLowerCase().includes(needle) || description.toLowerCase().includes(needle);
      });

      if (entries.length === 0) {
        const suggestions = suggestOperatorTypes(args.search ?? "", Object.keys(all));
        return joinSections(
          `No operator type matches "${args.search}".`,
          suggestions.length > 0 ? `Closest matches: ${suggestions.join(", ")}` : undefined,
          `This deployment has ${Object.keys(all).length} operator types; call operator_list_types with no search to see them all.`
        );
      }

      entries.sort(([a], [b]) => a.localeCompare(b));
      return joinSections(
        `${entries.length} operator type(s)${needle ? ` matching "${args.search}"` : ""}:`,
        formatTable(
          ["operatorType", "description"],
          entries.map(([type, description]) => [type, description.replace(/\s+/g, " ").slice(0, 140)])
        )
      );
    },
  });

  registerTool(server, context, {
    name: "operator_get_schema",
    title: "Show an operator type's property schema",
    description:
      "Show the JSON Schema for one operator type's properties, plus its input and output ports. " +
      "Call this before workflow_add_operator so the properties are right the first time; the schema " +
      "names required fields and their exact shapes.",
    inputSchema: { operator_type: z.string().min(1).describe('Exact operator type, e.g. "CSVFileScan"') },
    annotations: { readOnlyHint: true, idempotentHint: true },
    handler: async (args: { operator_type: string }, ctx) => {
      const metadata = await ctx.operatorMetadata();
      if (!metadata.operatorTypeExists(args.operator_type)) {
        const suggestions = suggestOperatorTypes(args.operator_type, Object.keys(metadata.getAllOperatorTypes()));
        throw new ToolError(
          `No operator type "${args.operator_type}" on this deployment.` +
            (suggestions.length > 0 ? ` Did you mean: ${suggestions.join(", ")}?` : "") +
            ` Use operator_list_types to browse.`
        );
      }

      const compact = metadata.getCompactSchema(args.operator_type);
      const additional = metadata.getAdditionalMetadata(args.operator_type) ?? {};
      const inputPorts: { displayName?: string }[] = additional.inputPorts ?? [];
      const outputPorts: { displayName?: string }[] = additional.outputPorts ?? [];

      const ports = [
        `Input ports:  ${inputPorts.length === 0 ? "none (this is a source operator)" : inputPorts.map((port, index) => `${index}=${port.displayName || `input-${index}`}`).join(", ")}`,
        `Output ports: ${outputPorts.length === 0 ? "none (this is a sink operator)" : outputPorts.map((port, index) => `${index}=${port.displayName || `output-${index}`}`).join(", ")}`,
      ].join("\n");

      return joinSections(
        `${args.operator_type} — ${metadata.getDescription(args.operator_type)}`,
        ports,
        compact
          ? joinSections(
              `Required properties: ${compact.required.length > 0 ? compact.required.join(", ") : "(none)"}`,
              "Property schema:",
              JSON.stringify(compact.properties, null, 2)
            )
          : "No property schema published for this operator type."
      );
    },
  });
}
