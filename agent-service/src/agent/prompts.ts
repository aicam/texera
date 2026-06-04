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

import { readFileSync } from "fs";
import { join } from "path";
import { WorkflowSystemMetadata } from "./util/workflow-system-metadata";
import { env } from "../config/env";
import { createLogger } from "../logger";

const log = createLogger("Prompts");

// Capability names map to the operator types that enable a marked section of the prompt
// document. A `<!-- @requires-capability: NAME -->...<!-- @end-capability -->` block is kept
// only when at least one of its operator types exists in the backend metadata; otherwise the
// block is stripped, so we never instruct the model to use an operator it does not have.
const CAPABILITY_OPERATOR_TYPES: Record<string, string[]> = {
  python: ["PythonUDFV2"],
  r: ["RUDF"],
};

// The prompt is a standalone document bundled with the source tree (so it ships in the image
// and is editable without touching code). Set AGENT_SYSTEM_PROMPT_PATH — e.g. a k8s ConfigMap
// mount — to override it and change the prompt without rebuilding the image.
const BUNDLED_PROMPT_PATH = join(import.meta.dir, "system-prompt.md");

// Minimal safety net used only if neither the override nor the bundled document can be read.
const FALLBACK_PROMPT =
  "You are dkNetAgent, the DKNet-AI assistant for dknet-ai.org. Help users with datasets, " +
  "biomedical research, and building/running DKNet-AI dataflows using the available tools. Do not " +
  "invent dataset names, file paths, or operator properties.";

const CAPABILITY_BLOCK_PATTERN =
  /[ \t]*<!--\s*@requires-capability:\s*([\w-]+)\s*-->\n?([\s\S]*?)\n?[ \t]*<!--\s*@end-capability\s*-->\n?/g;

function loadPromptDocument(): string {
  const overridePath = env.AGENT_SYSTEM_PROMPT_PATH;
  if (overridePath) {
    try {
      const content = readFileSync(overridePath, "utf8");
      if (content.trim()) return content;
      log.warn({ path: overridePath }, "AGENT_SYSTEM_PROMPT_PATH is empty; falling back to the bundled system prompt");
    } catch (err) {
      log.warn(
        { path: overridePath, err: (err as Error).message },
        "could not read AGENT_SYSTEM_PROMPT_PATH; falling back to the bundled system prompt"
      );
    }
  }
  try {
    const content = readFileSync(BUNDLED_PROMPT_PATH, "utf8");
    if (content.trim()) return content;
    log.error("the bundled system prompt is empty; using the minimal fallback prompt");
  } catch (err) {
    log.error({ err: (err as Error).message }, "could not read the bundled system prompt; using minimal fallback");
  }
  return FALLBACK_PROMPT;
}

function applyCapabilities(doc: string, metadataStore: WorkflowSystemMetadata): string {
  return doc.replace(CAPABILITY_BLOCK_PATTERN, (_match, capability: string, body: string) => {
    const operatorTypes = CAPABILITY_OPERATOR_TYPES[capability.trim()] ?? [];
    const available = operatorTypes.some(type => metadataStore.operatorTypeExists(type));
    return available ? body : "";
  });
}

/**
 * Build the agent system prompt by loading the prompt document (an AGENT_SYSTEM_PROMPT_PATH
 * override or the bundled default) and keeping only the capability sections whose operators
 * are available in the current backend metadata.
 */
export function buildSystemPrompt(metadataStore: WorkflowSystemMetadata): string {
  const doc = loadPromptDocument();
  return `${applyCapabilities(doc, metadataStore).trimEnd()}\n`;
}
