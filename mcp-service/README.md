<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Texera MCP Service

A [Model Context Protocol](https://modelcontextprotocol.io) server that connects any MCP-capable
chatbot — Claude Desktop, Claude Code, Cursor, ChatGPT Desktop — to a user's account on **any**
Texera deployment.

The chatbot can then manage datasets, build and edit workflows operator by operator, run them and
read the results, all against the user's own account.

Design and rationale: [DESIGN.md](DESIGN.md).

---

## Connect a chatbot

You need two things: the **URL of your deployment** and a **token** for your account.

### 1. Get a token

Sign in to your Texera deployment in a browser, open the developer console on that page, and run:

```js
localStorage.getItem("access_token");
```

Copy the value. Tokens are valid for 7 days by default (`auth.jwt.expiration-in-minutes`); the
server warns you in its tool output when yours is within a day of expiring.

### 2. Add the server to your MCP client

Claude Desktop (`claude_desktop_config.json`), Claude Code (`.mcp.json`) and most other clients use
the same shape:

```jsonc
{
  "mcpServers": {
    "texera": {
      "command": "npx",
      "args": ["-y", "@texera/mcp"],
      "env": {
        "TEXERA_BASE_URL": "https://texera.dknet-ai.org",
        "TEXERA_TOKEN": "eyJhbGciOiJIUzI1NiJ9..."
      }
    }
  }
}
```

Any deployment works — `https://hub.texera.io`, your own Helm install, or a local
`bin/local-dev.sh` stack at `http://localhost:8080`.

Then ask the chatbot to call `texera_whoami`. It reports which account and deployment it reached,
which is the fastest way to confirm the setup.

### Configuration

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `TEXERA_BASE_URL` | yes | — | Deployment origin. All services are reached through it. |
| `TEXERA_TOKEN` | yes | — | Your account's JWT. |
| `TEXERA_MAX_RESULT_CHARS` | no | `40000` | Ceiling on one tool result. |
| `TEXERA_MAX_UPLOAD_BYTES` | no | `26214400` | Ceiling on one `dataset_upload_file`. |
| `TEXERA_RUN_TIMEOUT_SECONDS` | no | `120` | Default budget for `workflow_run`. |
| `TEXERA_REQUEST_TIMEOUT_MS` | no | `60000` | Per-request HTTP timeout. |

Bad configuration fails at startup with a message naming the variable, rather than surfacing as a
confusing failure mid-conversation.

---

## Two rules that are easy to get wrong

Both are stated in the server's instructions and repeated in the relevant tool descriptions, because
ignoring either produces something that looks fine and silently does not work.

**Dataset uploads are staged.** `dataset_upload_file` and `dataset_delete_file` change nothing a
workflow can read until `dataset_create_version` commits them — datasets are LakeFS repositories and
a version is a commit.

```
dataset_create → dataset_upload_file → dataset_create_version → dataset_list_files
                                       ^^^^^^^^^^^^^^^^^^^^^^ without this, no operator can see the data
```

**Workflow edits are in memory.** `workflow_open` loads a workflow, the editing tools change a local
copy, and `workflow_save` writes it back. `workflow_run` is the deliberate exception: it runs the
in-memory graph, so you can test before committing to a save.

```
workflow_open → add/modify/delete → workflow_validate → workflow_run → workflow_save
```

---

## Tools

### Session

| Tool | What it does |
| --- | --- |
| `texera_whoami` | Which deployment and account, token expiry, enabled features, open sessions. |

### Datasets

| Tool | What it does |
| --- | --- |
| `dataset_list` / `dataset_get` | Browse datasets and their versions. |
| `dataset_create` / `dataset_update` / `dataset_delete` | Manage datasets. Deletion needs the exact name as confirmation. |
| `dataset_upload_file` / `dataset_delete_file` | Stage file changes. |
| `dataset_create_version` | Commit staged changes into a usable version. |
| `dataset_list_files` | List a version's files, each with the path an operator's `fileName` needs. |
| `dataset_read_file` | Read a text file, to check the data before building over it. |
| `dataset_uncommitted_changes` | What is staged but not yet committed. |
| `dataset_list_access` / `dataset_share` / `dataset_unshare` | Sharing by email. |

### Workflows

| Tool | What it does |
| --- | --- |
| `workflow_list` / `workflow_create` / `workflow_update` / `workflow_duplicate` / `workflow_delete` | Manage workflows. |
| `workflow_open` / `workflow_describe` / `workflow_discard` | Open, inspect and abandon an edit session. |
| `workflow_add_operator` / `workflow_modify_operator` / `workflow_delete_operator` | Edit the graph. Properties are checked against the operator's schema first. |
| `workflow_add_link` / `workflow_delete_link` / `workflow_auto_layout` | Edit connections and layout. |
| `workflow_validate` | Type-check and compile without running. |
| `workflow_save` | Persist, with a concurrent-edit check. |
| `workflow_list_versions` | Version history — the recovery path after a bad edit. |
| `workflow_list_access` / `workflow_share` / `workflow_unshare` | Sharing by email. |
| `operator_list_types` / `operator_get_schema` | The deployment's operator catalogue. |

### Execution

| Tool | What it does |
| --- | --- |
| `computing_unit_list` / `_create` / `_terminate` / `_rename` | Manage the units workflows run on. |
| `workflow_run` | Run to completion and return results, errors and console output. `target_operator_id` runs only that operator's upstream sub-graph. |

### Resources and prompts

- `texera://operator-metadata` — the full operator catalogue.
- `texera://workflow/{wid}`, `texera://dataset/{did}` — JSON snapshots.
- `build_workflow_from_dataset` — a walkthrough in the order Texera requires.

---

## Safety

- Deleting a dataset, workflow or computing unit requires passing its **exact current name** as a
  separate confirmation argument, and is annotated `destructiveHint` so clients prompt the user.
- Sharing tools are annotated destructive too: they expose a real person's data to another real
  person, and the email address must be supplied, never inferred.
- `workflow_save` refuses to overwrite a workflow that changed on the server since it was opened.
  Texera's editor saves from the browser, so an open tab is the common cause; `force: true`
  overwrites deliberately.
- The token is never echoed into tool output.

---

## Development

```bash
bun install
bun test          # 150+ unit and integration tests, no deployment needed
bun run typecheck
bun run dev       # stdio server against the deployment in your env
```

Tests run against `src/testing/fake-texera.ts`, an HTTP-level stand-in for a deployment, driven
through a real MCP client over an in-memory transport — so tool schemas, dispatch, handlers and
error translation are all exercised.

Shared client and workflow-graph code lives in [`packages/texera-sdk`](../packages/texera-sdk) and
is used by [`agent-service`](../agent-service) as well.

```bash
bun run build     # bundles to dist/index.js for `npx @texera/mcp`
```
