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

# Texera MCP Service — Design

A [Model Context Protocol](https://modelcontextprotocol.io) server that lets any
MCP-capable chatbot (Claude Desktop / Claude Code, ChatGPT Desktop, Cursor, …)
drive a **user's own account** on **any** Texera deployment — `texera.dknet-ai.org`,
`hub.texera.io`, a local `bin/local-dev.sh` stack — given only a base URL and a token.

```
┌──────────┐   MCP/stdio    ┌──────────────┐   HTTPS + Bearer JWT   ┌────────────────────┐
│ chatbot  │ ─────────────► │ mcp-service  │ ─────────────────────► │ Texera deployment  │
│ (client) │ ◄───────────── │  (Node/Bun)  │ ◄───────────────────── │  Envoy Gateway     │
└──────────┘   tools/       └──────────────┘   /api/**              └────────────────────┘
               resources                                             │
                                                                     ├─ webserver (workflows, exec, metadata)
                                                                     ├─ file-service (datasets)
                                                                     ├─ computing-unit-manager
                                                                     ├─ workflow-compiling-service
                                                                     └─ config-service
```

---

## 1. What the platform already gives us

### 1.1 One origin, many services

Every deployment fronts all services behind a single Gateway hostname. From
[`bin/k8s/templates/base/gateway/gateway-routes.yaml`](../bin/k8s/templates/base/gateway/gateway-routes.yaml):

| Path prefix | Backing service | Used by the MCP for |
| --- | --- | --- |
| `/api/dataset`, `/api/access/dataset` | file-service :9092 | dataset CRUD, files, versions, sharing |
| `/api/computing-unit`, `/api/access/computing-unit` | computing-unit-manager :8888 | CU lifecycle |
| `/api/compile` | workflow-compiling-service :9090 | pre-run validation, schema propagation |
| `/api/config` | config-service :9094 | capability discovery |
| `/api/models`, `/api/chat` | access-control-service :9096 | (not used) |
| `/api` (catch-all), `/` | webserver :8080 | auth, workflows, versions, metadata, executions |
| `/api/executions/…/stats`, `/wsapi`, `/api/pve` | dynamic (per-CU) backend | (not used in v1) |

**Consequence: the MCP needs exactly one config value for the endpoint — the deployment
base URL.** Everything else is a path under it. This is why "user provides the link of
the deployment" works cleanly.

### 1.2 Authentication

[`common/auth/…/JwtAuthFilter.scala`](../common/auth/src/main/scala/org/apache/texera/auth/JwtAuthFilter.scala)
protects every service identically:

- `Authorization: Bearer <jwt>` → HS256, shared secret (`auth.jwt.256-bit-secret`).
- Claims: `sub` (username), `userId`, `email`, `role`, `exp`.
- Default TTL `auth.jwt.expiration-in-minutes = 10080` (**7 days**), overridable per deployment.
- Tokens are minted by `POST /api/auth/login {username,password}` or the Google flow.
- **No refresh tokens, no API keys, no OAuth authorization server.**
- Failure semantics are precise and machine-readable — RFC 6750:
  - missing header → `401` + `WWW-Authenticate: Bearer realm="texera"`
  - bad/expired token → `401` + `error="invalid_token"`

**Chosen auth model (v1): pre-issued JWT.** The user pastes a token into MCP config:

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

Nothing is stored server-side; the MCP is a stateless proxy holding one bearer token in
memory for the life of the process. To make the 7-day expiry non-mysterious the server:

- decodes `exp` at startup and **fails fast** with an actionable message if already expired;
- warns on every tool result when `exp` is under 24 h away;
- maps any `401 invalid_token` to a single clear error: *"Your Texera token has expired.
  Get a fresh one: log in at `<base>`, then in DevTools run
  `localStorage.getItem("access_token")`, and update `TEXERA_TOKEN`."*

Deferred (documented, not built): personal access tokens (`user_api_token` table +
`/api/auth/tokens` + `JwtAuthFilter` opaque-token branch) would remove the expiry cliff and
give revocability and scoping. That is a backend PR to `apache/texera`, tracked separately.

Remote (HTTP) transport, when added, takes the token from the MCP request's own
`Authorization` header and forwards it — per-request auth context, no shared state,
no credentials at rest.

### 1.3 Workflow representation

Two different shapes, and getting them confused is the classic bug:

| | `WorkflowContent` (stored/edited) | `LogicalPlan` (compiled/executed) |
| --- | --- | --- |
| Where | `workflow.content` — a **JSON string** column | request body of `/api/compile`, `/api/execution/.../run` |
| Operators | `OperatorPredicate` — `operatorID`, `operatorType`, `operatorVersion`, `operatorProperties`, `inputPorts[]`, `outputPorts[]`, `customDisplayName`, … | flattened: properties spread at top level + `operatorID`/`operatorType` |
| Links | `{linkID, source:{operatorID,portID}, target:{operatorID,portID}}` — port IDs are `"input-0"`/`"output-0"` strings | `{fromOpId, fromPortId:{id,internal}, toOpId, toPortId:{id,internal}}` — port **ordinals** |
| Extras | `operatorPositions`, `commentBoxes`, `settings` | `opsToViewResult`, `opsToReuseResult` |

`agent-service` already implements both shapes and the conversion
(`buildLogicalPlan`, `WorkflowUtilService`, `WorkflowState`) — this is the code we lift
into the shared SDK rather than reimplement.

Operator catalogue comes from `GET /api/resources/operator-metadata` (**unauthenticated**):
every operator type with a JSON Schema for its properties plus port metadata. That is
what makes "add a `TableFilter` with these predicates" checkable *before* hitting the server.

### 1.4 Datasets are LakeFS repositories

`file-service` maps each dataset to a LakeFS repo `dataset-<did>`. The critical semantic
for tool design:

```
upload file  ─┐
delete file  ─┼─► uncommitted changes on branch `main`  ──► POST /{did}/version/create ──► immutable version (commit hash)
edit file    ─┘        (visible via GET /{did}/diff)
```

**Uploads are invisible to workflows until a version is created.** A naive MCP that only
exposes "upload" produces a dataset that silently doesn't work. So `dataset_create_version`
is a first-class tool, `dataset_uncommitted_changes` exists, and every upload tool result
tells the model what still has to happen.

Workflows reference dataset files by a path string, resolved by
[`FileResolver`](../common/workflow-core/src/main/scala/org/apache/texera/amber/core/storage/FileResolver.scala):

```
/ownerEmail/datasetName/versionName/relative/path.csv
   e.g. /me@uci.edu/covid/v1/data/cases.csv
```

`dataset_list_files` therefore returns **this exact string** for each file, ready to paste
into a `CSVFileScan.fileName` property. That single detail is what makes
"upload this CSV and build a workflow over it" a two-step conversation instead of a
scavenger hunt.

### 1.5 Execution

`POST /api/execution/{wid}/{cuid}/run` (`SyncExecutionResource`) runs a `LogicalPlan`
**synchronously** and returns per-operator results, row counts, compilation errors and
runtime errors — with server-side caps (`MAX_OPERATOR_RESULT_CHARS = 100_000`,
`MAX_OPERATOR_RESULT_CELL_CHARS = 20_000`). It also supports "execute to operator X"
(`targetOperatorIds` → upstream sub-DAG only).

This is *exactly* the shape an agent needs: one call, terminal result, errors included.
It requires a computing unit — on k8s each CU is a pod, hence the CU management tools.

---

## 2. Architecture

### 2.1 Modules

```
texera/
├── packages/texera-sdk/          # NEW — shared TypeScript client + graph model
│   └── src/
│       ├── types/                # WorkflowContent, LogicalPlan, dataset, CU types
│       ├── api/                  # thin REST clients, one per backend area
│       └── graph/                # WorkflowState, auto-layout, metadata/schema validation
├── agent-service/                # refactored to import @texera/sdk
└── mcp-service/                  # NEW — the MCP server
    └── src/
        ├── config.ts             # env parsing + token introspection
        ├── server.ts             # McpServer wiring, tool registry
        ├── session.ts            # per-workflow edit sessions
        └── tools/                # one module per capability area
```

`@texera/sdk` is consumed via a `file:` dependency (no repo-root `package.json`, so the
frontend's yarn workspace and the sbt build are untouched). `mcp-service` bundles the SDK
into `dist/index.js` for `npx` distribution.

### 2.2 The edit session

Granular tools over server-side state, saved explicitly:

```
workflow_open(wid) ──► GET /api/workflow/{wid}
                       parse content JSON → WorkflowState
                       remember lastModifiedTime          (optimistic-concurrency token)
        │
        ├── workflow_add_operator / modify / delete
        ├── workflow_add_link / delete_link
        ├── workflow_auto_layout                          (dagre, so the graph is readable in the UI)
        └── workflow_validate ──► POST /api/compile       (schema propagation + per-operator errors)
        │
workflow_save() ──► GET /api/workflow/{wid} → compare lastModifiedTime
                    ├─ changed and !force → refuse, tell the model to re-open
                    └─ POST /api/workflow/persist (also snapshots a version)
```

Why not stateless whole-content read/write: an 80 KB `content` blob round-tripped through
the model on every edit is both expensive and a reliable way to produce structurally
invalid graphs. Why not live Yjs co-editing (yet): see §4.

Properties are validated against the operator's JSON Schema **client-side, before**
mutation, so the model gets `"predicates[0].attribute is required; expected {…}"`
instead of a 500 three steps later.

### 2.3 Tool surface

Verb-first, snake_case, area-prefixed. `readOnlyHint` / `destructiveHint` annotations set
so clients can auto-approve reads.

**Session / discovery**

| Tool | Backing call |
| --- | --- |
| `texera_whoami` | decode JWT + `GET /api/config/pre-login`, `/api/config/gui` |

**Datasets**

| Tool | Backing call |
| --- | --- |
| `dataset_list` / `dataset_get` | `GET /api/dataset/list`, `/api/dataset/{did}` |
| `dataset_create` | `POST /api/dataset/create` |
| `dataset_update` (name, description, public, downloadable) | `POST /api/dataset/update/{name,description}`, `/{did}/update/{publicity,downloadable}` |
| `dataset_delete` ⚠ | `DELETE /api/dataset/{did}` |
| `dataset_list_versions` / `dataset_create_version` | `GET /{did}/version/list`, `POST /{did}/version/create` |
| `dataset_list_files` | `GET /{did}/version/{dvid}/rootFileNodes` → flattened + `FileResolver` paths |
| `dataset_upload_file` | `POST /{did}/upload` (single-shot) or `/multipart-upload` (large) |
| `dataset_delete_file` ⚠ | `DELETE /{did}/file` |
| `dataset_read_file` | `GET /presign-download` → fetch, text preview with caps |
| `dataset_uncommitted_changes` | `GET /{did}/diff` |
| `dataset_share` / `dataset_unshare` ⚠ | `PUT /api/access/dataset/grant/…`, `DELETE …/revoke/…` |

**Workflows**

| Tool | Backing call |
| --- | --- |
| `workflow_list` / `workflow_get` | `GET /api/workflow/list`, `/api/workflow/{wid}` |
| `workflow_create` / `workflow_duplicate` | `POST /api/workflow/create`, `/duplicate` |
| `workflow_delete` ⚠ | `POST /api/workflow/delete` |
| `workflow_update` (name, description, public) | `POST /api/workflow/update/{name,description}`, `/public/{wid}`, `/private/{wid}` |
| `workflow_list_versions` | `GET /api/version/{wid}` |
| `workflow_share` / `workflow_unshare` ⚠ | `PUT /api/access/workflow/grant/…`, `DELETE …/revoke/…` |
| **edit session** — `workflow_open`, `_describe`, `_add_operator`, `_modify_operator`, `_delete_operator`, `_add_link`, `_delete_link`, `_auto_layout`, `_validate`, `_save`, `_discard` | see §2.2 |
| `operator_list_types` / `operator_get_schema` | `GET /api/resources/operator-metadata` (cached) |

**Execution**

| Tool | Backing call |
| --- | --- |
| `computing_unit_list` / `_create` / `_terminate` ⚠ | `/api/computing-unit*` |
| `workflow_run` | `POST /api/execution/{wid}/{cuid}/run` |

### 2.4 Resources & prompts

- `texera://operator-metadata` — the operator catalogue (cached, big; a resource rather
  than a tool result so clients can pin it).
- `texera://workflow/{wid}` and `texera://dataset/{did}` — readable snapshots.
- Prompt `build_workflow_from_dataset` — the canonical
  upload → version → scan → transform → run loop, so a fresh chatbot does not have to
  rediscover the ordering constraints.

---

## 3. Safety

| Risk | Mitigation |
| --- | --- |
| Model deletes a dataset/workflow it misidentified | destructive tools require `confirm: true` **and** the exact name as a second argument; `destructiveHint` annotation set |
| Model overwrites edits made in the browser | optimistic concurrency on `lastModifiedTime`; `workflow_save` refuses on drift unless `force` |
| Token leakage into logs/transcripts | token never echoed; redaction in the error formatter; `texera_whoami` returns claims, never the raw token |
| Runaway result payloads | server caps (100 K chars/op) mirrored client-side; list tools paginate; file reads truncate with an explicit marker |
| Upload of a file that never becomes visible | every upload result states the pending-version requirement; `dataset_uncommitted_changes` surfaces it |
| Sharing data with the wrong person ⚠ | `*_share` requires explicit email + privilege, annotated destructive, never inferred |

---

## 4. Known limitation: live co-editing

The workspace UI edits through a Yjs document served at `/rtc` (`SharedModel`); the browser
tab is authoritative while a workflow is open. An MCP `workflow_save` is a REST
last-write-wins persist, so **edits made by the chatbot while the same workflow is open in a
browser tab can be clobbered by the tab** (and vice versa). v1 detects the common case via
`lastModifiedTime` and tells the user to close/reload the tab.

Making the chatbot a first-class co-editor — joining the Yjs room so operators appear on the
canvas live — is the natural v2 and is where this becomes genuinely impressive. It needs a
`y-websocket` client, awareness handling, and conflict semantics; deliberately out of scope
for the first cut.

---

## 5. Delivery plan

| Phase | Content | Verification |
| --- | --- | --- |
| 0 | `packages/texera-sdk` extracted from agent-service; agent-service imports it | `bun test` in agent-service stays green |
| 1 | `mcp-service` scaffold: config, token introspection, error mapping, `texera_whoami`, stdio transport | unit tests w/ mocked fetch; real handshake against a deployment |
| 2 | Dataset tools | unit tests both directions (valid + 401/403/404/oversize/bad path) |
| 3 | Workflow read/CRUD + operator catalogue + resources | unit tests |
| 4 | Edit session + validate + save | unit tests incl. concurrency-drift and invalid-property paths |
| 5 | Computing units + `workflow_run` | unit tests + live run on a deployment |
| 6 | Sharing tools, README, `npx` packaging | end-to-end conversation transcript |

Per [AGENTS.md](../AGENTS.md): tests first, one issue + one PR per phase, Conventional
Commits, `mcp-service` added to `.github/labeler.yml`.
