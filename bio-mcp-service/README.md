# Texera Bio MCP Service

`bio-mcp-service` is a standalone Bun microservice that exposes biomedical
research tools through the standard Model Context Protocol streamable HTTP
transport.

The agent service does not import BioMCP source directly. Instead, it connects
to this service with the official `@modelcontextprotocol/sdk` MCP client and
discovers tools through `tools/list`.

## Run Locally

```bash
bun install
bun run start
```

By default the service listens on `http://localhost:3010/mcp`.

## Configuration

| Variable | Default | Detail |
| --- | --- | --- |
| `PORT` | `3010` | HTTP port for the MCP service. |
| `MCP_PATH` | `/mcp` | Streamable HTTP MCP endpoint path. |
| `BIOMCP_API_KEY` | unset | Optional shared key required for MCP requests. |
| `API_KEY` | unset | Alternate optional shared key. |
| `OMIM_API_KEY` | unset | Enables OMIM-backed clinical search. |
| `ENABLE_PLACEHOLDER_TOOLS` | `false` | Enables placeholder-backed sequence alignment and protein-structure tools. |
| `ENABLE_OMIM_PLACEHOLDER` | `false` | Enables OMIM search without `OMIM_API_KEY`. |
| `ENABLE_BLAST_PLACEHOLDER` | `false` | Enables placeholder BLAST tool. |

## Health

```bash
curl http://localhost:3010/healthcheck
```

The health response includes the current enabled MCP tool names.

## Agent Integration

Configure `agent-service` with:

```bash
MCP_SERVERS='[{"name":"biomcp","url":"http://localhost:3010/mcp","toolPrefix":"biomcp","apiKeyEnv":"BIOMCP_API_KEY"}]'
BIOMCP_API_KEY=
```

Remote tools are exposed to the model as `<toolPrefix>_<remoteToolName>`, for
example `biomcp_search_pubmed`.
