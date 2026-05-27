# MCP Gateway

The MCP Gateway sits between an MCP client (e.g. Claude Desktop) and an
upstream MCP server, intercepting every `tools/call` to evaluate it against
Ardur policy before the tool executes.

Source: [`python/vibap/mcp_gateway.py`](../../python/vibap/mcp_gateway.py).

## Architecture

```
┌──────────────┐     stdio/JSON-RPC     ┌──────────────┐     subprocess stdio     ┌──────────────────┐
│  MCP Client  │ ◄────────────────────► │ MCP Gateway  │ ◄─────────────────────► │  Upstream MCP    │
│  (Claude)    │                        │  (Ardur)     │                          │  Server          │
└──────────────┘                        │              │                          └──────────────────┘
                                        │  ┌─────────┐ │
                                        │  │ Policy  │ │
                                        │  │ Engine  │ │
                                        │  └─────────┘ │
                                        └──────────────┘
```

The gateway:
1. Spawns the upstream MCP server as a child process.
2. Forwards `initialize`, `tools/list`, and notifications transparently.
3. Intercepts `tools/call` — evaluates the tool name and arguments against
   the active Ardur policy before forwarding to the upstream server.
4. When configured, runs content safety pre-scan on arguments and post-scan
   on tool output.

## Quickstart

```bash
ardur mcp-gateway --upstream-command npx -- -y @modelcontextprotocol/server-filesystem /tmp
```

With a mission passport and content safety:

```bash
ardur mcp-gateway \
  --upstream-command npx -- -y @modelcontextprotocol/server-filesystem /tmp \
  --mission my-mission.json \
  --content-safety \
  --content-safety-mode deny
```

## Protocol

The gateway speaks **JSON-RPC 2.0** over **stdio** — the standard MCP
transport. It is not an HTTP server or a WebSocket endpoint. It follows the
same contract as any MCP stdio server: read JSON-RPC messages from stdin,
write JSON-RPC responses to stdout, and log to stderr.

### Methods handled

| Method | Behavior |
|--------|----------|
| `initialize` | Forwarded to upstream; returned capabilities are passed through |
| `notifications/initialized` | Forwarded to upstream |
| `tools/list` | Forwarded; manifest is cached for policy context |
| `tools/call` | **Intercepted** — evaluated against Ardur policy. PERMIT → forward to upstream; DENY → return JSON-RPC error |
| All other requests | Forwarded transparently |
| All notifications | Forwarded transparently |

### Policy evaluation

When `tools/call` is intercepted, the gateway:

1. Deserializes the tool name and arguments.
2. (Optional) Runs content safety pre-scan on the arguments. If `safe = False`,
   returns a JSON-RPC error.
3. Evaluates the tool against the active Ardur policy (mission passport,
   session state, tool budgets, resource scope).
4. If `Deny` — returns a JSON-RPC error with the denial reason.
5. If `Permit` — forwards the request to the upstream MCP server.
6. (Optional) Runs content safety post-scan on the upstream response.

### Denial response

When a tool call is denied, the gateway returns:

```json
{
  "jsonrpc": "2.0",
  "id": "<request-id>",
  "error": {
    "code": -32001,
    "message": "Tool call denied by Ardur governance policy",
    "data": {
      "tool_name": "run_command",
      "reason": "Forbidden tool",
      "denial_code": "tool_not_in_allowlist"
    }
  }
}
```

## Session lifecycle

Each gateway instance manages one session:

- On startup, if `--mission` is provided, the gateway starts a governed
  session with that mission passport.
- The session tracks tool-call count, per-class budgets, and elapsed time.
- On shutdown (SIGTERM/SIGINT), the session is finalized and a summary is
  logged.

## Content safety integration

When `--content-safety` is passed:

- **Pre-scan:** Tool arguments are scanned before policy evaluation. Secrets
  found in arguments trigger the configured mode (deny/redact/warn).
- **Post-scan:** Tool output is scanned before being returned to the client.
  Secrets found in output follow the same mode.

Use `--content-safety-mode` to set the global mode:

```bash
--content-safety-mode deny   # Block on any detection
--content-safety-mode redact # Redact secrets, pass redacted content through
--content-safety-mode warn   # Log and continue (default)
```

## Metrics

The gateway emits these Prometheus metrics:

```
ardur_mcp_connections_total{transport="stdio"} 1
ardur_mcp_tools_evaluated_total{decision="permit"} 42
ardur_mcp_tools_evaluated_total{decision="deny"} 3
ardur_mcp_messages_total{method="tools/call"} 45
ardur_mcp_messages_total{method="tools/list"} 1
```

## Caveats

- **Stdio transport only.** The gateway does not support HTTP/SSE MCP
  transports.
- **Single upstream per instance.** Each gateway instance manages exactly one
  upstream MCP server process.
- **No persistent session storage.** Sessions are in-memory only and do not
  survive gateway restart.
- **Upstream process lifecycle.** The gateway spawns and manages the upstream
  process. If the upstream crashes, the gateway exits.
