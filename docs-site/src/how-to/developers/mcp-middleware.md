# MCP Middleware Integration

Gate an MCP server so every `tools/call` must carry a DRS bundle signed for
exactly the arguments it executes. Works with MCP protocol versions
`2025-11-25` and `2026-07-28`, over Streamable HTTP or stdio.

## What the gate does

```
MCP client ──► gate (pkg/gate MCP adapter)
                 │ initialize, server/discover, tools/list, notifications, GET → pass through
                 │ tools/call → bundle from X-DRS-Bundle header or params._meta["xyz.okeyamy.drs/bundle"]
                 │            → verify chain → invocation.cmd == /mcp/tools/call
                 │            → signed args == params.arguments + {"tool": params.name}
                 │            → commit jti (replay protection)
                 ▼
            MCP server handler
```

The agent signs `args = { ...arguments, tool: name }` under `cmd: "/mcp/tools/call"`.
An argument named `tool` is reserved and refused.

Refusals are JSON-RPC errors that echo the request `id`, code `-32010`, with
`error.data.code` set to `MISSING_BUNDLE`, `BINDING_MISMATCH`, `REPLAY_DETECTED`,
`POLICY_VIOLATION`, `CMD_MISMATCH`, `HEADER_MISMATCH`, … A missing bundle is
HTTP **403**, never 401 — MCP clients treat 401 as an OAuth challenge.

## Go: the official Go MCP SDK behind `gate.Middleware`

```bash
go get github.com/OkeyAmy/DRS/drs-verify
```

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/binding"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/gate"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/nonce"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	srv := mcp.NewServer(&mcp.Implementation{Name: "tools", Version: "1.0.0"}, nil)
	// mcp.AddTool(srv, ...) — register your tools as usual.

	deps, err := verify.NewDefaultDeps("did:web:tools.example") // this server's identity
	if err != nil {
		log.Fatal(err)
	}
	// Use nonce.NewRedisStore for multi-replica deployments.
	cfg, err := gate.NewConfig(deps, nonce.New(100_000, 15*time.Minute), binding.ModeEnforced)
	if err != nil {
		log.Fatal(err)
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	http.Handle("/mcp", gate.Middleware(cfg, gate.MCP{}, mcpHandler))
	log.Fatal(http.ListenAndServe(":3000", nil))
}
```

Inside a tool, `gate.VerificationContext(ctx)` returns the verified root
principal, chain depth and leaf policy.

`binding.ModeLenient` (log, don't refuse) and `binding.ModeOff` exist for
migrations. `binding.ParseMode` and `gate.NewConfig` reject unknown modes and a
nil nonce store, so a configuration typo cannot silently open the gate.

## Node / other languages

Use `@drs/mcp-server` (server) and `@drs/mcp-client` (agent). The server
package forwards each request to a running drs-verify at `POST /v1/gate`; all
protocol rules stay in Go. See [MCP on a Node server](../builders/mcp-node.md).

## Testing

The live suite in `integration-tests/` runs the official MCP SDKs (v1.31,
v2.2 in both protocol eras, stdio) and the official Go MCP SDK against this
gate, including tampering, replay, tool swap and unsigned-call attacks:

```bash
cd integration-tests/go && go test ./...
cd integration-tests && DRS_VERIFY_URL=http://127.0.0.1:8080 pnpm test:protocols
```
