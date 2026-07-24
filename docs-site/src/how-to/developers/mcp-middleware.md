# MCP Middleware Integration

Add DRS verification to an MCP server. The Go middleware verifies the
`X-DRS-Bundle` header before your business handler runs.

## How it works

```
MCP client
    │  POST /mcp/tools/call
    │  X-DRS-Bundle: <base64url(JSON bundle)>
    ▼
drs-verify/pkg/middleware.MCPMiddleware
    │  decode base64url
    │  parse JSON bundle
    │  run verify.Chain (blocks A–F)
    ▼ VALID
business handler
```

If verification fails:

- missing bundle: `401`
- malformed base64url/JSON: `400`
- invalid chain: `403`

## Go integration

If your MCP-facing server is in Go, wrap the route with
`middleware.MCPMiddleware` or `middleware.OptionalMCPMiddleware`.

```bash
go get github.com/OkeyAmy/DRS/drs-verify
```

```go
package main

import (
    "log"
    "net/http"
    "time"

    "github.com/OkeyAmy/DRS/drs-verify/pkg/middleware"
    "github.com/OkeyAmy/DRS/drs-verify/pkg/nonce"
    "github.com/OkeyAmy/DRS/drs-verify/pkg/resolver"
    "github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
)

func main() {
    res, err := resolver.New(10_000, time.Hour)
    if err != nil {
        log.Fatal(err)
    }

    deps := verify.Deps{
        Resolver: res,
    }

    mux := http.NewServeMux()
    // 1) Define your normal business logic handler.
    mcpBusinessHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 3) Read verification context after middleware has validated the bundle.
        ctx := middleware.GetVerificationContext(r.Context())
        if ctx == nil {
            http.Error(w, "missing verification context", http.StatusForbidden)
            return
        }

        // Example: make authorization/usage decisions with verified identity.
        // ctx.RootPrincipal, ctx.ChainDepth, ctx.LeafPolicy
        w.WriteHeader(http.StatusOK)
    })

    // 2) Configure replay protection and wrap your business handler with MCP middleware.
    nonceStore := nonce.NewMemoryStore(100_000)
    mux.Handle("/mcp/", middleware.MCPMiddleware(
        deps,
        nonceStore,
        "enforced",
        mcpBusinessHandler,
    ))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Use `OptionalMCPMiddleware` only when DRS is advisory and your business handler can
safely process requests without a bundle.

## TypeScript / pure JSON-RPC integration

This Go middleware is the normative HTTP (Shape 1) enforcement path. If your
tool server is Node rather than Go, DRS ships no bundled middleware — you write
a small fail-closed gate against `/verify`, shown in the
[Node tool-server guide](../builders/mcp-node.md#the-gate).

If your MCP traffic is pure JSON-RPC rather than HTTP-terminated (**Shape 2**),
the same base64url bundle rides in `params._meta["X-DRS-Bundle"]`:

- client side: inject the bundle into `params._meta["X-DRS-Bundle"]`
- server side: decode that string, `POST { ...bundle, body }` to `/verify`, and
  require `valid: true` **and** `binding === "match"` — building the binding
  body from `params.name` and `params.arguments`, matching signed invocation
  args such as `{ "tool": "web_search", "query": "..." }`

Both shapes are the same fail-closed check; only where the bundle and body come
from differs.

## Testing your integration

```bash
# Valid bundle — expect exit code 0
DRS_VERIFY_URL=http://localhost:8080 pnpm exec drs verify bundle.json

# Missing bundle — expect 401
curl -X POST http://localhost:8080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"web_search","query":"test"}'

# Malformed bundle — expect 400
curl -X POST http://localhost:8080/mcp/tools/call \
  -H "X-DRS-Bundle: !!!not-base64url!!!" \
  -H "Content-Type: application/json" \
  -d '{"tool":"web_search","query":"test"}'
```
