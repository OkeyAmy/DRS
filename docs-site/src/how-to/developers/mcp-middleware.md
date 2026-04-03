# MCP Middleware Integration

Add DRS verification to an MCP server. The Go middleware handles all verification — your tool handler code does not change.

## How it works

```
MCP Client
    │  POST /mcp/tools/call
    │  X-DRS-Bundle: <base64url bundle>
    ▼
drs-verify middleware
    │  parse bundle
    │  run verify_chain (blocks A–F)
    ▼ VALID
Your tool handler
    ▼
Response + drs:tool-call event emitted
```

If verification fails, the middleware returns `403` with a JSON error body before your handler is called.

## Option A: Go middleware (native)

If your MCP server is in Go, import the middleware package directly:

```go
package main

import (
    "net/http"
    "time"

    "github.com/yourorg/drs/drs-verify/pkg/middleware"
    "github.com/yourorg/drs/drs-verify/pkg/resolver"
    "github.com/yourorg/drs/drs-verify/pkg/verify"
)

func main() {
    res, _ := resolver.New(10_000, time.Hour)
    verifier := verify.New(res)

    mcp := middleware.NewMCP(verifier, middleware.MCPConfig{
        RequireBundle: true,   // 403 on missing X-DRS-Bundle header
        EmitEvents:    true,   // emit drs:tool-call events
    })

    mux := http.NewServeMux()
    mux.Handle("/mcp/", mcp.Wrap(yourMCPHandler))
    http.ListenAndServe(":8080", mux)
}
```

## Option B: Sidecar (any language)

Run drs-verify as a sidecar in front of your server. It listens on `:8081` and proxies verified requests to your server on `:8080`:

```bash
docker run -d \
  --name drs-verify \
  --network host \
  -e DRS_LISTEN_ADDR=:8081 \
  -e DRS_UPSTREAM=http://localhost:8080 \
  -e DRS_REQUIRE_BUNDLE=true \
  ghcr.io/okeyamy/drs-verify:latest
```

Point your MCP client at `:8081`. Your server on `:8080` only receives requests that have passed full verification.

## Option C: TypeScript VerifyClient

For TypeScript MCP servers that need fine-grained control:

```typescript
import { VerifyClient, parseBundle } from '@drs/sdk';

const drs = new VerifyClient({ baseUrl: process.env.DRS_VERIFY_URL! });

app.post('/mcp/tools/call', async (req, res) => {
  const bundleHeader = req.headers['x-drs-bundle'] as string;

  if (!bundleHeader) {
    return res.status(403).json({ error: 'DRS bundle required' });
  }

  const result = await drs.verify(bundleHeader);
  if (!result.valid) {
    return res.status(403).json({
      error: result.error,
      block: result.block,
      message: result.message,
    });
  }

  // result.context contains:
  //   root_principal, subject, chain_depth, policy_result
  return executeTool(req.body, result.context);
});
```

## Testing your integration

```bash
# Valid bundle — expect 200
DRS_VERIFY_URL=http://localhost:8081 pnpm exec drs verify bundle.json

# Missing bundle — expect 403
curl -X POST http://localhost:8081/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"web_search","query":"test"}'
# {"error":"DRS bundle required"}

# Tampered bundle — expect 403
curl -X POST http://localhost:8081/mcp/tools/call \
  -H "X-DRS-Bundle: $(echo 'corrupt' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"tool":"web_search","query":"test"}'
# {"error":"BUNDLE_INCOMPLETE","block":"A","message":"..."}
```
