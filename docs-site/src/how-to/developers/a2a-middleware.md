# A2A Middleware Integration

DRS integrates with Agent-to-Agent (A2A) calls using the same bundle transport
as HTTP-terminated MCP: the full bundle travels in the `X-DRS-Bundle` header as
base64url-encoded JSON.

The middleware validates the bundle before your business handler executes.

## Transport

```
POST /a2a/tasks/send HTTP/1.1
X-DRS-Bundle: <base64url(JSON bundle)>
Content-Type: application/json
```

The bundle must contain the full delegation chain from the original root to the
current caller.

## What happens on failure

- missing bundle: `401`
- malformed base64url/JSON: `400`
- invalid chain: `403`

## Go middleware

```go
package main

import (
    "log"
    "net/http"
    "time"

    "github.com/drs-protocol/drs-verify/pkg/middleware"
    "github.com/drs-protocol/drs-verify/pkg/resolver"
    "github.com/drs-protocol/drs-verify/pkg/verify"
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
    // 1) Define your normal A2A business handler.
    a2aBusinessHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 3) Read verification context after middleware validation.
        ctx := middleware.GetVerificationContext(r.Context())
        if ctx == nil {
            http.Error(w, "missing verification context", http.StatusForbidden)
            return
        }

        // Example: use ctx.RootPrincipal / ctx.ChainDepth / ctx.LeafPolicy.
        w.WriteHeader(http.StatusOK)
    })

    // 2) Wrap your business handler with A2A middleware.
    mux.Handle("/a2a/", middleware.A2AMiddleware(deps,
        a2aBusinessHandler,
    ))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Use `OptionalA2AMiddleware` only when DRS is advisory and your business handler
can safely process requests without a bundle.

## Chain depth in multi-agent A2A topologies

In multi-agent A2A deployments, an orchestrator may dispatch to multiple worker
agents. Each worker carries the full chain to itself:

```
Human → Orchestrator DR → Worker DR → Invocation
```

That worker bundle includes:

- `receipts[0]`: root delegation
- `receipts[1]`: orchestrator → worker sub-delegation
- `invocation`: worker invocation receipt

The orchestrator issues the worker's sub-delegation before dispatch. The worker
issues the invocation receipt when calling the next service.
