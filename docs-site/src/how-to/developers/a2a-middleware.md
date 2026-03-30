# A2A Middleware Integration

DRS integrates with the Agent-to-Agent (A2A) protocol using the same bundle mechanism as MCP.

## Transport

The DRS bundle is transmitted as the `X-DRS-Bundle` header in A2A requests, identical to MCP:

```
POST /a2a/tasks/send HTTP/1.1
X-DRS-Bundle: <base64url bundle>
Content-Type: application/json
```

The bundle must contain the full delegation chain from the original human root through every agent hop to the current caller.

## Go middleware

```go
import "github.com/yourorg/drs/drs-verify/pkg/middleware"

a2a := middleware.NewA2A(verifier, middleware.A2AConfig{
    RequireBundle: true,
    HeaderName:    "X-DRS-Bundle",
})

mux.Handle("/a2a/", a2a.Wrap(yourA2AHandler))
```

## Sidecar for non-Go A2A servers

```bash
docker run -d \
  -e DRS_LISTEN_ADDR=:8082 \
  -e DRS_UPSTREAM=http://localhost:8080 \
  -e DRS_REQUIRE_BUNDLE=true \
  ghcr.io/yourorg/drs-verify:latest
```

## Chain depth in multi-agent A2A topologies

In A2A deployments, an orchestrator agent may dispatch to multiple worker agents. Each worker must carry the full chain from the human root to itself:

```
Human → Orchestrator DR → Worker DR → Invocation
```

The Worker's bundle must include:
- `receipts[0]`: Root DR (human → orchestrator)
- `receipts[1]`: Sub-DR (orchestrator → worker)
- `invocation`: Invocation receipt (worker → tool server)

The Orchestrator issues the Sub-DR to the Worker before dispatching the task. The Worker creates the Invocation Receipt.
