# Which part of DRS do I install?

DRS has three core layers plus workspace helper packages. Which you install or
vendor depends on what you are building. This page maps common roles to the
artifact(s) you need.

## One-minute decision tree

```
What are you building?
│
├─ An AI agent / client that ACTS on behalf of a user or service
│    → Install @okeyamy/drs-sdk (issuance path)
│
├─ A tool server or gateway that ACCEPTS requests from agents
│    → Run ghcr.io/okeyamy/drs-verify (verification service)
│    → OR embed pkg/gate in your Go server
│
├─ A human-consent UI (user clicks "Approve", you mint a root delegation)
│    → Install @okeyamy/drs-sdk
│
├─ An auditor / compliance replay tool (verify chains after the fact)
│    → Point @okeyamy/drs-sdk VerifyClient at a running drs-verify /verify endpoint
│    → OR run your own drs-verify instance for replay
│
└─ Rust tooling / conformance work (non-normative — not a production verifier)
     → Install drs-core from crates.io
```

## Mapping roles to artifacts

### Role: Agent runtime (Node, browser, React Native, Deno)

Install the SDK from npm.

```bash
pnpm add @okeyamy/drs-sdk
```

You use it to:

- generate keys (`drs keygen` or programmatically)
- issue root delegations (when a human consents)
- issue sub-delegations (when an agent delegates to another agent)
- issue invocations (when the agent actually calls a tool)
- optionally, verify bundles via `VerifyClient`

You **do not** need to run `drs-verify` for issuance. Issuance is all
local cryptography.

### Role: Tool server / MCP server / API gateway

Run the verification service. Two shapes:

**Shape A — sidecar verifier (any language tool server)**

Run `ghcr.io/okeyamy/drs-verify:latest` next to your tool server. In your
server's request handler, before doing real work, call
`POST /v1/gate` with the method, the `X-DRS-Bundle` header and the parsed
body (or `POST /verify` with the bundle plus the executed request as `body`).
If the decision allows the call, proceed.

```
┌─────────────────┐          ┌─────────────────┐
│  your tool      │  POST    │  drs-verify     │
│  server (any    │/v1/gate─▶ :8080 (sidecar) │
│  language)      │  ◀─json─ │                 │
└─────────────────┘          └─────────────────┘
```

Best for: Node, Python, Rust, Ruby, Java — anything not Go.

**Shape B — embedded Go middleware**

If your tool server is in Go, import the middleware package directly.
Faster path (no extra hop), but Go-only.

```go
import "github.com/OkeyAmy/DRS/drs-verify/pkg/gate"

cfg, err := gate.NewConfig(deps, nonceStore, binding.ModeEnforced)
mux.Handle("/mcp", gate.Middleware(cfg, gate.MCP{}, yourMCPHandler)) // or gate.A2A{}, gate.HTTP{}
```

Best for: Go MCP servers, Go A2A servers.

### Role: Human-consent UI

Install the SDK from npm, same as an agent. The difference is semantic:
your app's `issueRootDelegation` call represents the moment a human
clicked "Approve". Capture consent metadata (session ID, policy hash,
timestamp) in the `consent` field.

See [Human Consent Records](../developers/human-consent.md).

### Role: Auditor / compliance reviewer

Install the SDK and use its `VerifyClient` to replay past chains against a
running `drs-verify` endpoint. For air-gapped replay, run `drs-verify` inside
the air-gapped environment; the SDK does not currently ship a full in-process
verifier.

```bash
pnpm add @okeyamy/drs-sdk
```

```ts
import { VerifyClient } from "@okeyamy/drs-sdk";

const client = new VerifyClient({ baseUrl: "https://drs-verify.internal" });
// body: the parsed request your server is about to execute
const result = await client.verify(bundle, { body: requestBody });
```

### Role: Rust tooling builder

Most builders do not need to call `drs-core` directly — it is a
non-normative, feature-frozen reference implementation, not a production
verifier. If you're building Rust tooling that needs the DRS primitives
(canonicalisation, chain hashing, issuance) in-process, use the crate:

```toml
[dependencies]
drs-core = "0.1"
```

See [Use drs-core directly (Rust)](./rust-core.md) for the in-process
primitives and their limits.

## Combining them

A typical production deployment uses all three:

```
┌──────────────────────┐
│ Agent (React Native) │   uses @okeyamy/drs-sdk (npm)
└──────────┬───────────┘
           │  HTTPS: X-DRS-Bundle: <base64url>
           ▼
┌──────────────────────┐
│ Tool server (Node)   │   forwards body + bundle
└──────────┬───────────┘
           │  POST /verify
           ▼
┌──────────────────────┐
│ drs-verify (Docker)  │   runs from ghcr.io/okeyamy/drs-verify
│ + Redis (replay)     │
└──────────────────────┘
```

None of these three boxes clones the DRS monorepo.

## Related

- [You do not need to fork](./no-fork-required.md)
- [Integrate with MCP (Node)](./mcp-node.md)
- [Integrate with React Native](./react-native.md)
- [Integrate with a non-Go HTTP gateway](./node-backend.md)
