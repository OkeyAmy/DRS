# Delegation Receipt Standard (DRS)

> Infrastructure-grade accountability layer for agentic AI systems.

DRS is a cryptographic delegation receipt protocol implemented in this repository as JWT receipts, RFC 8785 JCS canonicalization, Ed25519 signatures, DID-based identity, and SHA-256 hash chaining. Every time an AI agent acts on behalf of a human, DRS produces a signed, hash-chained receipt that proves — to a human, an auditor, or a regulator — who authorized the action, what was permitted, and when the authorization was granted.

**Documentation → [okeyamy.github.io/DRS](https://okeyamy.github.io/DRS/)**

**Plugging DRS into your product? You do not need to fork this repo.**
DRS ships as published core artifacts plus workspace helper packages you install
or vendor according to your deployment shape:

- `@okeyamy/drs-sdk` — `pnpm add @okeyamy/drs-sdk` (issue receipts and bundles)
- `ghcr.io/okeyamy/drs-verify` — `docker pull` (verifier trust engine)
- `drs-core` — `cargo add drs-core` (Rust crypto / WASM core)
- `@drs/mcp-server` — workspace Node app enforcement middleware; use from this
  monorepo until it is included in the release workflow

Product shape: use the SDK to issue, use middleware or a future gateway to
enforce, and use the verifier service as the trust engine. `drs-verify` answers
whether a bundle is trusted; your app middleware decides whether the protected
handler may execute.

Start at the [Builder guides](https://okeyamy.github.io/DRS/how-to/builders/no-fork-required.html)
to map your role (React Native, MCP server, A2A agent, Node backend)
to the right artifact.

---

## The Problem

When an AI agent sub-delegates work to other agents, ordinary bearer-token context and server logs lose the chain of custody. An attacker can splice a forged delegation into the middle of the chain and the tool server has no way to detect it. DRS closes this gap with a tamper-evident, hash-linked receipt at every hop — from the human who clicked "approve" to the agent that executed the tool call.

OAuth 2.1, RFC 8693, and MCP are important surrounding ecosystem context, but this repository does not currently implement OAuth 2.1 or RFC 8693 runtime flows.

## How It Works

```
Human approves (consent record with session ID + policy hash)
  └─ Root Delegation Receipt issued (signed by operator key)
       └─ Sub-delegation Receipt issued (signed by agent A)
            └─ Invocation Receipt issued (signed by agent B)
                 └─ Tool Server verifies the full chain before executing
                      └─ Auditor reconstructs the chain months later
```

Each receipt is an Ed25519-signed JWT. Each receipt's hash is carried in the next receipt's `prev_dr_hash` field. The chain cannot be reordered, truncated, or spliced without breaking the hash linkage. The verifier checks all of this — six verification blocks — before allowing a tool call through.

## Architecture

Three-layer language stack chosen for correctness, performance, and deployability:

| Layer | Language | Responsibility |
|---|---|---|
| `drs-core` | Rust | Ed25519 crypto, SHA-256 chain computation, RFC 8785 JCS canonicalization, capability index |
| `drs-verify` | Go | HTTP verification service, LRU caches, revocation, RFC 3161 anchor |
| `drs-sdk` | TypeScript | Developer-facing SDK, issuance path, bundle helpers, CLI, HTTP verify client |
| `@drs/mcp-server` | TypeScript | Workspace Node HTTP/MCP enforcement middleware that calls `drs-verify` before app handlers execute |

Rust compiles to native and can be built to WASM. Go compiles to a single static binary (`CGO_ENABLED=0`). The TypeScript SDK issues receipts natively with `@noble/ed25519` and verifies exclusively through the HTTP `VerifyClient` against a running `drs-verify` service — there is no supported in-process/WASM verification path. `drs-core` remains the non-normative, frozen algorithm reference.

## What DRS proves — and what it does not

DRS receipts are cryptographic evidence of **authorisation and claims**, not
of runtime behaviour. Read this before designing your policy model:

| Policy field | What the verifier proves |
|---|---|
| `max_cost_usd` | The invoker **claimed** `estimated_cost_usd` within the limit — it signed that claim. The verifier cannot know the actual cost. **The tool owner must validate real cost.** |
| `pii_access`, `write_access` | The invoker **claimed** compliance. Enforcement of actual data access is the tool owner's responsibility. |
| `allowed_tools`, `allowed_resources`, `allowed_data_classes` | The named tool/resource/class in the signed args is within the delegated set. The binding check (`body` ↔ `invocation.args`) additionally proves the executed request matches the signed args. |
| `max_calls` | **Nothing — informational only.** The verifier is stateless; call counting belongs in your session layer, using the leaf policy returned in `VerificationContext`. |

Two further operational notes:

- `/verify` is unauthenticated by design in the current release. Anyone
  holding a captured bundle can consume its replay nonce (JTI) at the
  endpoint before the legitimate tool server does — a denial-of-service on
  that one invocation, not an authorisation bypass. Rate limiting bounds it;
  API-key authentication closes it in a future release.
- Human-consent records (`drs_consent`) currently prove consent **existed**
  (method, session, timestamp). The `policy_hash` field is checked for
  presence, not yet bound to the policy content — the canonical preimage is
  defined in DRS 4.1.

## Quick Start

### Run the verifier (zero config)

Either with the published image directly:

```bash
docker run -p 8080:8080 ghcr.io/okeyamy/drs-verify:latest
```

Or with Docker Compose if you want `.env`-based configuration:

```bash
git clone https://github.com/OkeyAmy/DRS
cd DRS
cp .env.example .env            # review defaults; set DRS_ADMIN_TOKEN if needed
docker compose up -d

curl http://localhost:8080/healthz
# {"status":"ok"}

# Metrics are disabled by default. Set METRICS_ADDR=:9090 and expose that
# listener separately if you want Prometheus metrics.
curl http://localhost:9090/metrics | head -5
# # HELP drs_verify_verifications_total Total verification attempts by outcome.
```

See [`.env.example`](./.env.example) for every supported configuration variable.

### Issue and enforce a request

```bash
# Install the SDK
pnpm add @okeyamy/drs-sdk

# Generate a keypair
npx drs keygen
```

```ts
import { createInvocationBundle, issueRootDelegation, serialiseBundle } from '@okeyamy/drs-sdk'

const dr = await issueRootDelegation({
  signingKey: operatorKey,
  issuerDid: operatorDid,
  subjectDid: operatorDid,
  audienceDid: agentDid,
  cmd: '/mcp/tools/call',
  policy: { max_cost_usd: 1.00, allowed_tools: ['web_search'] },
  nbf: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
})

const bundle = await createInvocationBundle({
  rootReceipt: dr,
  signingKey: agentKey,
  issuerDid: agentDid,
  subjectDid: operatorDid,
  toolServer: toolServerDid,
  tool: 'web_search',
  args: { query: 'delegation receipts' },
})

const drsHeader = serialiseBundle(bundle)
```

Protected Node apps should receive that header as `X-DRS-Bundle`, pass the
exact parsed request body to `/verify`, and execute only when verification is
valid and `binding === "match"`. Use the workspace `@drs/mcp-server` HTTP
middleware for that pattern, or copy the same fail-closed checks into your own
framework adapter.

## HTTP API

### `POST /verify`

Accepts a `ChainBundle` JSON body. Runs all six verification blocks. Returns `VerificationResult` JSON — check `result.valid` in the body.

```json
{
  "valid": true,
  "context": {
    "root_principal": "did:key:z6Mk...",
    "root_type": "human",
    "chain_depth": 2,
    "session_id": "sess_abc123"
  }
}
```

### MCP, A2A, and Node app middleware

`drs-verify` exposes `POST /verify`; it is not a transparent MCP/A2A proxy. For
Node tool servers, use the workspace `@drs/mcp-server` HTTP middleware to extract the `X-DRS-Bundle` header,
send the bundle plus the parsed request body to `/verify`, reject invalid chains
or body-binding mismatches, and call your handler with `VerificationContext`
attached. For Go tool servers, import the reusable Go middleware and mount it
inside your own server.

```go
mux.Handle("/mcp/", middleware.MCPMiddleware(deps, nonceStore, "enforced", yourHandler))
```

### `POST /admin/revoke`

Marks a delegation by its status list index as locally revoked. Requires `Authorization: Bearer <DRS_ADMIN_TOKEN>`.

### `GET /healthz` / `GET /readyz`

Kubernetes and Docker health probes.

## Security Properties

- **Ed25519** via `ed25519-dalek` 2.x — RUSTSEC-2022-0093 patched, `verify_strict` semantics in Rust core
- **Nonce replay protection** — invocation JTIs checked against a bounded TTL-evicting store before chain verification; replays get `409 Conflict`
- **Fail-closed** — any verification error denies the capability; there is no partial success
- **Constant-time comparisons** — multicodec prefix checks and bearer token validation use `crypto/subtle`
- **RFC 8785 JCS canonicalization** — no shallow `JSON.stringify` key sort; conformance vectors guard cross-language canonicalization behavior
- **LRU-bounded DID resolver cache** — hard cap at 10,000 entries (~640 KB)
- **W3C Bitstring Status List revocation** — mutex + re-check concurrency guard prevents thundering herd on cache miss (`sync.Once` is deliberately avoided: a failed fetch must be retryable)
- **Request body capped** at 64 KiB — hard-coded, not configurable, so a deployment cannot accidentally widen it
- **DID resolver** supports `did:key` (self-authenticating, no network I/O) and `did:web` (HTTPS + TLS)

## Performance

Measured against the published artifacts (`ghcr.io/okeyamy/drs-verify` v0.1.1,
`@okeyamy/drs-sdk` 0.1.1 from npm) with 15 simulated developers, each with
their own keypair, delegation chain, and client IP. Full methodology and the
replicable harness live in the standalone
[**drs-bench**](https://github.com/OkeyAmy/drs-bench) repository (see its
[RESULTS.md](https://github.com/OkeyAmy/drs-bench/blob/main/RESULTS.md));
numbers below are from a 4-core/8-thread laptop — treat them as relative,
not absolute.

| Measurement | Result |
|---|---|
| Verification floor latency (depth-1 chain) | ~2.8 ms avg |
| Verification at the depth cap (16 receipts) | ~8.6 ms avg |
| Steady multi-tenant load (300 rps, depth 4) | p95 5.4 ms, ~1 core, 0 errors |
| Single-instance saturation (depth 4) | ~800 rps at 5 cores |
| Replay storm (10 % replayed JTIs at 300 rps) | all replays 409, latency unchanged |
| Full topology (agent → org tool server → verifier → tool, 300 rps) | ~5.5 ms median per tool call — the enforcement hop costs ~2.3 ms over direct `/verify` |
| Redis nonce backend vs in-memory | +0.4 ms avg — the full cost of multi-replica replay safety |
| SDK issuance (per Node process) | ~217 bundles/s (depth 1) → ~114 (depth 16) |

Past ~800 rps a single instance queues; scale horizontally — the Redis nonce
store already makes replicas replay-safe.

## Configuration

All configuration is environment-variable driven. No hard-coded URLs, ports, or keys.

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `SERVER_IDENTITY` | — | This server's DID — enforces `invocation.tool_server` binding |
| `DID_CACHE_SIZE` | `10000` | LRU DID resolver cache cap |
| `DID_CACHE_TTL_SECS` | `3600` | DID cache TTL (1 hour) |
| `STATUS_LIST_BASE_URL` | — | W3C Bitstring Status List endpoint |
| `STATUS_CACHE_TTL_SECS` | `300` | Status list cache TTL (5 min) |
| `NONCE_STORE_BACKEND` | `memory` | Replay backend: `memory` or `redis` |
| `REDIS_URL` | — | Required when `NONCE_STORE_BACKEND=redis` |
| `NONCE_STORE_MAX_ENTRIES` | `100000` | Replay protection store capacity |
| `NONCE_STORE_TTL_SECS` | `3600` | Replay protection TTL (1 hour) |
| `DRS_ADMIN_TOKEN` | — | Bearer token for `POST /admin/revoke` |
| `REVOCATION_STORE_PATH` | — | Optional durable local revocation log path |
| `STORE_DIR` | — | Filesystem store base directory (Tier 1/3) |
| `TSA_URL` | — | RFC 3161 TSA endpoint — enables Tier 3 store |
| `MAX_BODY_BYTES` | `1048576` | Maximum request body size (1 MiB) |
| `LOG_LEVEL` | `info` | Log level: debug / info / warn / error |
| `LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `METRICS_ADDR` | — | Separate Prometheus listener; empty disables metrics |

## Storage Tiers

| Tier | Backend | Use case |
|---|---|---|
| 0 | In-memory LRU | Development and testing (default) |
| 1 | Filesystem | Standard production (`STORE_DIR`) |
| 2 | S3-compatible | Long-term retention (roadmap) |
| 3 | WORM + RFC 3161 | Regulated deployments (`STORE_DIR` + `TSA_URL`) |
| 5 | Ethereum mainnet | Blockchain-native enterprise (opt-in only, roadmap) |

Tier 3 uses RFC 3161 trusted timestamping — legally recognized under EU eIDAS and admissible in US federal courts. Supported TSA providers: FreeTSA (free), DigiCert, GlobalSign.

## Verification Algorithm

The verifier runs six blocks in sequence. All must pass. Failure is fail-closed.

| Block | Name | What it checks |
|---|---|---|
| A | Completeness | Bundle has receipts and an invocation |
| B | Structural Integrity | Hash chain linkage, JTI prefixes, issuer continuity, subject consistency |
| C | Cryptographic Validity | Ed25519 signature on every receipt and the invocation |
| D | Policy Validity | Command attenuation, capability subset checks, invocation args satisfy all policies |
| E | Temporal Validity | `nbf` / `exp` bounds on every receipt |
| F | Revocation | W3C Bitstring Status List + local revocation store |

## Repository Layout

```
drs-core/           Rust — crypto primitives, capability index, WASM target
drs-verify/         Go  — verification server, middleware, caches
  pkg/nonce/        Replay protection store
  pkg/verify/       Six-block verification algorithm
  pkg/resolver/     DID resolver (did:key, did:web)
  pkg/revocation/   Status list cache and local revocation store
  pkg/middleware/   MCP and A2A HTTP middleware
  pkg/anchor/       RFC 3161 trusted timestamp client and verifier
  pkg/policy/       Capability policy evaluation and attenuation
  pkg/store/        Tiered receipt storage (memory, filesystem, Tier3)
drs-sdk/            TypeScript — SDK, HTTP verify client, CLI
docs-site/          mdBook source → okeyamy.github.io/DRS
examples/           DRS wired into real agentic systems (contributions welcome)
```

## Implementation Status

**Fully implemented:**

- Six-block chain verification (Blocks A–F)
- Nonce replay protection with in-memory and Redis backends
- `did:key` and `did:web` DID resolution with LRU cache
- SSRF hardening and circuit breaker for `did:web` resolution
- W3C Bitstring Status List revocation with concurrency guard
- Local revocation store with `POST /admin/revoke`, optionally file-backed
- RFC 3161 trusted timestamp anchor (Tier 3 store)
- TypeScript SDK: issuance, CLI (`drs keygen`, `drs issue`, `drs verify`, `drs audit`)
- Structured logging via `log/slog`
- Docker deployment (distroless image, static binary)
- Human-rooted consent records with session ID, policy hash, and locale

See [CONTRIBUTING.md](CONTRIBUTING.md) for open work and how to get involved.

**Roadmap:**

- EU AI Act / HIPAA / SOX audit export formats
- KMS/HSM signing integration
- Durable object-store backend (Tier 2)
- Ethereum mainnet anchor (Tier 5 — opt-in only)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
