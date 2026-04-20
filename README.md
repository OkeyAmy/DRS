# Delegation Receipt Standard (DRS)

> Infrastructure-grade accountability layer for agentic AI systems.

DRS is a cryptographic delegation receipt protocol implemented in this repository as JWT receipts, RFC 8785 JCS canonicalization, Ed25519 signatures, DID-based identity, and SHA-256 hash chaining. Every time an AI agent acts on behalf of a human, DRS produces a signed, hash-chained receipt that proves — to a human, an auditor, or a regulator — who authorized the action, what was permitted, and when the authorization was granted.

**Documentation → [okeyamy.github.io/DRS](https://okeyamy.github.io/DRS/)**

**Plugging DRS into your product? You do not need to fork this repo.**
DRS ships as three published artifacts you install like any other
dependency:

- `@okeyamy/drs-sdk` — `pnpm add @okeyamy/drs-sdk` (issuance, Node / RN / browser)
- `ghcr.io/okeyamy/drs-verify` — `docker pull` (verification service)
- `drs-core` — `cargo add drs-core` (Rust crypto / WASM core)

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
| `drs-verify` | Go | HTTP verification server, MCP/A2A middleware, LRU caches, revocation, RFC 3161 anchor |
| `drs-sdk` | TypeScript | Developer-facing SDK, issuance path, WASM bundle |

Rust compiles to native and WASM. Go compiles to a single static binary (`CGO_ENABLED=0`). TypeScript ships the WASM bundle — no native compilation step for developers.

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

curl http://localhost:8080/metrics | head -5
# # HELP drs_verify_verifications_total Total verification attempts by outcome.
```

See [`.env.example`](./.env.example) for every supported configuration variable.

### Issue and verify a receipt

```bash
# Install the SDK
pnpm add @okeyamy/drs-sdk

# Generate a keypair
npx drs keygen
```

```ts
import { issueRootDelegation } from '@okeyamy/drs-sdk'

const dr = await issueRootDelegation({
  issuerKey: operatorKey,
  subject:   'did:key:z6Mk...',
  policy:    { max_cost_usd: 1.00, allowed_tools: ['web_search'] },
  expiresIn: 3600,
})
```

```bash
# Verify a bundle
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d @bundle.json
```

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

### MCP and A2A middleware — `POST /mcp/*` and `POST /a2a/*`

Drop `drs-verify` in front of your MCP or A2A server. It extracts the `X-DRS-Bundle` header, runs the full verification chain, and forwards verified requests with the `VerificationContext` attached. Unverified requests get `401`. Invalid bundles get `403`. Replayed invocations get `409`.

```go
mux.Handle("/mcp/", middleware.MCPMiddleware(deps, nonceStore, yourHandler))
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
- **RFC 8785 JCS canonicalization** — no `JSON.stringify` key sort, no canonicalization divergence across implementations
- **LRU-bounded DID resolver cache** — hard cap at 10,000 entries (~640 KB)
- **W3C Bitstring Status List revocation** — `sync.Once` concurrency guard prevents thundering herd on cache miss
- **Request body capped** at 1 MiB by default (`MAX_BODY_BYTES`)
- **DID resolver** supports `did:key` (self-authenticating, no network I/O) and `did:web` (HTTPS + TLS)

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
| `NONCE_STORE_MAX_ENTRIES` | `100000` | Replay protection store capacity |
| `NONCE_STORE_TTL_SECS` | `3600` | Replay protection TTL (1 hour) |
| `DRS_ADMIN_TOKEN` | — | Bearer token for `POST /admin/revoke` |
| `STORE_DIR` | — | Filesystem store base directory (Tier 1/3) |
| `TSA_URL` | — | RFC 3161 TSA endpoint — enables Tier 3 store |
| `MAX_BODY_BYTES` | `1048576` | Maximum request body size (1 MiB) |
| `LOG_LEVEL` | `info` | Log level: debug / info / warn / error |

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
drs-sdk/            TypeScript — SDK, WASM bundle, CLI
docs/               Architecture documents and technical audit
docs-site/          mdBook source → okeyamy.github.io/DRS
examples/           DRS wired into real agentic systems (contributions welcome)
```

## Implementation Status

**Fully implemented:**

- Six-block chain verification (Blocks A–F)
- Nonce replay protection for MCP and A2A middleware
- `did:key` and `did:web` DID resolution with LRU cache
- W3C Bitstring Status List revocation with concurrency guard
- Local revocation store with `POST /admin/revoke`
- RFC 3161 trusted timestamp anchor (Tier 3 store)
- TypeScript SDK: issuance, CLI (`drs keygen`, `drs issue`, `drs verify`, `drs audit`)
- Docker deployment (distroless image, static binary)
- Human-rooted consent records with session ID, policy hash, and locale

See [CONTRIBUTING.md](CONTRIBUTING.md) for open work and how to get involved.

**Roadmap:**

- EU AI Act / HIPAA / SOX audit export formats
- Structured logging (`log/slog`)
- Circuit breaker for `did:web` resolution
- Ethereum mainnet anchor (Tier 5 — opt-in only)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
