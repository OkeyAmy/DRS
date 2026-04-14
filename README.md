# Delegation Receipt Standard (DRS)

> **Research Project** — Infrastructure-grade accountability layer for agentic AI systems.

DRS is a per-step delegation receipt standard built on top of OAuth 2.1 + RFC 8693 + MCP that issues cryptographically signed receipts at every step of an agentic delegation chain — so humans, auditors, and regulators can prove *who authorized what, to whom, and when*.

**Full documentation → [okeyamy.github.io/DRS](https://okeyamy.github.io/DRS/)**

---

## The Problem

When an AI agent sub-delegates work to other agents, standard OAuth 2.1 and JWT-based flows lose the chain of custody. An attacker can splice a forged delegation into the middle of the chain (CVE-2025-55241) and the tool server cannot detect it. DRS closes this gap with a tamper-evident receipt at every hop.

## Architecture

Three-layer language stack chosen for correctness and performance:

| Layer | Language | Responsibility |
|---|---|---|
| `drs-core` | Rust | Ed25519 crypto, CID computation, RFC 8785 JCS canonicalization, capability index |
| `drs-verify` | Go | Verification server, MCP/A2A middleware, LRU caches, revocation, RFC 3161 anchor |
| `drs-sdk` | TypeScript | Developer SDK, issuance path, WASM bundle |

```
End User
  └─ issues Root DR (drs-sdk)
       └─ Developer sub-delegates (drs-sdk)
            └─ Agent Runtime invokes tool (drs-sdk)
                 └─ Tool Server verifies chain (drs-verify + drs-core)
                      └─ Auditor reconstructs chain (drs-verify CLI)
```

## Quick Start

```bash
# Install the SDK
pnpm add @okeyamy/drs-sdk

# Generate a keypair
npx drs keygen --out operator.key

# Issue a root delegation
import { issueRootDelegation } from '@okeyamy/drs-sdk'
const dr = await issueRootDelegation({
  issuerKey: operatorKey,
  subject:   'did:key:z6Mk...',
  policy:    [['==', '.tool', '"web_search"']],
  expiresIn: 3600,
})

# Start the verification server
docker run -p 8080:8080 \
  -e DRS_OPERATOR_DID=did:key:z6Mk... \
  ghcr.io/okeyamy/drs-verify:latest

# Verify a bundle (returns full VerificationResult JSON)
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d @bundle.json
```

## HTTP API

### `POST /verify`

Verifies a DRS chain bundle. Accepts a `ChainBundle` JSON body. Returns `VerificationResult` JSON. HTTP 200 on all responses (check `result.valid` in the body).

### `POST /admin/revoke`

Marks a delegation receipt as locally revoked by its status list index. Requires `Authorization: Bearer <DRS_ADMIN_TOKEN>` header.

```bash
curl -X POST http://localhost:8080/admin/revoke \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{"status_list_index": 42}'
```

### `GET /healthz` / `GET /readyz`

Health and readiness probes for Kubernetes/Docker.

### `POST /mcp/*` / `POST /a2a/*`

MCP and A2A middleware routes — extract the `X-DRS-Bundle` header, verify, and forward verified requests.

## Storage Tiers

| Tier | Name | Backend | Use case |
|---|---|---|---|
| 0 | Session | In-memory | Development and testing (default) |
| 1 | Ephemeral | Filesystem | Standard production (set `STORE_DIR`) |
| 2 | Durable | S3-compatible | Long-term retention (roadmap) |
| 3 | Compliant | WORM + RFC 3161 | Regulated deployments — WORM with cryptographic timestamps (set `STORE_DIR` + `TSA_URL`) |
| 4 | Timestamped | Tier 3 + per-DR TSToken | EU AI Act or third-party time proof (set `STORE_DIR` + `TSA_URL`) |
| 5 | On-Chain | Tier 3 + Ethereum | Explicit customer requirement only — gas costs apply (roadmap) |

Tiers 3 and 4 use RFC 3161 trusted timestamping (IETF 2001) — legally recognized under EU eIDAS and US federal courts. No gas fees. TSA providers: FreeTSA (free), DigiCert, GlobalSign. See [`docs/storage-tiers.md`](docs/storage-tiers.md) for the full tier reference.

## Configuration

All configuration is environment-variable driven. No hard-coded URLs, ports, or keys.

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `DID_CACHE_SIZE` | `10000` | LRU DID resolver cache cap (~640 KB) |
| `DID_CACHE_TTL_SECS` | `3600` | DID cache entry TTL |
| `STATUS_LIST_BASE_URL` | — | W3C Bitstring Status List endpoint |
| `STATUS_CACHE_TTL_SECS` | `300` | Status list cache TTL (5 min) |
| `DRS_ADMIN_TOKEN` | — | Bearer token for `POST /admin/revoke` (required to enable the endpoint) |
| `STORE_DIR` | — | Base directory for filesystem store (Tier 1/3) |
| `TSA_URL` | — | RFC 3161 TSA endpoint — enables Tier 3 store |
| `MAX_BODY_BYTES` | `1048576` | Maximum request body size (1 MiB) |
| `LOG_LEVEL` | `info` | Log level: debug / info / warn / error |

## Repository Layout

```
drs-core/          Rust — crypto primitives and capability index
drs-verify/        Go  — verification server and middleware
drs-sdk/           TypeScript — developer SDK
docs/              Architecture documents and technical audit
docs-site/         mdBook source for the documentation site
.github/workflows/ CI: docs deploy to GitHub Pages on every push
```

## Documentation

The docs cover four audiences:

| Audience | What you'll find |
|---|---|
| **Developers** | SDK install, MCP/A2A middleware, issuance guide |
| **Operators** | Deployment, key management, revocation, storage tiers |
| **Auditors** | Chain reconstruction, EU AI Act export, HIPAA evidence |
| **Contributors** | Architecture deep-dive, testing standards, false-positive history |

→ **[Read the docs](https://okeyamy.github.io/DRS/)**

## Security

- Ed25519 signatures via `ed25519-dalek` 2.x (RUSTSEC-2022-0093 patched)
- Constant-time multicodec prefix comparison (no timing oracle)
- RFC 8785 JCS canonicalization (no `JSON.stringify` key sort)
- Fail-closed capability checks — error = denied
- LRU-bounded DID resolver cache (10,000 entries max)
- Bitstring Status List revocation with `sync.Once` concurrency guard
- Admin revocation endpoint requires bearer token (`DRS_ADMIN_TOKEN`)
- Request body capped at 1 MiB by default (`MAX_BODY_BYTES`)

## Implementation Status

**Fully implemented:**

- Six-block chain verification algorithm (Blocks A–F: completeness, structural integrity, Ed25519 signatures, policy attenuation, temporal validity, revocation)
- MCP and A2A protocol middleware
- LRU DID resolver cache with TTL
- W3C Bitstring Status List revocation cache (sync.Once concurrency guard)
- Local revocation store with `POST /admin/revoke`
- RFC 3161 trusted timestamp anchor (Tier 3 store)
- TypeScript SDK: issuance path, CLI (`drs keygen`, `drs issue`, `drs verify`, `drs audit`)
- Docker deployment (distroless, static binary)

**Roadmap:**

- EU AI Act / HIPAA / SOX audit export formats
- Ethereum mainnet blockchain anchor (Tier 5 — opt-in only, for blockchain-native enterprise deployments)
- Automated system root renewal logic

## Status

This is a research project. APIs are not stable. Do not deploy to production without a full security audit.

Version history: v1 (scrapped — wrong threat model), v2 (scrapped — wrong UCAN version + O(n·m) capability check), v3 (migrated to OAuth 2.1), v4 (current).

## License

MIT
