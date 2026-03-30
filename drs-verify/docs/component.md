# drs-verify — Component Documentation

## What This Binary Does

`drs-verify` is the DRS verification HTTP server. It exposes:

- `POST /verify` — accepts a raw `ChainBundle` JSON body (or `DRS-Chain-Bundle` header) and returns a `VerificationResult`
- `GET /healthz` — liveness check; returns `200 OK` always
- `GET /readyz` — readiness check; returns `503` until the Bitstring Status List has been fetched at least once
- MCP route group at `/mcp/*` — applies DRS verification as middleware; passes through on success
- A2A route group at `/a2a/*` — same pattern as MCP, named separately for route group isolation

---

## The Six Verification Blocks

| Block | File | Description |
|---|---|---|
| A | `pkg/verify/chain.go` | Completeness — at least one receipt, non-empty invocation |
| B | `pkg/verify/chain.go` | Structural integrity — types, versions, chain hash linkage, issuer chain, dr_chain |
| C | `pkg/verify/chain.go` | Cryptographic validity — Ed25519 signatures via Go stdlib `crypto/ed25519` |
| D | `pkg/verify/chain.go` | Semantic/policy validity — command sub-path, subject consistency, policy attenuation, policy evaluation |
| E | `pkg/verify/chain.go` | Temporal validity — nbf/exp checks against current time |
| F | `pkg/verify/chain.go` | Revocation — Bitstring Status List lookup via `pkg/revocation/status.go` |

Block F is implemented here (unlike the Rust core) because it requires I/O. The Rust core
performs no I/O — all network calls are in Go.

---

## DID Resolver Cache

**File:** `pkg/resolver/did.go`

- LRU cache, hard-capped at `DID_CACHE_SIZE` entries (default: 10,000)
- At ~64 bytes per entry, 10,000 entries ≈ 640 KB — stays resident in L2/L3 cache
- TTL: `DID_CACHE_TTL_SECS` (default: 3600 seconds / 1 hour)
- Expired entries are evicted lazily on next access
- Uses `golang-lru/v2` (not `sync.Map`) for O(1) eviction under LRU pressure
- Why bounded: the v2 implementation used an unbounded `sync.Map` that grew forever under agent churn

---

## Status List Cache

**File:** `pkg/revocation/status.go`

- `sync.Once` gates the first fetch — prevents the double-fetch race condition present in v2
- `sync.RWMutex` guards reads/writes: many concurrent readers, one writer
- TTL: `STATUS_CACHE_TTL_SECS` (default: 300 seconds / 5 minutes)
- On TTL expiry: refresh attempted in the request path; stale data served if refresh fails
- If `STATUS_LIST_BASE_URL` is empty, revocation checking is disabled

---

## Ed25519 Signature Verification

Uses Go stdlib `crypto/ed25519` (package `crypto/ed25519`):
- Ships with Go — no external crypto dependency
- No CGO required — the binary is fully static
- `ed25519.Verify` is the correct function; it implements the cofactored equation

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `DID_CACHE_SIZE` | `10000` | Maximum DID cache entries |
| `DID_CACHE_TTL_SECS` | `3600` | DID cache entry TTL in seconds |
| `STATUS_CACHE_TTL_SECS` | `300` | Status list cache TTL in seconds |
| `STATUS_LIST_BASE_URL` | _(empty)_ | Bitstring Status List endpoint URL |
| `LOG_LEVEL` | `info` | Log verbosity: debug, info, warn, error |

---

## Build

```sh
# Static binary (no CGO)
CGO_ENABLED=0 go build -o drs-verify ./cmd/server

# Docker image (distroless/nonroot)
docker build -t drs-verify .

# Run tests
go test ./...
```

---

## Architecture Relationship

```
TypeScript SDK (drs-sdk)
    │  issues delegation receipts
    │  assembles ChainBundle
    ▼
drs-verify (this service)
    │  verifies ChainBundle (Blocks A–F)
    │  wraps MCP and A2A routes
    ▼
drs-core (Rust)
    │  crypto primitives (Ed25519, SHA-256, JCS)
    │  compiled to WASM for SDK use
    └─ not called at runtime by drs-verify
       (Go uses stdlib crypto/ed25519 directly)
```

The Rust core and Go verifier implement the same algorithm independently.
The Rust WASM module is used by the TypeScript SDK for client-side verification.
