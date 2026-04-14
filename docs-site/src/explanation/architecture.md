# Architecture

DRS uses a three-language stack. The three layers are peer implementations with
different primary roles; the Go verifier does not call Rust at runtime.

## The three layers

```
┌──────────────────────────────────────────────┐
│  TypeScript SDK  (@okeyamy/drs-sdk)           │
│  issuance, bundle assembly, CLI               │
│  optional HTTP verification client            │
└───────────────────┬──────────────────────────┘
                    │  optional WASM for browser/runtime use
                    │  HTTP to drs-verify
┌───────────────────▼──────────────────────────┐
│  Go verifier  (drs-verify)                    │
│  verification server, middleware, revocation  │
│  resolver cache, health/readiness, storage    │
└───────────────────┬──────────────────────────┘
                    │  shared protocol contract
                    │  conformance vectors
┌───────────────────▼──────────────────────────┐
│  Rust core  (drs-core)                        │
│  crypto primitives, JCS, chain hash, policy   │
│  reference implementation for ambiguous cases │
└──────────────────────────────────────────────┘
```

## Why Rust for the core

Rust is the lowest-level implementation and the internal reference when a
conformance vector is ambiguous. It provides:

- `ed25519-dalek 2.x` for strict cryptographic operations
- `serde-json-canonicalizer` for RFC 8785 JCS
- deterministic, low-level primitives suitable for WASM export

Rust is important for protocol correctness, but it is not linked into
`drs-verify` through CGO.

## Why Go for verification

The Go service is the production verification path today. It handles:

- `verify.Chain()` (Blocks A-F)
- `MCPMiddleware` / `A2AMiddleware`
- DID resolution with LRU caching
- Bitstring Status List caching with `sync.Once`
- health and readiness endpoints
- storage and local revocation

Key implementation details:

- `crypto/ed25519` for signature verification
- `crypto/subtle.ConstantTimeCompare` for DID multicodec prefix checks
- `CGO_ENABLED=0 go build` for a single static binary

## Why TypeScript for the SDK

Issuance is developer-facing and low-frequency. TypeScript provides:

- ergonomic npm distribution: `pnpm add @okeyamy/drs-sdk`
- strong typing for policies, receipts, and bundles
- browser-friendly UI integration for consent flows
- the CLI used for local development and testing

The SDK also includes `VerifyClient`, which sends bundles to a running
`drs-verify` instance over HTTP. Local WASM verification exists as a separate,
explicit capability; it is not an automatic fallback inside `VerifyClient`.

## JCS canonicalisation

All signed JSON in DRS is canonicalised with RFC 8785 before signing. The rules
are:

- object keys sorted recursively
- no insignificant whitespace
- canonical JSON number formatting

```typescript
// WRONG
const payload = JSON.stringify(obj);

// CORRECT
const payload = jcsSerialise(obj);
```

In the TypeScript SDK, `jcsSerialise` lives in `drs-sdk/src/sdk/jcs.ts`. The
Rust and TypeScript outputs are checked against shared conformance vectors.

## WASM build

```bash
cd drs-core
wasm-pack build --target web --features wasm
# Output: drs-core/pkg/
```

The browser/WASM path is explicit: callers initialize it themselves via the
loader in `drs-sdk/src/wasm/loader.ts`.
