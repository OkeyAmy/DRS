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
                    │  HTTP to drs-verify
┌───────────────────▼──────────────────────────┐
│  Go verifier  (drs-verify)  — NORMATIVE       │
│  verification server, middleware, revocation  │
│  resolver cache, health/readiness, storage    │
└───────────────────┬──────────────────────────┘
                    │  shared protocol contract
                    │  conformance vectors
┌───────────────────▼──────────────────────────┐
│  Rust core  (drs-core)  — non-normative       │
│  crypto primitives, JCS, chain hash, policy   │
│  frozen reference implementation              │
└──────────────────────────────────────────────┘
```

## Why Rust for the core

Rust is the lowest-level implementation and the internal reference when a
conformance vector is ambiguous. It is **feature-frozen**: `drs-verify` is
the sole normative verifier, and `drs-core` records the algorithms as
reviewable Rust (bug fixes only). It provides:

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
- Bitstring Status List caching with mutex + re-check guard (failed fetches are retryable)
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
`drs-verify` instance over HTTP. This is the only verification path the SDK
exposes — as of SDK 0.2.0 there is no WASM loader in the package entry point.

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

`drs-core` still compiles to `wasm32-unknown-unknown` (a JS host is required
for the clock), and its WASM test suite runs in CI:

```bash
cd drs-core
wasm-pack build --target web --features wasm
# Output: drs-core/pkg/
```

No standalone WASM artifact is published, and the SDK no longer exports a
loader for one. Browser-side verification is a parked integration path — if
it is revived, it will ship as its own package. Production verification is
`drs-verify` over HTTP, full stop.
