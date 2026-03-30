# Architecture

DRS uses a three-language stack. Each language handles the layer it is genuinely best suited for. This is not aesthetic preference — it is a consequence of the performance and correctness requirements of each layer.

## The three layers

```
┌──────────────────────────────────────────────┐
│  TypeScript SDK  (@drs/sdk)                   │
│  Issuance path only. Low-frequency.           │
│  issueRootDelegation, issueSubDelegation,     │
│  buildBundle, CLI tools                       │
│  Delegates crypto to WASM or HTTP             │
└───────────────────┬──────────────────────────┘
                    │  WASM (drs-core compiled for browser)
                    │  HTTP (VerifyClient → drs-verify)
┌───────────────────▼──────────────────────────┐
│  Go Middleware  (drs-verify)                  │
│  Verification path. High-frequency.           │
│  verify_chain (6 blocks), MCP/A2A middleware  │
│  LRU DID resolver, status list cache          │
│  Single static binary, goroutine-based        │
└───────────────────┬──────────────────────────┘
                    │  Rust crate (native library)
                    │  WASM (browser target)
┌───────────────────▼──────────────────────────┐
│  Rust Core  (drs-core)                        │
│  Ed25519 sign/verify, SHA-256, JCS (RFC 8785) │
│  Capability index (O(1) policy check)         │
│  DID key resolution, chain hash computation   │
│  Zero GC. Stack-allocated. Deterministic.     │
└──────────────────────────────────────────────┘
```

## Why Rust for the core

Ed25519 signature verification requires deterministic, constant-time operations. V8 (JavaScript/TypeScript) cannot guarantee either:
- GC pauses of 50–1500ms are common under load
- V8 does not guarantee constant-time execution of arithmetic

Rust's `ed25519-dalek 2.x` provides:
- RUSTSEC-2022-0093 patched (batch verification side-channel fixed)
- `verify_strict()` enforcing `S < L` — rejects signature malleability
- `subtle::ConstantTimeEq` for security-sensitive comparisons
- Compiles to native library (used by Go via CGO) and WASM (used in browsers)

The v2 architecture used TypeScript for verification and hit all of these problems in implementation.

## Why Go for verification

The verification server handles thousands of concurrent requests. Go's goroutine model gives concurrent request handling without the complexity of async Rust, while the GC is predictable enough for the latency requirements:

- `sync.Once` prevents double-fetch race conditions in the Bitstring Status List cache
- `hashicorp/golang-lru/v2` — LRU with hard cap of 10,000 entries (~640KB)
- `crypto/subtle.ConstantTimeCompare` for DID multicodec prefix checks
- `CGO_ENABLED=0 go build` — single static binary, no runtime dependencies
- `/healthz` and `/readyz` endpoints for Kubernetes readiness probes

## Why TypeScript for the SDK

Delegation issuance is low-frequency (human sets up a session, agent runtime boots). The developer experience matters more than raw performance. TypeScript gives:
- Native npm ecosystem integration — one `pnpm add @drs/sdk`
- IDE autocompletion and type safety
- Browser compatibility for consent UIs
- Matches the existing tech stack of most MCP server developers

TypeScript never handles verification — that path runs in Go or Rust.

## JCS canonicalisation

All JWTs in DRS are canonicalised with RFC 8785 (JSON Canonicalization Scheme) before signing. This ensures two logically equivalent objects always produce identical JWT bytes, regardless of which implementation created them.

The rules:
- Object keys sorted recursively by Unicode code point
- No whitespace
- IEEE 754 shortest number representation

```typescript
// WRONG — does not sort nested object keys:
const payload = JSON.stringify(obj);

// CORRECT — RFC 8785 JCS:
const payload = jcsSerialise(obj);  // from drs-sdk/src/sdk/issue.ts
```

The Rust implementation uses `serde-json-canonicalizer`. The TypeScript implementation has an inline `jcsSerialise()` function. Both must produce identical output for the same logical object — this is tested in the cross-implementation test suite.

## WASM build

```bash
cd drs-core
wasm-pack build --target web --features wasm
# Output: drs-core/pkg/ — publish as @drs/wasm
```

The `@drs/wasm` package is an optional peer dependency of `@drs/sdk`. The WASM loader (`src/wasm/loader.ts`) is:
- **Idempotent:** `initWasm()` can be called multiple times safely
- **Lazy:** the WASM binary is not fetched until `initWasm()` is awaited
- **Graceful:** if `@drs/wasm` is not installed, a clear error is thrown
