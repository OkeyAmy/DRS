# drs-core

[![crates.io](https://img.shields.io/crates/v/drs-core.svg)](https://crates.io/crates/drs-core)
[![docs.rs](https://img.shields.io/docsrs/drs-core)](https://docs.rs/drs-core)
[![license](https://img.shields.io/crates/l/drs-core.svg)](https://github.com/OkeyAmy/DRS/blob/main/LICENSE)

Cryptographic core for the **Delegation Receipt Standard (DRS)** — a JWT-based delegation
receipt system for agentic accountability.

> **Status: non-normative reference implementation.** The normative DRS
> verifier is [`drs-verify`](../drs-verify) (Go); all production verification
> goes through its HTTP `/verify` endpoint. This crate records the DRS
> algorithms (RFC 8785 JCS, SHA-256 chain hashing, Ed25519 verification,
> Blocks A–E) as reviewable Rust and is **feature-frozen** — it receives
> bug fixes only.
>
> Known, intentional gaps vs the normative verifier: no `tool_server`
> binding, no invocation `iat` freshness check, no replay protection, no
> revocation (Block F), `did:key` only. Do not use this crate's
> `verify_chain` as your production verifier.

- **Ed25519** signatures (`ed25519-dalek` 2.x, strict verification)
- **SHA-256** chain linkage (`prev_dr_hash` / `dr_chain`)
- **RFC 8785 (JCS)** canonical JSON (`serde_json_canonicalizer`)
- **`did:key`** identity (multicodec `ed25519-pub`)
- Capability attenuation checks and a bounded delegation chain (`MAX_CHAIN_DEPTH = 16`)

> Zero GC, stack-allocated byte arrays, no panics in library code — built for the
> sub-5ms verification path where a V8 GC pause is unacceptable.

## Install

```toml
[dependencies]
drs-core = "0.1"
```

Or:

```bash
cargo add drs-core
```

## Quick start

```rust
use drs_core::{verify_chain, ChainBundle};
use drs_core::crypto::{generate_keypair, sign};
use drs_core::did::encode_did_key;

// Generate an Ed25519 identity and its did:key.
let (signing_key, verifying_key) = generate_keypair()?;
let did = encode_did_key(verifying_key.as_bytes());

// Sign a message (raw 64-byte Ed25519 signature).
let sig = sign(&signing_key, b"message");

// Verify a full delegation chain bundle. verify_chain runs the depth cap
// before any crypto, then checks signatures, attenuation, temporal validity,
// and the SHA-256 hash chain — fail-closed.
let bundle: ChainBundle = serde_json::from_str(bundle_json)?;
let result = verify_chain(&bundle);
if !result.valid {
    eprintln!("denied: {:?}", result.error);
}
# Ok::<(), drs_core::DrsError>(())
```

## API surface

| Item | Purpose |
|---|---|
| `verify_chain(&ChainBundle) -> VerificationResult` | full chain verification (the hot path) |
| `build_jwt(...)` | encode a DRS receipt as a signed JWT |
| `crypto::generate_keypair()` / `sign()` / `verify_strict()` | Ed25519 primitives |
| `did::encode_did_key()` / `resolve_did_key()` | `did:key` ⇄ raw public key |
| `chain::compute_chain_hash(jwt)` | SHA-256 receipt hash for chain linkage |
| `jcs` | RFC 8785 canonical JSON serialization |
| `capability` | capability index + attenuation (`child ⊆ parent`) |
| `types` | `ChainBundle`, `DelegationReceipt`, `InvocationReceipt`, `Policy`, … |
| `DrsError` | the crate's error type — never `unwrap()` in callers |

## Features

| Feature | Default | Effect |
|---|---|---|
| (none) | ✓ | native `rlib` + `cdylib` |
| `wasm` | | `wasm-bindgen` bindings for the browser/Node issuance path |

### Building for WebAssembly

```bash
wasm-pack build --target web --features wasm
```

The same source produces the native `.so`/`.rlib` and the WASM artifact consumed by
`@okeyamy/drs-sdk`.

## How it fits together

| Layer | Component | Role |
|---|---|---|
| Crypto core | **drs-core** (this crate) | JCS, SHA-256 chain hash, Ed25519, capability index |
| Issuance | [`@okeyamy/drs-sdk`](https://www.npmjs.com/package/@okeyamy/drs-sdk) (TS/WASM) | mint receipts, assemble bundles |
| Verification | [`drs-verify`](https://github.com/OkeyAmy/DRS/tree/main/drs-verify) (Go) | the `/verify` service + MCP/A2A middleware |

## Security notes

- Ed25519 verification is **strict** (`verify_strict`) — no malleable or small-order
  signatures are accepted.
- Canonicalization is RFC 8785 JCS over the exact bytes; never reimplement it with
  `serde_json::to_string` + key sorting.
- The delegation chain is capped at `MAX_CHAIN_DEPTH = 16`, checked **before** any
  cryptographic work, so a malicious deep chain cannot exhaust CPU.
- Every fallible path returns `Result<_, DrsError>`; the library does not panic.

## License

Apache-2.0 © Okey Amy
