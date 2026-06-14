# Use drs-core directly (Rust)

Most builders never touch `drs-core` — you issue receipts with the TypeScript
SDK and verify them with the `drs-verify` service. Use this guide only if you
are:

- building a **Rust** agent, tool server, or CLI and want the primitives
  in-process (no HTTP hop), or
- compiling DRS logic to **WebAssembly** for the browser / React Native, or
- writing **conformance tooling** that must match the canonical encoder
  byte-for-byte.

`drs-core` is the same Rust crate that compiles to the native library and the
WASM artifact. It contains the crypto primitives, JCS canonicalisation, chain
hashing, the capability index, and an **offline** chain verifier. It performs
**no network I/O** — `did:web` resolution and revocation list fetching live in
`drs-verify` (Go), not here.

## Install

```toml
[dependencies]
drs-core = "0.1"
```

```bash
cargo add drs-core
```

## Generate a keypair and a DID

```rust
use drs_core::crypto::ed25519::generate_keypair;
use drs_core::did::key::encode_did_key;

let (signing_key, verifying_key) = generate_keypair()?;

// did:key string for the public half — this is the agent's identity.
let did = encode_did_key(&verifying_key.to_bytes());
println!("{did}"); // did:key:z6Mk...
# Ok::<(), drs_core::DrsError>(())
```

## Sign and verify bytes

`verify_strict` rejects malleable signatures (`S ≥ L`) — the same strict
Ed25519 check the production verifier enforces.

```rust
use drs_core::crypto::ed25519::{generate_keypair, sign, verify_strict};

let (signing_key, verifying_key) = generate_keypair()?;
let message = b"delegation payload bytes";

let signature: [u8; 64] = sign(&signing_key, message);
verify_strict(&verifying_key, message, &signature)?; // Ok(()) on success
# Ok::<(), drs_core::DrsError>(())
```

## Resolve a did:key back to public-key bytes

```rust
use drs_core::did::key::resolve_did_key;

let public_key: [u8; 32] = resolve_did_key("did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2")?;
# Ok::<(), drs_core::DrsError>(())
```

`did:web` is intentionally **not** resolved here — it requires network I/O and
is handled by `drs-verify`.

## Canonicalise JSON (RFC 8785 JCS)

This is the byte-exact encoder. Use it when you need the signing preimage to
match the SDK and verifier exactly.

```rust
use drs_core::jcs::canonicalise::jcs_canonical_bytes;
use serde_json::json;

let bytes = jcs_canonical_bytes(&json!({ "b": 2, "a": 1 }))?;
assert_eq!(bytes, br#"{"a":1,"b":2}"#); // keys sorted by code point, no whitespace
# Ok::<(), drs_core::DrsError>(())
```

## Compute a chain hash

The hash that links one receipt to the next — `sha256:<hex>` over the exact JWT
string bytes.

```rust
use drs_core::chain::hash::compute_chain_hash;

let hash = compute_chain_hash("eyJhbGciOiJFZERTQS...");
assert!(hash.starts_with("sha256:"));
```

## Build a signed receipt JWT

```rust
use drs_core::jwt::encode::build_jwt;
use drs_core::crypto::ed25519::generate_keypair;
use serde_json::json;

let (signing_key, _) = generate_keypair()?;
let payload = json!({
    "iss": "did:key:z6MkOperator",
    "sub": "did:key:z6MkOperator",
    "aud": "did:key:z6MkAgent",
    "drs_v": "4.0",
    "drs_type": "delegation-receipt",
    "cmd": "/mcp/tools/call",
    "jti": "dr:did:key:z6MkOperator-1",
    "nbf": 0,
    "iat": 0
});

let jwt = build_jwt(&payload, &signing_key)?; // header + payload JCS-encoded, then signed
# Ok::<(), drs_core::DrsError>(())
```

## Verify a bundle offline

`verify_chain` runs the structural, cryptographic, policy, and temporal checks
in-process. Because it does no I/O, it does **not** perform `did:web`
resolution or revocation lookups — for those, send the bundle to a running
`drs-verify` instead.

```rust
use drs_core::{verify_chain, ChainBundle};

let bundle: ChainBundle = serde_json::from_str(bundle_json)?;
let result = verify_chain(&bundle);

if result.valid {
    let ctx = result.context.expect("valid result carries context");
    println!("root principal: {}", ctx.root_principal);
    println!("chain depth:    {}", ctx.chain_depth);
} else {
    let err = result.error.expect("invalid result carries error");
    eprintln!("{}: {}", err.code, err.message);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`VerificationResult` mirrors the JSON the Go service returns: `valid`,
`context` (`root_principal`, `chain_depth`, …), and `error`
(`code`, `message`, `suggestion`). The `code` values are the same ones listed
in [Error Codes](../../reference/error-codes.md).

## Check a capability index

The capability index answers "does this grant cover (resource, tool)?" with
exact-match precedence over prefix wildcards.

```rust
use drs_core::capability::index::CapabilityIndex;

let index = CapabilityIndex::build(
    &["mcp://tools/*".to_string()],
    &["web_search".to_string()],
);

assert!(index.covers("mcp://tools/search", "web_search"));
assert!(!index.covers("mcp://other/x", "web_search"));
```

## Build for WebAssembly

The same crate targets WASM via `wasm-pack`:

```bash
cd drs-core
wasm-pack build --target web
```

The `wasm` module exposes the verification and canonicalisation entry points to
JavaScript. The TypeScript SDK ships an optional WASM loader
(`initWasm`, `getWasmModule`) that consumes this artifact when you want the
Rust core's speed in a JS runtime.

## When to reach for `drs-verify` instead

| You need | Use |
|---|---|
| `did:web` resolution | `drs-verify` (network I/O) |
| Revocation / status-list checks | `drs-verify` (network I/O) |
| Replay protection (nonce store) | `drs-verify` |
| A drop-in HTTP verification service | `drs-verify` |
| In-process primitives, offline verify, WASM | `drs-core` (this page) |
