# Architecture Deep Dive

Read this before touching the crypto layer or the verification path.

## Required reading

Before making changes to the core verification logic:

1. `docs/Drs_language&algorithms.md` — authoritative reference for language choices and corrected algorithms
2. `docs/Drs_architecture_v2.md` — the full DRS 4.0.0 specification
3. [False Positives: What We Tried](./false-positives.md) — the v1 and v2 failures

## Module boundaries

Each module has exactly one responsibility. Do not write code that crosses these boundaries:

| Module | Responsibility | Does NOT do |
|---|---|---|
| `drs-core/src/crypto/` | Ed25519 sign/verify, SHA-256 | JWT parsing, policy evaluation |
| `drs-core/src/chain/` | Chain hash computation, `verify_chain` | Network I/O, caching |
| `drs-core/src/jcs/` | RFC 8785 canonicalisation | Serialisation to non-JSON formats |
| `drs-core/src/capability/` | Policy evaluation, attenuation check | Crypto operations |
| `drs-core/src/did/` | `did:key` decode to public key bytes | DID resolution with caching |
| `drs-verify/pkg/resolver/` | DID resolution + LRU cache | Chain verification |
| `drs-verify/pkg/verify/` | `verify_chain` (6 blocks) | DID resolution, HTTP I/O |
| `drs-verify/pkg/middleware/` | HTTP request/response handling | Verification logic |
| `drs-verify/pkg/policy/` | Policy field evaluation | Signing, serialisation |
| `drs-sdk/src/sdk/` | Issuance (sign + build JWTs) | Verification |
| `drs-sdk/src/verify/` | HTTP client to drs-verify | Verification logic itself |
| `drs-sdk/src/cli/` | CLI command dispatch | SDK logic |

## Data flow

```
Issuance (TypeScript SDK):
  Policy params → jcsSerialise(payload) → sign → JWT string

Verification (Go):
  JWT string → parse header/payload → resolve_did → crypto/ed25519.Verify
            → check_policy_attenuation → revocation checks → VerificationResult

DID resolution (Go):
  DID string → base58Decode → strip multicodec prefix [0xed, 0x01]
             → [32]byte public key (constant-time prefix check)
```

## Adding a new algorithm

1. Write it in Rust first (`drs-core/src/`)
2. Add or extend shared conformance vectors when the protocol surface changes
3. Port it to Go if the verifier needs the same rule on the hot path
4. Keep TypeScript logic aligned with the conformance contract

## Security-sensitive code checklist

Before merging any change to the crypto or verification path:

- [ ] Comparisons on key material use constant-time equality (`subtle::ConstantTimeEq` / `crypto/subtle.ConstantTimeCompare`)
- [ ] No `unwrap()` in Rust library code — use `Result<T, E>` and propagate
- [ ] No `_` on error returns in Go production paths — check and propagate
- [ ] Signing keys are not logged, even in debug
- [ ] New error messages do not expose key material or sensitive internal state
