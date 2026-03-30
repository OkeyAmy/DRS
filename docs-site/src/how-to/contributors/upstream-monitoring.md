# Upstream Monitoring

DRS depends on external specifications and libraries that evolve. Upstream changes can break assumptions baked into our architecture without any change to the DRS codebase.

## What to watch

| Source | What to watch | Why it matters |
|---|---|---|
| `ed25519-dalek` (Rust) | RUSTSEC advisories, 2.x API changes | Core signing/verification library — RUSTSEC-2022-0093 is the reference for why we use 2.x |
| `serde-json-canonicalizer` | RFC 8785 compliance updates, new test vectors | JCS divergence breaks cross-implementation JWT verification |
| `golang-lru/v2` | API changes, eviction policy updates | DID resolver cache — eviction semantics affect security properties |
| W3C DID Core / `did:key` | Multicodec prefix changes, new key type support | The `[0xed, 0x01]` prefix check is hard-coded — any change breaks all DID resolution |
| `golang-jwt/jwt` v5 | API changes, new algorithm support | JWT parsing in the Go verification server |
| MCP (Model Context Protocol) | Middleware adapter interface changes, new transport types | `X-DRS-Bundle` header integration — transport changes affect bundle delivery |
| A2A (Agent-to-Agent Protocol) | Interceptor interface changes | A2A middleware integration |
| IETF OAuth WG | RFC 8693 updates, new chain-splicing guidance | DRS is positioned as RFC 8693 mitigation #3 — spec changes affect our positioning |
| W3C Bitstring Status List | Spec changes to revocation format | Block F implementation |

## When you notice a change

1. **Stop.** Do not silently update the dependency or adapt the code.
2. Open a GitHub issue with this format:

```
UPSTREAM CHANGE DETECTED

Source: <spec/crate/library name>
Version: <old version> → <new version>
What changed: <one sentence>
DRS impact: <which layer(s) and files are affected>
Recommended action: <what we need to decide>
Reference: <URL to release notes, advisory, or spec section>
```

3. Wait for the maintainer to confirm before incorporating the change.
4. Once confirmed, discuss architecture impact before writing any code.

## The upstream drift lesson

v2 failed partly because it was built against UCAN 0.x while the actual specification was UCAN v1.0-rc.1. The difference between versions was not cosmetic — it was a complete change in encoding format (JSON → CBOR) and policy language (`att.nb` → `cmd`/`pol`).

Upstream drift caught during development is a discussion. Upstream drift caught in production is a vulnerability or a broken implementation.

## Subscribing to security advisories

```bash
# Watch for Rust security advisories
cargo install cargo-audit
cargo audit   # run periodically in CI

# Go vulnerability database
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Both `cargo audit` and `govulncheck` should run in CI on every PR that touches dependencies.
