# Roadmap

DRS is still a research project, but several items previously listed as future
work are now implemented.

## Phase 1 — Core protocol

**Status:** Mostly complete

- ✓ `drs-core`: Rust crypto primitives, JCS canonicalisation, chain hash, policy primitives
- ✓ `drs-verify`: Go verification server, MCP/A2A middleware, DID resolver cache, revocation, local revoke endpoint
- ✓ `drs-sdk`: TypeScript issuance SDK and CLI (`verify`, `audit`, `policy`, `translate`, `keygen`)
- ✓ Shared conformance suite across Rust, Go, and TypeScript
- ✓ RFC 3161 timestamping support
- ✓ `did:web` resolver SSRF hardening and circuit breaker

## Phase 2 — Production hardening

- HSM / KMS integration in the verifier
- durable object-store backend (Tier 2 roadmap)
- stronger retention / immutability story for regulated deployments
- external security review
- repeatable performance benchmarks
- workspace-level release and CI orchestration

## Phase 3 — Ecosystem integration

- richer MCP integration guidance and examples
- browser-focused verification flows using the WASM build
- stronger TypeScript packages for pure JSON-RPC MCP transport
- Ethereum anchoring as explicit **Tier 5** opt-in
- richer policy language extensions

## Phase 4 — Standards track

- standards-track documentation and draft work
- external governance / interoperability alignment
- stronger regulatory reference material once implementation catches up

## Non-goals

- behavioral safety or prompt injection prevention
- model determinism
- post-compromise key recovery
- DID lifecycle management outside DRS itself
