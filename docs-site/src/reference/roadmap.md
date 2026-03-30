# Roadmap

DRS is a research project. The implementation roadmap has four phases.

## Phase 1 — Core protocol *(current)*

**Status:** In progress

- ✓ DRS 4.0 specification (`docs/Drs_architecture_v2.md`)
- ✓ `drs-core`: Rust crypto primitives, JCS canonicalisation, chain verification, WASM build target
- ✓ `drs-verify`: Go verification server, MCP/A2A middleware, DID resolver with LRU cache, Bitstring Status List cache
- ✓ `drs-sdk`: TypeScript SDK (issuance path), CLI tools (`verify`, `audit`, `policy`, `translate`, `keygen`)
- ✓ Documentation site (this site)
- ✓ Local revocation store with `POST /admin/revoke` (in-memory, immediate effect)
- ✓ RFC 3161 trusted timestamp anchor (`pkg/anchor/`) — Tier 3 store with TSA client
- ◻ `did:web` resolver production hardening (DNS pinning, certificate transparency)
- ◻ Cross-implementation test suite (Rust ↔ Go ↔ TypeScript JWT interop)

## Phase 2 — Production hardening *(6 months)*

**Goal:** Production-ready for early adopters and AIUC-1 certification candidates.

- HSM key management integration (AWS KMS, GCP Cloud KMS) in drs-verify
- Tier 3 storage (WORM S3, Azure Blob Immutable Storage)
- AIUC-1 compliance export format and certification documentation
- Performance benchmarks: p50/p99 latency at 10K req/sec with 5-hop chains
- Security audit (external)

## Phase 3 — Ecosystem integration *(12 months)*

**Goal:** Plug-and-play integration with the MCP and A2A ecosystems.

- MCP server reference implementation with DRS built in (Go)
- A2A protocol reference implementation with DRS middleware
- Browser SDK: WASM-based verification for browser-hosted agents
- On-chain registry: Ethereum mainnet blockchain anchor (Tier 4 — explicit opt-in for blockchain-native enterprise deployments; Ethereum is the only chain with established regulatory and legal precedent)
- Policy language extensions: resource-level constraints, time-windows, rate limiting

## Phase 4 — Standards track *(18–24 months)*

**Goal:** DRS becomes an IETF standard or an officially recognised OAuth profile.

- IETF Internet-Draft submission (OAuth Working Group)
- W3C Community Group proposal for the consent record format
- FINOS AI Governance Framework alignment documentation
- Integration with OpenID for Verifiable Credentials (OID4VC) for human identity binding

## Non-goals

These are explicitly out of scope:

- Behavioral safety (preventing LLMs from doing bad things) — model/runtime problem
- LLM non-determinism — outside the authorisation layer
- Prompt injection prevention — DRS records injections, does not prevent them
- Post-compromise key recovery — operational problem
- Agent identity (DIDs are used but not managed by DRS)
