# Glossary

**Attenuation** — The constraint that a sub-delegation's policy must be a strict subset of its parent's policy. A sub-agent can only be granted less authority than the agent that delegated to it. See [Principle of Least Authority (POLA)](#pola).

**Bundle** — The unit of transport in DRS. A JSON object containing the invocation receipt and all delegation receipts in the chain, transmitted as `X-DRS-Bundle: base64url({bundle_json})`.

**Chain splicing** — An attack where an adversary substitutes an unrelated token into a delegation chain to exceed the scope they were actually granted. CVE-2025-55241 (Azure AD, 2025) is a documented instance. DRS mitigates this with `prev_dr_hash`.

**Delegation Receipt (DR)** — A signed JWT issued by each delegator recording one hop in the delegation chain. Contains issuer DID, audience DID, command, policy constraints, temporal bounds, and a hash linking to the previous DR.

**DID (Decentralised Identifier)** — A URI that identifies an actor without a central registry. Format: `did:method:identifier`. DRS uses `did:key` and `did:web`.

**did:key** — A DID where the identifier encodes the public key directly: `did:key:z{base58btc(multicodec_prefix + pubkey_bytes)}`. No registry, no DNS. Preferred for DRS because it is self-contained and requires no network resolution.

**did:web** — A DID whose identifier is a domain name. Resolved by fetching a DID document from `https://domain/.well-known/did.json`. Requires DNS and TLS security.

**DR Store** — The storage backend for delegation receipts. One of five tiers from in-memory (tier 0) to on-chain (tier 4).

**EdDSA / Ed25519** — The signature algorithm used in all DRS JWTs. Deterministic (no random nonce), constant-time, and immune to fault attacks. DRS uses `ed25519-dalek 2.x` (Rust) and `golang.org/x/crypto` (Go).

**Invocation Receipt** — A signed JWT recording an actual tool call. Contains the command, arguments, the ordered array of DR hashes (`dr_chain`), and the tool server's DID.

**JCS (JSON Canonicalization Scheme)** — RFC 8785. Defines a canonical serialisation of JSON where object keys are sorted recursively by Unicode code point with no whitespace. Used by DRS to ensure identical JWT bytes for logically equivalent objects across all implementations.

**JTI (JWT ID)** — Unique identifier for a JWT. DRS format: `dr:uuid-v4` for delegation receipts, `inv:uuid-v4` for invocation receipts.

**MCP (Model Context Protocol)** — Anthropic's protocol for connecting language models to external tools. DRS bundles are transmitted as `X-DRS-Bundle` headers on MCP requests.

**Multicodec** — A self-describing binary encoding prefix used in `did:key`. For Ed25519, the prefix is `[0xed, 0x01]`. DRS uses constant-time comparison to check this prefix.

**POLA (Principle of Least Authority)** — Each delegation grants only the authority needed for the specific task. Sub-delegations must be strictly less permissive than their parent. POLA is enforced both at issuance (SDK) and at verification (Block D).

**prev_dr_hash** — The field in each sub-DR that links it to its parent: `"sha256:{lowercase hex of SHA-256 of parent DR JWT bytes}"`. Null at the chain root. Creates a tamper-evident chain — any modification to any DR changes its hash and breaks subsequent links.

**RFC 8693** — IETF Token Exchange. Defines how one OAuth bearer token can be exchanged for another representing a different principal acting on behalf of the original user. DRS adds per-step receipts to close the chain splicing gap that RFC 8693 leaves open.

**sub (Subject)** — The JWT claim identifying the original resource owner — always the human at the root of the chain. The `sub` field must remain identical through every delegation hop. It is never the agent.

**Verify_chain** — The Go function that runs all six verification blocks (A–F) on a DRS bundle. Fail-closed: any error immediately rejects the request without continuing.
