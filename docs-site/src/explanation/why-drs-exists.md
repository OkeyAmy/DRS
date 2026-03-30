# Why DRS Exists

DRS exists because the AI agent ecosystem is deploying faster than the accountability infrastructure to support it.

## The market reality

- 75% of C-suite executives rank auditability as their top AI governance requirement
- 82% of executives are confident in their AI oversight, but only 14.4% send agents to production with full approval chains
- Only 5.2% of enterprises have AI agents in production today — the accountability gap is the primary blocker

The question every CISO asks before approving an agent deployment: *"If this agent does something it shouldn't, can we prove exactly who authorised it, and what they authorised?"*

OAuth 2.1 + server logs cannot answer that question. DRS can.

## The RFC 8693 gap

RFC 8693 (Token Exchange) defines how Agent A exchanges its bearer token for a new token representing Agent B acting on behalf of the user. This is the correct building block for agentic delegation.

The gap: RFC 8693 tokens are bearer tokens. Any agent that obtains a valid token can present it as if it were the legitimate holder. There is no per-step binding between the token and the specific delegation act that produced it.

**Chain splicing:** An attacker with access to one token can splice it into a different chain, presenting apparently legitimate credentials while exceeding the scope they were actually granted. CVE-2025-55241 (Azure AD, March 2025) is a real-world exploitation.

DRS closes this gap: the `prev_dr_hash` field in each receipt links it cryptographically to the previous one. Any substitution breaks the chain and fails Block B of verification.

## Version history: what was tried

DRS reached v4 through three prior architectures that were each scrapped. Understanding what failed is essential for contributors — see [False Positives: What We Tried](../how-to/contributors/false-positives.md) for the full history.

### v1 — Invented from scratch
Three fundamental errors:
1. UCAN already defines delegation chains — v1 reinvented the wheel badly
2. Applied a binary Merkle tree to a linear chain (CVE-2012-2459 risk)
3. Under-specified security model

**v1 was scrapped.** The document is preserved in `docs/DRS_architecture_v1.md`.

### v2 — UCAN profile (against wrong version)
Correctly identified DRS should be a UCAN Profile — but built against UCAN 0.x (JWT) while the actual spec was UCAN v1.0-rc.1 (CBOR/IPLD). Additional problems: TypeScript-only verification with V8 GC pauses destroying the <5ms latency requirement, unbounded DID resolver cache, status list race condition, O(n·m) policy check.

**v2 was scrapped.** The document is preserved in `docs/Drs_architecture_v2.md`.

### v3/v4 — OAuth 2.1 profile (current)

The final pivot was from UCAN to OAuth 2.1. The reason: the ecosystem standardised on OAuth. AT Protocol and MCP both chose JWT + OAuth. UCAN's production adoption is near-zero. Building on UCAN would have meant building on a standard nobody uses.

The current architecture separates concerns by language: Rust for crypto (zero GC), Go for verification middleware (goroutines), TypeScript for the developer SDK (npm ecosystem).
