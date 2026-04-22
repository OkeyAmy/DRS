# False Positives: What We Tried

This is a research project. Three architectural approaches were designed and discarded before the current architecture. This page is preserved as a record of what failed and why — essential context for anyone contributing to the codebase.

> "Those who cannot remember the past are condemned to repeat it." — George Santayana

## v1: Invented from scratch

**The hypothesis:** We need a new delegation chain system for AI agents.

**What we built:** A custom delegation chain with Ed25519 signatures and a binary Merkle tree over the chain.

**The errors:**

**Error 1 — Reinvented the wheel:** UCAN (User Controlled Authorization Network) already defines cryptographic delegation chains. We built something equivalent but worse, without the benefit of the prior art and the community that had already reviewed it.

**Error 2 — Wrong data structure:** We applied a binary Merkle tree to a linear delegation chain. A linear chain is not a tree. The Merkle tree added complexity without benefit, and it introduced the same last-node duplication vulnerability as Bitcoin's transaction Merkle tree (CVE-2012-2459).

**Error 3 — "Ed25519 is simply secure":** This is not a security model. A security model names the threats, the mechanisms that counter them, and the residual risks. "Simply secure" means nothing to an auditor.

**The lesson:** Check whether the problem is already solved before designing a solution. Read the existing standards. Read the CVE history of similar approaches.

**v1 documents:** `docs/DRS_architecture_v1.md`

---

## v2: UCAN Profile (wrong version)

**The hypothesis:** DRS should be a UCAN Profile — extend UCAN rather than invent something new. This was the correct insight.

**What we built:** A UCAN 0.x Profile with JWT-based delegation tokens.

**The errors:**

**Error 1 — Wrong spec version:** We built against UCAN 0.x (JWT-based, `att.nb` policy field) while the actual current specification was UCAN v1.0-rc.1 (CBOR/IPLD-based, `cmd`/`pol` policy). We discovered this when we tried to validate against real UCAN implementations.

**Error 2 — TypeScript for verification:** Verification is a high-frequency, latency-sensitive operation. V8 (Node.js) has GC pauses of 50–1500ms. The <5ms p99 latency requirement was mathematically impossible with TypeScript on the verification path. We measured 120ms median verification time under moderate load.

**Error 3 — Unbounded DID resolver cache:** The cache grew without bound under agent churn. With 10,000 active agents, the cache consumed >640MB. There was no eviction policy.

**Error 4 — Status list race condition:** Two concurrent requests arriving when the status list cache expired could both issue HTTP GET requests to the status list server. This is a double-fetch race condition. Under load, this caused 2–10× the expected traffic on the status list endpoint.

**Error 5 — O(n·m) policy check:** `is_attenuated_subset()` iterated over all n fields in the parent policy and all m fields in the child policy. At moderate load (1,000 req/sec with 5-level chains), this produced 25 million comparisons per second.

**Error 6 — Wrong canonicalisation:** We used JCS on JSON for JWT signing, but UCAN v1.0 uses CBOR encoding, not JSON. The JWT payloads were valid JSON but the wrong format for the specification we were implementing against.

**The lesson:** Read the specification you are implementing against before writing any code. Check the encoding format. Check the version number. Validate against a reference implementation early.

**v2 documents:** `docs/Drs_architecture_v2.md`

---

## v3/v4: JWT-based DRS for OAuth/MCP ecosystems (current)

**The pivot:** From UCAN to JWT-based DRS aligned with the OAuth/MCP ecosystem.

**Why the pivot:** The ecosystem standardised on JWT-based infrastructure around OAuth and MCP. UCAN's production adoption is near-zero (Storacha is the only known production deployment). Building on UCAN would have meant building for a standard that the target ecosystem does not use.

**What changed:**
- UCAN envelopes/CBOR assumptions → DRS JWT receipts with RFC 8785 JCS canonicalisation
- TypeScript verification → Go verification server (goroutines, predictable GC)
- Unbounded cache → `golang-lru/v2` with hard cap of 10,000 entries
- Race condition → `sync.Once` on status list fetch
- O(n·m) policy check → capability index with O(1) average lookup
- JSON/CBOR confusion → JWT throughout, JCS canonicalisation for signing

**What stayed the same:**
- Ed25519 signatures (correct from the start)
- The concept of per-step delegation receipts (correct from v2)
- The chain hash linking mechanism (correct from v2, minus the Merkle tree)
- The five-actor model (refined from v1)

The current architecture is not a revolution — it is the same core idea implemented correctly, on the right base layer, in the right languages.
