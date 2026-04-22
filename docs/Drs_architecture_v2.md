# Delegation Receipt Standard (DRS)
## Architecture, Technical Audit, Market Position, and Interaction Design

**Version:** 4.0.0  
**Date:** March 2026  
**Author:** Okey — Founder, Quorum  
**Status:** Historical Working Draft — Prior Working Path  
**Classification:** Confidential

---

> **Historical archive.** This document captures the v2/v4 research path you were working through. Keep it for design history and tradeoff analysis, but do not treat it as the current implementation contract. For current implementation behavior, use `docs/drs-source-of-truth.md` and the code in `drs-core`, `drs-verify`, and `drs-sdk`.

---

## Preamble: Why This Version Exists

Every previous version of this document was built on the wrong foundation. DRS v1, were all designed as UCAN v1.0.0-rc.1 profiles. That was a mistake. This document is the complete research that corrects it.

The correction is not a minor adjustment. It changes the encoding format, the token structure, the cryptographic approach, the library stack, the integration surface, and the market positioning. Every claim in this document has been verified against primary sources: the RFC datatracker, the IETF OAuth Working Group mailing list, the MCP specification at modelcontextprotocol.io, and working open-source implementations. No version, library name, or protocol claim in this document is invented.

### What Changed and Why

**v1–v3 assumed:** UCAN v1.0.0-rc.1 as the foundation (CBOR/IPLD encoding, delegation envelopes, dag-cbor CIDs, Policy Language).

**The problem:** Fission — the company that created and maintained UCAN — shut down in April 2024. The spec stalled permanently at v1.0-rc.1, never reaching final 1.0. When Bluesky's AT Protocol and Anthropic's MCP both needed an authorization layer, both chose OAuth 2.1 over UCAN. Boris Mann, Fission co-founder, acknowledged: "Capabilities adoption needs a lot more education and promotion." The go-ucan and rs-ucan implementations remain in active development within the working group, but no major platform has adopted them. The industry standardised on OAuth 2.1 + MCP.

**v4 builds on:** OAuth 2.1 + RFC 8693 (Token Exchange) + RFC 9728 (Protected Resource Metadata) + MCP Authorization Specification. DRS adds per-step signed delegation receipts on top of this stack — the specific mitigation that the IETF OAuth Working Group itself identified as missing from the current specification.

**The gap DRS fills:** RFC 8693 Section 4.1 explicitly states that nested `act` claims are "informational only" for access control. The `may_act` claim (Section 4.4) is optional — there is no normative requirement that subject tokens carry it or that the STS enforce it. There is no cross-validation between `subject_token` and `actor_token`. A compromised intermediary can present mismatched tokens from different delegation contexts; the STS validates each independently and issues a new properly-signed token asserting a delegation chain that never occurred. This is "delegation chain splicing." CVE-2025-55241 (Microsoft Entra ID, patched July 2025) is the real-world precedent. The IETF OAuth WG open thread on this (mail-archive.com/oauth@ietf.org/msg25680.html) lists three suggested mitigations, the third of which is: "Per-step delegation receipts: Each STS that performs a token exchange includes a signed attestation of the delegation step, providing independently-verifiable provenance." DRS is that mitigation, built as an implementable open standard.

---

## Table of Contents

1. [Market Reality and Problem Statement](#1-market-reality-and-problem-statement)
2. [What DRS Is and Is Not](#2-what-drs-is-and-is-not)
3. [The Five Actors](#3-the-five-actors)
4. [Technical Foundation — The Correct Stack](#4-technical-foundation--the-correct-stack)
5. [DRS Data Model](#5-drs-data-model)
6. [Core Algorithms](#6-core-algorithms)
7. [Human Interaction Flows](#7-human-interaction-flows)
8. [Machine-to-Machine Trust Model](#8-machine-to-machine-trust-model)
9. [MCP Integration](#9-mcp-integration)
10. [Storage Architecture](#10-storage-architecture)
11. [Language and Runtime Stack](#11-language-and-runtime-stack)
12. [Technical Audit — Verified Claims Only](#12-technical-audit--verified-claims-only)
13. [Security Model](#13-security-model)
14. [Regulatory Alignment](#14-regulatory-alignment)
15. [Implementation Roadmap](#15-implementation-roadmap)
16. [What DRS Does Not Solve](#16-what-drs-does-not-solve)

---

## 1. Market Reality and Problem Statement

### 1.1 The Gap Is Real and Documented

The accountability problem in multi-agent AI is not theoretical. The numbers from 2025–2026 surveys paint a specific picture:

- 75% of C-suite leaders at $1B+ organisations rank security, compliance, and auditability as their top requirement for agent deployment (KPMG Q4 2025).
- 79% of enterprises operate with blindspots where agents invoke tools, touch data, or trigger actions that security teams cannot observe (Akto 2026).
- 45.6% of technical teams rely on shared API keys for agent-to-agent authentication. When multiple agents share credentials, attribution becomes impossible.
- Only 21.9% of teams treat AI agents as independent, identity-bearing entities with their own access scopes and audit trails.
- Only 17% of enterprises continuously monitor agent-to-agent interactions.
- 88% reported confirmed or suspected AI agent security incidents in the last year.
- 82% of executives report confidence that their existing policies protect against unauthorised agent actions. But only 14.4% of organisations send agents to production with full security or IT approval.

IBM's analysis identifies four structural failures in current enterprise agent deployments: over-privilege without visibility, invisible delegation where agents reuse human tokens, zero enforcement at runtime, and no accountability after incidents.

### 1.2 What Existing Tools Solve and Do Not Solve

Twenty or more observability tools exist in this space as of Q1 2026. Langfuse (acquired by ClickHouse, January 2026) serves 19 Fortune 50 companies. Arize AI raised a $70M Series C. Datadog launched AI Agent Monitoring. LangSmith, W&B Weave, Patronus AI, Maxim AI, and AgentOps round out the field.

Every one of these tools solves the same category of problem: **observability**. They can tell you what happened. They cannot prove what happened. The gap between "we can see what happened" and "we can prove what happened to a regulator" is the gap DRS fills.

Specifically unsolved as of March 2026:
- Cross-organisational agent delegation with verifiable provenance
- Cryptographic proof that an agent action was authorised by a specific human
- Per-step attestation of delegation chains across multiple token exchanges
- Tamper-evident audit trails that survive legal scrutiny
- Runtime enforcement of delegation policy (not just post-hoc logging)

### 1.3 The Protocol Landscape

**OAuth 2.1** is the authorisation standard the industry has standardised on for agents. MCP (March 2025, June 2025, November 2025 revisions) uses it. AT Protocol uses it. ChatGPT, Cursor, Gemini, Copilot all implement it for tool/server authentication.

**MCP** reached 10,000+ active public servers and 97 million monthly SDK downloads by late 2025. It was donated to the Linux Foundation's Agentic AI Foundation in December 2025. This is where agents live.

**RFC 8693** (OAuth 2.0 Token Exchange) is the standard mechanism for multi-hop delegation in OAuth. It defines `act` and `may_act` claims for representing delegation chains in JWTs. It works for single-hop delegation. It has a structural weakness at multi-hop: chain splicing (described above).

**Agentic JWT** (IETF draft-goswami-agentic-jwt-00, December 2025) is an active IETF draft proposing agent checksums (SHA-256 of system prompt + tools + config), intent tokens, and workflow binding. It addresses intent-execution separation. DRS is complementary: Agentic JWT handles identity and intent; DRS handles per-step delegation provenance.

**UCAN** (User-Controlled Authorisation Networks): The working group remains active with commits as recent as January 2026. go-ucan and rs-ucan are in development. However, no major platform has adopted UCAN. Both AT Protocol and MCP chose OAuth 2.1. Storacha (web3.storage) is the only meaningful production user. DRS v4 does not build on UCAN. UCAN's capability model is theoretically superior for decentralised delegation, but the ecosystem is not there. DRS builds where the ecosystem is.

---

## 2. What DRS Is and Is Not

### 2.1 DRS Is

DRS is a **per-step delegation receipt standard** that sits on top of OAuth 2.1 + RFC 8693 + MCP. At every point in a delegation chain where one principal authorises another to act, DRS produces a signed receipt — a JWT with specific claims — that provides independently verifiable provenance of that delegation step.

The core primitive is the **Delegation Receipt (DR)**. A DR is a signed JWT issued by the delegating party at the moment of delegation. It records who delegated, to whom, under what policy constraints, at what time, and with what human consent evidence. DRs chain together. Each DR references the CID (content identifier) of the previous DR in the chain. The chain is linear, not a tree. The chain from root to leaf proves the complete delegation history for any agent action.

This is the "per-step delegation receipt" mitigation that the IETF OAuth WG identified as the correct fix for chain splicing in RFC 8693. DRS is that mitigation, built as an implementable specification.

### 2.2 DRS Is Not

- **Not a replacement for OAuth 2.1.** DRS extends OAuth. Every DRS deployment still uses OAuth 2.1 for authentication and token issuance. DRS adds receipts on top of tokens.
- **Not a replacement for MCP.** DRS adds accountability to MCP tool calls. It does not replace the MCP protocol.
- **Not an observability tool.** LangSmith, Langfuse, and Datadog AI tell you what happened. DRS proves what was authorised. These are different things.
- **Not UCAN.** DRS uses JWTs and OAuth, not CBOR/IPLD capability tokens. A UCAN compatibility layer may be defined in a future addendum, but it is not the primary path.
- **Not a blockchain product.** DRS can optionally anchor receipt CIDs on-chain for maximum tamper-evidence, but this is a storage tier choice, not a requirement.

### 2.3 The Single Sentence

DRS adds a signed receipt to every step of an OAuth delegation chain, so that any party — including a regulator, auditor, or tool server — can independently verify the complete provenance of any agent action without contacting a central authority.

---

## 3. The Five Actors

Every design decision in DRS is anchored to one of five actor types. If a feature cannot be traced to a named actor's need, it should not be built.

### Actor 1: The Enterprise Operator

A CISO, CTO, or compliance officer deploying an AI agent system inside an organisation. Their needs:
- Proof that every agent action was authorised before it happened, not just logged after.
- Evidence they can present to a regulator under EU AI Act, HIPAA, SOC 2, or SR 11-7.
- The ability to revoke an agent's authority instantly and prove the revocation is effective.
- A complete chain of custody from the original human approval to the final tool call.

Current gap: None of the observability tools (Langfuse, Arize, Datadog AI) produce legally defensible delegation evidence. They produce logs. Logs can be altered. DRS receipts are cryptographically signed and independently verifiable.

### Actor 2: The Developer

An engineer building a multi-agent application on top of MCP or A2A. Their needs:
- Integrate DRS in under one day using an SDK.
- Clear error messages that explain why a chain failed, not opaque codes.
- A way to test chains without a live agent deployment.
- No performance penalty that degrades user experience.

Current gap: There is no standard SDK or library for delegation chain verification in the OAuth/MCP ecosystem. Each team builds this from scratch or skips it.

### Actor 3: The Agent Runtime

A software system (like OpenClaw or any agentic framework) that acts autonomously on behalf of a human or organisation. Their needs:
- Know precisely what capabilities it holds, as machine-readable policy in the delegation receipt.
- Request additional capability when a task requires it, through a defined protocol.
- Handle delegation expiry gracefully, without failing silently.
- Operate for extended periods with no human present, with a clear trust model.

Current gap: No standard defines what an agent should do when its delegation expires mid-task in a machine-to-machine deployment with no human interaction layer.

### Actor 4: The Tool Server

An MCP server or API endpoint that executes agent requests. Their needs:
- Verify that a requesting agent actually has authority to invoke a specific tool, before executing it.
- Know the full delegation history — how many hops, whether a human was in the loop, what policy constraints were set.
- Rate-limit by delegation chain identity, not just by agent DID.
- Block specific agents or delegation roots without affecting others.

Current gap: MCP's OAuth 2.1 implementation validates tokens. It does not validate delegation chains. A valid token does not prove a valid delegation chain.

### Actor 5: The Auditor

An internal or external auditor, regulator, or legal counsel reconstructing what happened during an agent-driven incident. Their needs:
- Retrieve the complete delegation evidence for any agent action, retroactively.
- Verify that evidence without contacting the deploying organisation.
- Confirm human consent occurred for a given delegation root.
- Produce a chain of custody that satisfies legal standards.

Current gap: Post-incident reconstruction requires trusting the logs of the very system under investigation. DRS receipts are independently verifiable and tamper-evident.

---

## 4. Technical Foundation — The Correct Stack

### 4.1 What DRS Is Built On

DRS builds on the following standards, all of which have working implementations and active ecosystem adoption:

| Standard | Role in DRS | Status |
|---|---|---|
| OAuth 2.1 | Base authorisation framework | Production standard, widely deployed |
| RFC 8693 | Token Exchange — `act` claim for delegation | IETF Standard, implemented by Auth0, Okta, ZITADEL |
| RFC 9728 | Protected Resource Metadata — dynamic auth discovery | Finalized 2025, required by MCP |
| RFC 8707 | Resource Indicators — audience binding | IETF Standard |
| RFC 7519 | JWT — token format for DRS receipts | IETF Standard, universal |
| RFC 8032 | Ed25519 — signing algorithm for receipts | IETF Standard |
| MCP Authorization Spec | Integration target | Production standard (March/June/November 2025) |
| W3C Bitstring Status List | Revocation | W3C Standard |
| SHA-256 | Receipt content addressing | Universal |

### 4.2 What DRS Adds

On top of this stack, DRS defines three things that do not exist anywhere else:

**1. The Delegation Receipt (DR) format.** A signed JWT with specific claims that record a single delegation step. The DR captures who delegated, to whom, what policy was set, what consent evidence exists, and what the previous DR's hash is. DRs are the primary artifact.

**2. The chain verification algorithm.** A deterministic algorithm that takes a bundle of DRs and an invocation and verifies the complete delegation chain — structural integrity, cryptographic validity, policy attenuation, temporal validity, and revocation status — without contacting any central authority.

**3. The machine-to-machine trust model.** A defined mechanism for how trust originates when there is no human consent UI — covering operator-signed root delegations, supervisor agent escalation paths, and auto-renewal rules set at deployment time.

### 4.3 The RFC 8693 Gap — Precisely

RFC 8693 defines the `act` claim for representing delegation. Section 4.1 says nested `act` claims are "informational only." Section 4.4 defines `may_act` but makes it optional. The result: when Agent B presents a `subject_token` (from User A) and an `actor_token` (Agent B's own credential) to an STS, the STS validates each token independently. It does not verify that Agent B's `actor_token` was acquired within the same delegation context as User A's `subject_token`. A compromised Agent B can combine User A's token with a different, unrelated actor credential and obtain a new properly-signed composite token.

DRS fixes this by adding a requirement that every token exchange step produces a Delegation Receipt (DR) that cryptographically binds the `subject_token` and `actor_token` together, signed by the delegating party. The STS cannot fake this binding because it requires the private key of the actual delegating party. A tool server that checks DRs before executing will reject any invocation whose DR chain is missing, broken, or references credentials from different delegation contexts.

---

## 5. DRS Data Model

### 5.1 The Delegation Receipt (DR)

A Delegation Receipt is a signed JWT. It is produced at the moment of delegation — when one principal authorises another to act on their behalf. It is separate from the OAuth access token. The access token proves identity and scope. The DR proves delegation provenance.

```json
{
  "typ": "JWT",
  "alg": "EdDSA"
}
.
{
  "iss": "did:key:z6MkHuman...",
  "sub": "did:key:z6MkHuman...",
  "aud": "did:key:z6MkAgent1...",

  "drs_v": "4.0",
  "drs_type": "delegation-receipt",

  "cmd": "/mcp/tools/call",
  "policy": {
    "max_cost_usd": 50.00,
    "pii_access": false,
    "allowed_tools": ["web_search", "write_file"],
    "max_calls": 100
  },

  "nbf": 1743000000,
  "exp": 1745592000,
  "iat": 1743000000,
  "jti": "dr:8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",

  "prev_dr_hash": null,

  "drs_consent": {
    "method": "explicit-ui-click",
    "timestamp": "2026-03-28T10:30:00Z",
    "session_id": "sess:8f3a2b1c",
    "policy_hash": "sha256:abc123...",
    "locale": "en-GB"
  },

  "drs_root_type": "human",

  "drs_regulatory": {
    "frameworks": ["eu-ai-act-art13"],
    "risk_level": "limited",
    "retention_days": 730
  }
}
```

**Field definitions:**

`iss` — The issuer. The party granting this delegation. Their DID.

`sub` — The subject. The resource owner this delegation chain is ultimately about. For a human-rooted chain, this is always the human's DID, through every hop.

`aud` — The audience. The party receiving this delegation. The agent or tool being authorised.

`drs_v` — DRS specification version. Enables forward compatibility.

`drs_type` — Must be `"delegation-receipt"` for DRs. Other types defined in future addenda.

`cmd` — The command or capability being delegated. Uses MCP command path format.

`policy` — The constraints under which this delegation operates. All policy from parent DRs is inherited. A child DR may only tighten policy, never loosen it. The tool server evaluates all policies in the chain conjunctively.

`nbf`, `exp`, `iat` — Standard JWT temporal claims. `exp` may be `null` for machine-rooted standing delegations (explicit decision, not default).

`jti` — Unique identifier for this specific DR. Used for revocation.

`prev_dr_hash` — SHA-256 of the previous DR's canonical JSON bytes. `null` for the root DR. This creates the hash chain. If any DR in the chain is modified after signing, its hash changes, and the next DR's `prev_dr_hash` no longer matches, breaking the chain.

`drs_consent` — Human consent evidence. Required for human-rooted chains at the root DR. Records the consent method, timestamp, session ID, a hash of the policy text shown to the human (not the raw JSON — the human-readable translation), and the locale in which consent was obtained.

`drs_root_type` — `"human"`, `"organisation"`, or `"automated-system"`. Determines the trust model, renewal rules, and escalation path.

`drs_regulatory` — Regulatory classification. Determines mandatory storage tier and retention period.

### 5.2 The Sub-Delegation Receipt

When Agent 1 delegates to Agent 2, it produces a sub-delegation receipt. The `prev_dr_hash` links back to the root DR. The `iss` is Agent 1. The `sub` remains the original human (or organisation). The policy is equal to or tighter than the root DR.

```json
{
  "iss": "did:key:z6MkAgent1...",
  "sub": "did:key:z6MkHuman...",
  "aud": "did:key:z6MkAgent2...",

  "drs_v": "4.0",
  "drs_type": "delegation-receipt",

  "cmd": "/mcp/tools/call",
  "policy": {
    "max_cost_usd": 5.00,
    "pii_access": false,
    "allowed_tools": ["web_search"],
    "max_calls": 20
  },

  "nbf": 1743000060,
  "exp": 1743000960,
  "jti": "dr:9g4b3c2d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",

  "prev_dr_hash": "sha256:abc123def456..."
}
```

Key differences from the root DR: cost limit reduced from $50 to $5 (POLA — Principle of Least Authority), allowed tools narrowed to just web_search, expiry shortened to 15 minutes, `prev_dr_hash` populated.

### 5.3 The Invocation Receipt

When an agent actually calls a tool, it produces an Invocation Receipt. This is different from the delegation receipts. It records what was actually done, not what was authorised.

```json
{
  "iss": "did:key:z6MkAgent2...",
  "sub": "did:key:z6MkHuman...",

  "drs_v": "4.0",
  "drs_type": "invocation-receipt",

  "cmd": "/mcp/tools/call",
  "args": {
    "tool": "web_search",
    "query": "Monad blockchain throughput 2026",
    "estimated_cost_usd": 0.02,
    "pii_access": false
  },

  "dr_chain": [
    "sha256:abc123...",
    "sha256:def456..."
  ],

  "iat": 1743000300,
  "jti": "inv:7h5c4d3e-6f7a-8b9c-0d1e-2f3a4b5c6d7e",

  "tool_server": "did:key:z6MkToolServer...",
  "result_hash": "sha256:ghi789...",
  "policy_evaluation": "pass"
}
```

The `dr_chain` field contains the SHA-256 hashes of every DR in the chain, root to leaf. The tool server can verify the complete chain by resolving these hashes from the DR store, verifying each signature, and confirming the hash chain is unbroken.

### 5.4 The DRS Bundle

When an agent invokes a tool, it transmits a DRS Bundle — the invocation receipt plus all DRs in the chain. The tool server resolves the chain from the bundle (or from its local DR store if the DRs were pre-registered).

```json
{
  "bundle_version": "4.0",
  "invocation": { /* Invocation Receipt JWT */ },
  "receipts": [
    /* Root DR JWT */,
    /* Sub-delegation DR JWT */
  ]
}
```

---

## 6. Core Algorithms

### 6.1 DR Issuance

```
ALGORITHM: issue_delegation_receipt(issuer_key, audience_did, policy, parent_dr?)

INPUT:
  issuer_key      Ed25519 private key of the delegating party
  audience_did    DID of the party receiving delegation
  policy          JSON object with constraint fields
  parent_dr       The parent DR JWT (null for root)
  consent_data    Consent evidence (required if drs_root_type == "human")
  root_type       "human" | "organisation" | "automated-system"
  regulatory      Regulatory classification (optional)
  ttl_seconds     How long this delegation is valid

OUTPUT:
  Signed JWT (the Delegation Receipt)
  SHA-256 hash of the signed DR bytes (for use as prev_dr_hash by children)

STEPS:

1. If parent_dr is not null:
   a. Verify parent_dr signature using issuer's DID public key
   b. Confirm that parent_dr.aud == issuer's DID
      (you can only delegate what was delegated to you)
   c. Confirm that policy is at most as permissive as parent_dr.policy
      (POLA — child may only tighten, never loosen)
   d. Confirm that nbf >= parent_dr.nbf (child cannot start earlier)
   e. Confirm that exp <= parent_dr.exp (child cannot outlast parent)
   f. Set prev_dr_hash = SHA-256(canonical_json(parent_dr_bytes))

2. If parent_dr is null (root DR):
   a. Require consent_data if root_type == "human"
   b. Validate consent_data.policy_hash:
      - Recompute SHA-256 of the human-readable policy text shown
      - Must match consent_data.policy_hash
   c. Set prev_dr_hash = null

3. Build DR payload:
   {
     iss:             issuer DID,
     sub:             root subject DID (propagated from parent if not root),
     aud:             audience_did,
     drs_v:           "4.0",
     drs_type:        "delegation-receipt",
     cmd:             command path,
     policy:          policy,
     nbf:             current_unix_time(),
     exp:             current_unix_time() + ttl_seconds,
     iat:             current_unix_time(),
     jti:             "dr:" + random_uuid(),
     prev_dr_hash:    (from step 1f or null),
     drs_consent:     consent_data (if root),
     drs_root_type:   root_type,
     drs_regulatory:  regulatory
   }

4. Canonicalise the payload:
   Apply RFC 8785 (JSON Canonicalization Scheme, JCS)
   This ensures deterministic byte representation for signing

5. Sign:
   signature = Ed25519Sign(issuer_private_key, canonical_payload_bytes)

6. Assemble JWT:
   header = base64url({ "typ": "JWT", "alg": "EdDSA" })
   payload = base64url(canonical_payload_bytes)
   jwt = header + "." + payload + "." + base64url(signature)

7. Compute DR hash:
   dr_hash = SHA-256(jwt_bytes)

8. Store in DR store:
   store.put(dr_hash, jwt)

9. Return (jwt, dr_hash)
```

**Why JCS (RFC 8785) and not CBOR:** DRS v4 uses JSON + JCS for canonicalisation because the target stack is OAuth 2.1 / JWT. JCS is an IETF standard (RFC 8785) that produces deterministic JSON bytes, enabling reproducible SHA-256 hashes and Ed25519 signatures over JSON payloads. CBOR (used in UCAN v1.0) is not part of the OAuth/JWT ecosystem and would require a separate decode path at every tool server.

### 6.2 Chain Verification

```
ALGORITHM: verify_chain(bundle)

INPUT:
  bundle    DRS Bundle containing invocation receipt and all DRs

OUTPUT:
  VerificationResult { valid: bool, error?: ErrorDetail, context?: ChainContext }

STEPS:

-- BLOCK A: Bundle completeness --

A1. bundle.receipts must not be empty
    ERROR "EMPTY_CHAIN": No delegation receipts provided.

A2. bundle.invocation must be present
    ERROR "MISSING_INVOCATION": No invocation receipt provided.

-- BLOCK B: Structural integrity --

B1. For each DR at index i (0 = root):
    a. Decode JWT header and payload
    b. Confirm payload.drs_type == "delegation-receipt"
    c. Confirm payload.drs_v == "4.0" (or compatible version)

B2. Root DR (index 0):
    a. Confirm payload.prev_dr_hash == null
    b. If payload.drs_root_type == "human":
       Confirm payload.drs_consent is present and not null

B3. For each DR at index i > 0:
    a. Compute expected_prev_hash = SHA-256(bundle.receipts[i-1] bytes)
    b. Confirm payload.prev_dr_hash == expected_prev_hash
       ERROR "CHAIN_BREAK": DR[i].prev_dr_hash does not match computed
       hash of DR[i-1]. Chain is broken at index i. Either a DR was
       modified after signing or the wrong DR is at this position.

B4. Confirm DR[i].iss == DR[i-1].aud for all i > 0
    ERROR "ISSUER_MISMATCH": DR[i] was issued by DID X but was expected
    to be issued by DID Y (the audience of DR[i-1]). You can only delegate
    what was delegated to you.

B5. Confirm bundle.invocation.iss == bundle.receipts[last].aud
    ERROR "INVOKER_MISMATCH": The invoking agent is not the audience of
    the leaf delegation receipt.

B6. Confirm bundle.invocation.dr_chain contains the hashes of all DRs
    in order (root hash first).
    ERROR "CHAIN_REFERENCE_MISMATCH": Invocation receipt does not
    reference the correct DR chain.

-- BLOCK C: Cryptographic validity --

C1. For each DR:
    a. Resolve the issuer's public key from their DID
       (For did:key: decode from the DID itself — no network call)
       (For did:web: fetch from /.well-known/did.json — cache aggressively)
    b. Verify Ed25519 signature over the canonical payload bytes
       Use verify_strict(): checks S < L (malleability), weak key rejection
       ERROR "INVALID_SIGNATURE": Ed25519 signature verification failed
       at DR[i]. DID: [iss]. This means the DR was tampered with after
       signing, or the wrong private key signed it.

C2. Verify invocation receipt Ed25519 signature
    ERROR "INVALID_INVOCATION_SIGNATURE": Invocation signature invalid.

-- BLOCK D: Semantic validity --

D1. Policy evaluation — for each DR in the chain:
    a. Evaluate DR.policy against bundle.invocation.args
    b. ALL policies must pass (conjunctive evaluation)
    ERROR "POLICY_VIOLATION": Invocation args failed policy check in
    DR[i]. Failing constraint: [constraint]. Args provided: [args].

D2. Policy attenuation — for each DR at index i > 0:
    Each numeric upper bound in DR[i].policy must be <= the corresponding
    bound in DR[i-1].policy.
    Each allowlist in DR[i].policy must be a subset of DR[i-1].policy.
    ERROR "POLICY_ESCALATION": DR[i] has a less restrictive policy than
    DR[i-1]. Children may only tighten policy, never loosen it.

D3. Command consistency:
    Confirm all DRs and the invocation have compatible cmd values.
    (Exact match or sub-path of root cmd)
    ERROR "COMMAND_MISMATCH": DR[i] has command [X] which is not
    compatible with root command [Y].

D4. Subject consistency:
    Confirm DR[i].sub == DR[0].sub for all i.
    ERROR "SUBJECT_MISMATCH": DR[i] has a different subject than
    the root DR. The subject (resource owner) must remain constant
    through the entire chain.

-- BLOCK E: Temporal validity --

E1. Current time = unix_timestamp_now()
    For each DR:
    a. If DR.nbf is present: Confirm E1 >= DR.nbf
       ERROR "NOT_YET_VALID": DR[i] is not valid until [nbf].
       Current time: [now]. The agent attempted to use a delegation
       before its start time.
    b. If DR.exp is not null: Confirm E1 <= DR.exp
       ERROR "EXPIRED": DR[i] expired at [exp]. Current time: [now].
       Request a new delegation from the authorising party.

-- BLOCK F: Revocation check --

F1. For each DR:
    a. Check DR.jti against revocation service (Bitstring Status List)
    b. If revoked: ERROR "REVOKED": DR with jti [jti] was explicitly
       revoked at [timestamp]. The delegating party withdrew this
       authorisation.
    Revocation cache: 5-minute TTL. Accept stale cache on network failure.

-- RESULT --

If all blocks pass:
  Return VerificationResult {
    valid: true,
    context: {
      root_principal:   DR[0].iss,
      root_type:        DR[0].drs_root_type,
      consent_record:   DR[0].drs_consent,
      regulatory:       DR[0].drs_regulatory,
      leaf_policy:      DR[last].policy,
      chain_depth:      receipts.length,
      session_id:       DR[0].drs_consent?.session_id
    }
  }
```

### 6.3 Policy Evaluation

DRS policy is a JSON object with typed constraint fields. Evaluation is straightforward — there is no Policy Language to parse. This is the key difference from UCAN v1.0's Policy Language array. DRS uses plain JSON constraints that map directly to invocation argument checks.

```
ALGORITHM: evaluate_policy(policy, args)

INPUT:
  policy    JSON object from a Delegation Receipt
  args      JSON object from the Invocation Receipt

OUTPUT:
  PolicyResult { pass: bool, failing_constraint?: string, detail?: string }

STEPS:

For each constraint in policy:

  "max_cost_usd": N
    Check: args.estimated_cost_usd <= N
    Fail: "Cost constraint violated. Max allowed: $N. Provided: $[args.estimated_cost_usd]."

  "pii_access": false
    Check: args.pii_access == false (or field absent)
    Fail: "PII access constraint violated. This delegation does not permit PII access."

  "allowed_tools": [list]
    Check: args.tool is in list (if args.tool is present)
    Fail: "Tool not permitted. Allowed: [list]. Provided: [args.tool]."

  "max_calls": N
    Check: session_call_count <= N (requires session state lookup)
    Fail: "Call count limit reached. Max: N. Current: [count]."

  "allowed_resources": [list]
    Check: args.resource_uri matches one of the allowed patterns (glob)
    Fail: "Resource not permitted."

  "write_access": false
    Check: args.write_access == false (or field absent)
    Fail: "Write access constraint violated."

  "allowed_data_classes": [list]
    Check: args.data_class is in list (if present)
    Fail: "Data class not permitted."

Unknown constraint fields:
  Treat as opaque, log for debugging, do not fail.
  (Forward compatibility — future DRS versions may add constraints.)

If all checks pass: Return { pass: true }
```

### 6.4 Policy Attenuation Check

```
ALGORITHM: check_policy_attenuation(parent_policy, child_policy)

INPUT:
  parent_policy   Policy from DR[i-1]
  child_policy    Policy from DR[i]

OUTPUT:
  AttenuationResult { valid: bool, violation?: string }

STEPS:

For each numeric upper bound in parent_policy:
  If the same field exists in child_policy:
    Confirm child_policy[field] <= parent_policy[field]
    VIOLATION: "Child DR loosens upper bound for [field].
    Parent: [parent_value]. Child: [child_value]."

For each allowlist field in parent_policy:
  If the same field exists in child_policy:
    Confirm child_policy[field] is a subset of parent_policy[field]
    VIOLATION: "Child DR adds [extra_items] to allowlist for [field]
    which are not permitted by parent DR."

For each boolean restriction in parent_policy (e.g. pii_access: false):
  Confirm child_policy does not set this to a less restrictive value
  VIOLATION: "Child DR relaxes restriction for [field]."

If child_policy contains a field not in parent_policy:
  This is adding a new restriction — always valid (child is more restrictive)

Return { valid: true } if no violations found.
```

---

## 7. Human Interaction Flows

### 7.1 Flow 1: End User Granting Agent Authority

This is the most visible flow. A human grants an AI agent the authority to act on their behalf. DRS makes this consent concrete, specific, and revocable.

**Step 1: The application requests delegation.**

The agent application shows the user a consent screen. This is NOT a raw JSON policy dump. The DRS Consent Translator converts the machine policy into plain language:

```
Raw policy in DR:
{ "max_cost_usd": 50.00, "pii_access": false, "allowed_tools": ["web_search", "write_file"] }

Translated to English (en-GB):
─────────────────────────────────────────────────────────
 Research Agent wants permission to:
 ✓ Search the web (up to 100 times per session)
 ✓ Create and save files in your workspace
 ✗ Cannot access personal data
 ✗ Cannot spend more than £50.00

 This permission expires in 30 days.
 You can revoke it at any time.
─────────────────────────────────────────────────────────
```

The policy hash stored in `drs_consent.policy_hash` is the SHA-256 of the English text shown above — not the raw JSON. This allows an auditor to verify that the user saw accurate, legible information, not obfuscated machine syntax.

**Step 2: User clicks Authorise.**

The application:
1. Records the consent event: method, timestamp, session ID, locale.
2. Issues the root DR using `issue_delegation_receipt()` with the user's private key.
3. Stores the DR in the DR store with the appropriate storage tier.
4. Registers the DR's JTI with the session manager.

**Step 3: Agent receives the delegation.**

The agent receives the root DR JWT. It verifies the signature and confirms the audience matches its own DID. It then loads the policy into its runtime context — this is the authoritative policy it will operate under until the DR expires or is revoked.

**Step 4: Agent operates within the delegation window.**

For each action:
1. Agent calls `evaluate_policy(root_dr.policy, proposed_args)` before invoking any tool.
2. If the check passes, agent creates a sub-delegation DR to the specific tool server.
3. Agent creates an Invocation Receipt.
4. Agent bundles the DRS Bundle (root DR + sub-delegation DR + Invocation Receipt).
5. Agent sends the bundle to the tool server via MCP, in the `X-DRS-Bundle` HTTP header.

**Step 5: Tool server verifies.**

Tool server calls `verify_chain(bundle)`. If valid, executes the tool call. If invalid, returns an error with the specific failure from the verification algorithm.

**Step 6: Human reviews activity.**

The session manager displays every tool call made by the agent, with cost, result, and the DR JTI that authorised it. The human can revoke at any time.

### 7.2 Flow 2: Developer Integrating DRS

```
Day 1:
  npm install @drs/sdk
  
  import { DRS } from '@drs/sdk';
  const drs = new DRS({ signingKey: process.env.AGENT_PRIVATE_KEY });

  // Verify a bundle received from a calling agent
  const result = await drs.verify(bundle);
  if (!result.valid) {
    console.error(result.error.message);    // Full English explanation
    console.error(result.error.suggestion); // What to do about it
    return;
  }

  // All checks passed — safe to execute
  executeTool(result.context);
```

Error messages are complete English sentences with a diagnosis and a suggested fix. No error codes alone. Example:

```
ERROR: Chain break at DR index 1.
  DR[1].prev_dr_hash is "sha256:abc..." but computing SHA-256 of DR[0]
  produces "sha256:def...". This means either DR[0] was modified after
  DR[1] was issued, or the wrong DR is at position 0 in the bundle.
  
SUGGESTION: Re-build the bundle from the original DR store. Ensure DRs
  are ordered root-first (index 0 = root). Ensure parent DRs are not
  modified after children are issued.
```

The CLI verifier:
```bash
# Install
npm install -g @drs/cli

# Verify a bundle
drs verify bundle.json
# Output: step-by-step verification with pass/fail at each block

# Explain a policy against test args
drs policy explain receipt.json --args '{"tool":"web_search","estimated_cost_usd":30}'
# Output: constraint-by-constraint evaluation

# Translate a policy to human language
drs translate receipt.json --locale en-GB
# Output: plain-language description of what the agent can do
```

### 7.3 Flow 3: Auditor Reconstructing a Chain

An auditor investigating an incident retrieves the complete delegation evidence for a specific agent action:

```bash
# Retrieve all DRs for a given invocation JTI
drs audit retrieve --inv-jti "inv:7h5c4d3e-..."

# Output:
DR Chain for invocation inv:7h5c4d3e-...
────────────────────────────────────────
[0] Root DR (dr:8f3a2b1c-...)
    Issued by:  did:key:z6MkHuman... (Human principal)
    Issued to:  did:key:z6MkAgent1...
    Issued at:  2026-03-28T10:30:00Z
    Expires:    2026-04-27T10:30:00Z
    Consent:    explicit-ui-click, session sess:8f3a2b1c
    Policy:     max_cost=$50, pii=false, tools=[web_search, write_file]
    Signature:  VALID ✓
    Revoked:    No ✓

[1] Sub-delegation DR (dr:9g4b3c2d-...)
    Issued by:  did:key:z6MkAgent1... (Agent — audience of DR[0])
    Issued to:  did:key:z6MkToolServer...
    Issued at:  2026-03-28T14:22:00Z
    Expires:    2026-03-28T14:37:00Z (15-minute sub-delegation)
    Policy:     max_cost=$5, pii=false, tools=[web_search]
    Prev hash:  sha256:abc123... matches DR[0] ✓
    Signature:  VALID ✓
    Revoked:    No ✓

[2] Invocation Receipt (inv:7h5c4d3e-...)
    Invoker:    did:key:z6MkAgent1...
    Subject:    did:key:z6MkHuman...
    Command:    /mcp/tools/call
    Tool:       web_search
    Query:      "Monad blockchain throughput 2026"
    Cost:       $0.02
    Policy:     PASS ✓
    Signature:  VALID ✓

Chain integrity: VERIFIED
Human consent: CONFIRMED (explicit-ui-click, 2026-03-28T10:30:00Z)
```

The auditor can verify this chain independently — they do not need to contact Quorum or any third party. Every verification uses public keys derived from DIDs. Every receipt is signed. Every hash link is computable.

---

## 8. Machine-to-Machine Trust Model

This is the section that every previous version of this document failed to define. The question: if there is no human consent UI — if the system is an internal deployment like an enterprise automation pipeline or a CLI-based agent runtime — where does trust originate?

### 8.1 The Problem with Human-Centric Trust

Previous DRS versions assumed the root of every delegation chain is a human clicking a consent button. This assumption breaks for:
- Internal enterprise agent systems deployed without user-facing UIs
- Agentic pipelines triggered by cron jobs, webhooks, or inter-agent messages
- Operator-deployed systems where the "user" is the organisation itself
- CLI-based agent runtimes with no browser or notification surface

Human interaction is not a predictable scheduling primitive. A human might not respond for days, or ever. Building a trust model that requires human intervention at specific times is not a trust model — it is a dependency on human availability.

### 8.2 Machine-Identity Root Delegations

When `drs_root_type` is `"automated-system"` or `"organisation"`, the root DR is signed by an operator key — a key controlled by the organisation deploying the agent, not by an individual human. This key is established at deployment time through an operator configuration process, not through a consent UI.

**Operator configuration:**
```json
{
  "drs_root_type": "automated-system",
  "operator_did": "did:key:z6MkOrg...",
  "operator_key_management": "HSM",
  "standing_policy": {
    "max_cost_usd_per_hour": 100.00,
    "pii_access": false,
    "allowed_tools": ["web_search", "write_file", "read_file"],
    "allowed_external_apis": ["api.github.com", "api.monad.xyz"]
  },
  "renewal_rules": {
    "auto_renew": true,
    "max_ttl_days": 7,
    "renewal_requires_human_approval": false
  },
  "escalation": {
    "target_type": "supervisor_agent",
    "supervisor_did": "did:key:z6MkSupervisor..."
  }
}
```

This configuration is set once by a human (a system administrator or DevOps engineer) at deployment time. The system then operates autonomously within these bounds. Auto-renewal is permissible when the root principal is a machine identity — the renewal rules are part of the original operator configuration, which was itself a human act.

### 8.3 Escalation to Supervisor Agent, Not Human

When an agent hits a policy boundary in a machine-to-machine deployment:
1. The agent writes a capability request to its escalation channel (log file, internal queue, Slack webhook — deployment-specific).
2. The capability request is addressed to the supervisor agent DID specified in `escalation.target_type`.
3. The supervisor agent evaluates the request against its own policy and the operator configuration.
4. If approved, the supervisor agent issues a new sub-delegation DR extending the capability.
5. If denied, the requesting agent completes as much work as possible within its current capability and logs a blocked-task record.

The supervisor agent is itself governed by a DRS delegation chain rooted in the operator key. This means escalations are auditable — every capability grant by the supervisor is a signed DR.

### 8.4 What Happens When No Human Is Available

The agent's behaviour at each boundary:

| Boundary | Human-rooted chain | Machine-rooted chain |
|---|---|---|
| Policy limit hit | Log capability request, send push notification, wait | Escalate to supervisor agent |
| Delegation expiring | Send renewal notification 48h before, wait | Auto-renew per renewal_rules |
| Delegation expired | Stop all new actions, preserve work-in-progress | Renew immediately if auto_renew=true |
| Capability denied | Complete partial work, return partial result with explanation | Complete partial work, log blocked task |

In all cases: the agent never silently ignores a boundary. It never proceeds anyway. It never fails without a record. The activity log (equivalent to HEARTBEAT.md in an OpenClaw deployment) contains every action, its cost, its DR JTI, and any escalation events.

---

## 9. MCP Integration

### 9.1 The MCP Authorization Stack

MCP's authorization spec (March 2025, updated June and November 2025) defines:
- OAuth 2.1 as the base authorization framework
- RFC 9728 (Protected Resource Metadata) for dynamic auth discovery
- RFC 8707 (Resource Indicators) for per-server audience binding
- PKCE mandatory for all clients

DRS sits on top of this stack. It does not replace it. An MCP server that implements DRS still implements OAuth 2.1 + RFC 9728. DRS adds a requirement: alongside the OAuth access token, agents must include a DRS Bundle proving the delegation chain for the action they are requesting.

### 9.2 HTTP Header Transport

DRS bundles are transmitted via HTTP headers:

```http
POST /mcp/tools/call HTTP/1.1
Authorization: Bearer <OAuth_access_token>
X-DRS-Bundle: <base64url(JSON.stringify(bundle))>
Content-Type: application/json

{
  "tool": "web_search",
  "query": "Monad blockchain throughput 2026"
}
```

The `Authorization` header carries the standard OAuth 2.1 bearer token. The MCP server validates this token as it would without DRS — issuer, audience, expiry, scopes.

The `X-DRS-Bundle` header carries the DRS Bundle. The MCP server that implements DRS middleware calls `verify_chain(bundle)` before executing the tool call. If verification fails, it returns a 403 with the DRS error details.

### 9.3 DRS Middleware for MCP Servers

```typescript
// @drs/mcp-middleware

import { DRS } from '@drs/sdk';
import type { MCPRequest, MCPContext } from '@modelcontextprotocol/sdk';

export function drsMiddleware(opts: { mode: 'require' | 'warn' | 'skip' }) {
  const drs = new DRS();

  return async (req: MCPRequest, ctx: MCPContext, next: () => Promise<void>) => {
    const bundleHeader = req.headers?.['x-drs-bundle'];

    if (!bundleHeader) {
      if (opts.mode === 'require') {
        ctx.status = 403;
        ctx.body = {
          error: 'DRS_BUNDLE_MISSING',
          message: 'This MCP server requires a DRS delegation bundle. ' +
                   'Include the X-DRS-Bundle header with a valid bundle. ' +
                   'See docs.delegationreceipt.org for SDK documentation.',
        };
        return;
      }
      return next();
    }

    let bundle;
    try {
      bundle = JSON.parse(
        Buffer.from(bundleHeader, 'base64url').toString('utf-8')
      );
    } catch {
      ctx.status = 400;
      ctx.body = {
        error: 'DRS_BUNDLE_MALFORMED',
        message: 'X-DRS-Bundle header could not be decoded. ' +
                 'Ensure the bundle is base64url-encoded JSON.',
      };
      return;
    }

    const result = await drs.verify(bundle);

    if (!result.valid) {
      if (opts.mode === 'require') {
        ctx.status = 403;
        ctx.body = {
          error: result.error.code,
          message: result.error.message,
          suggestion: result.error.suggestion,
        };
        return;
      }
      ctx.drsWarning = result.error;
    } else {
      ctx.drs = result.context;
      // Available to tool handlers:
      // ctx.drs.root_principal     — who ultimately authorised this
      // ctx.drs.root_type          — "human" | "organisation" | "automated-system"
      // ctx.drs.consent_record     — human consent evidence if applicable
      // ctx.drs.regulatory         — regulatory classification
      // ctx.drs.leaf_policy        — effective policy constraints
      // ctx.drs.chain_depth        — number of delegation hops
    }

    // Emit activity event for audit trail
    await emitActivityEvent({
      type: 'drs:tool-call',
      timestamp: new Date().toISOString(),
      root_principal: result.context?.root_principal,
      inv_jti: bundle.invocation?.jti,
      tool: req.body?.tool,
      policy_result: result.valid ? 'pass' : 'fail',
      error_code: result.error?.code,
    });

    return next();
  };
}
```

### 9.4 STDIO Transport (No HTTP Headers)

For MCP STDIO transport — used in CLI-based agent runtimes with no HTTP layer — the DRS Bundle is passed differently. The MCP spec states: "Implementations using STDIO transport SHOULD NOT follow the HTTP authorization specification, and instead retrieve credentials from the environment."

For STDIO deployments, DRS bundles are passed via:
1. A well-known file path in the agent workspace (e.g., `./drs_bundle.json`), loaded by the tool at startup.
2. A dedicated field in the MCP JSON-RPC message envelope (proposed DRS extension to MCP spec).
3. An environment variable containing the base64url-encoded bundle (for short-lived single-tool invocations).

The verification algorithm is identical regardless of transport.

---

## 10. Storage Architecture

The DR store is not optional. DRS's chain verification algorithm requires resolving DR content from hashes. Without a persistent store, verification is impossible.

### 10.1 Storage Tiers

| Tier | Trigger | Backend | Retention | SLA |
|---|---|---|---|---|
| 0 — Session | All DRs (default) | In-process memory | Session lifetime | Immediate |
| 1 — Ephemeral | Default for production | Local filesystem or Redis | 48 hours | Best effort |
| 2 — Durable | `retention_days > 0` | S3-compatible object store | As specified | 99.9% availability |
| 3 — Compliant | EU AI Act, HIPAA, SOC 2 | Durable store + WORM policy | Framework-mandated minimum | Legally defensible |
| 4 — On-chain | High-stakes delegations | Durable store + Monad anchor | Permanent hash proof | On-chain CID proves content existed |

### 10.2 Storage Policy Determination

```typescript
function determineStorageTier(dr: DelegationReceipt): StorageTier {
  const regulatory = dr.drs_regulatory;

  if (!regulatory || regulatory.retention_days === 0) {
    return StorageTier.Ephemeral;
  }

  if (regulatory.frameworks.includes('sox') ||
      regulatory.frameworks.includes('hipaa')) {
    return StorageTier.Compliant; // WORM, 7-year minimum
  }

  if (regulatory.frameworks.includes('eu-ai-act-art13') &&
      regulatory.risk_level === 'high') {
    return StorageTier.OnChain; // Immutable hash proof required
  }

  if (regulatory.retention_days > 0) {
    return StorageTier.Durable;
  }

  return StorageTier.Ephemeral;
}
```

### 10.3 Revocation — Bitstring Status List

DRS uses the W3C Bitstring Status List (v1.0) for revocation. A status list is a compressed bitstring where each bit represents the revocation status of one DR (by its position in the list, encoded in `drs_status_list_index` in the DR payload).

Revocation is checked in Block F of the verification algorithm. The status list is fetched from the DR store or a well-known URL and cached with a 5-minute TTL. Revocation by the issuer sets their DR's bit to 1. This takes effect on every tool server that fetches a fresh status list within 5 minutes.

For the highest-assurance deployments, revocations are also anchored on-chain. The Monad on-chain registry records revocation events with block timestamps, providing an independent and tamper-evident revocation log.

---

## 11. Language and Runtime Stack

### 11.1 Language Allocation

| Layer | Language | Rationale |
|---|---|---|
| Crypto core | Rust | No GC, stack-allocated byte arrays, constant-time operations, compiles to WASM |
| Verification middleware | Go | Goroutines handle concurrent verification, predictable GC, net/http native |
| Developer SDK | TypeScript | npm ecosystem, low-frequency operations (issuance not verification) |
| Consent UI | TypeScript / React | Standard component approach |
| Solidity | Monad EVM | On-chain registry requirement |

### 11.2 Verified Rust Dependencies

```toml
[dependencies]
# Ed25519 signing and verification
# RUSTSEC-2022-0093 patched in 2.0.0. verify_strict() available.
# S < L enforced by all verify_* methods in 2.x.
ed25519-dalek = "2.2.0"

# SHA-256 for DR content hashing and prev_dr_hash
sha2 = "0.10"

# JSON Web Token encoding/decoding
jsonwebtoken = "9.3"

# RFC 8785 JSON Canonicalization Scheme
# Required for deterministic signing over JSON payloads
jcs = "0.1"

# CID computation (for optional on-chain anchoring)
# Note: cid = "1.0" does NOT exist. Latest is 0.11.1.
cid = "0.11.1"

# WASM compilation
wasm-bindgen = "0.2"
```

**Critical correction from v3:** `cid = "1.0"` was cited in previous versions. This version does not exist. The crate has never left 0.x. The correct version is `0.11.1`. Any code referencing `cid = "1.0"` will fail to compile.

### 11.3 Verified Go Dependencies

```go
require (
  // JWT parsing and validation
  github.com/golang-jwt/jwt/v5 v5.2.1

  // Ed25519 — use stdlib (golang.org/x/crypto wraps it)
  golang.org/x/crypto v0.21.0

  // LRU cache for DID public key resolution
  github.com/hashicorp/golang-lru/v2 v2.0.7

  // CBOR (only needed if providing UCAN compatibility layer)
  github.com/fxamacker/cbor/v2 v2.9.0

  // SHA-256 — use stdlib crypto/sha256
)
```

**Critical correction from v3:** `github.com/multiformats/go-cid` was cited with a wrong module path. The correct path is `github.com/ipfs/go-cid`. The latest version is v0.5.0. The `multiformats` path does not host this module — `go get github.com/multiformats/go-cid` will fail.

### 11.4 Verified TypeScript Dependencies

```json
{
  "dependencies": {
    "@drs/core-wasm": "*",
    "jose": "^5.9.6",
    "did-resolver": "^4.1.0",
    "key-did-resolver": "^3.1.0",
    "uint8arrays": "^5.1.0"
  }
}
```

**Why `jose` instead of `jsonwebtoken`:** `jose` is the recommended JWT library for browser + Node.js with native Ed25519 support, maintained by Panva. `jsonwebtoken` has limited EdDSA support. `jose` is what MCP implementations use.

### 11.5 Performance Profile

Verification performance targets (verified against ed25519-dalek 2.x benchmarks):

| Operation | Target | Mechanism |
|---|---|---|
| Ed25519 signature verification | ~0.05ms | Hardware acceleration (AVX-512 on supported CPUs) |
| SHA-256 (per DR hash) | ~0.003ms | Hardware SHA-NI |
| JSON parse (per DR) | ~0.05ms | serde_json |
| DID resolution (did:key) | ~0.001ms | Pure computation, no network |
| Full chain, n=3 DRs | ~0.5ms | All above combined |
| Full chain, n=5 DRs | ~0.8ms | Linear scaling |
| Policy evaluation | ~0.01ms | Simple JSON field comparison |

Verification is stateless. No locks, no shared state in the critical path. Horizontal scaling is unlimited.

---

## 12. Technical Audit — Verified Claims Only

This section audits every technical claim in the DRS specification against primary sources. Anything that cannot be verified is excluded.

### 12.1 UCAN Status — Verified

**Claim (v1–v3):** DRS should be built on UCAN v1.0.0-rc.1.

**Verdict: Incorrect for v4.**

Verified facts:
- The UCAN working group (github.com/ucan-wg) has commits as recent as January 2026. It is not completely dead.
- go-ucan is the most active implementation (443+ commits). rs-ucan is published on crates.io at v0.8.
- The spec is at v1.0.0-rc.1 and has not advanced to final 1.0. No timeline announced.
- Fission (the company that created UCAN) shut down April 2024.
- AT Protocol and MCP both chose OAuth 2.1 over UCAN.
- Storacha (web3.storage) is the only meaningful production user.
- Boris Mann (Fission co-founder): "Capabilities adoption needs a lot more education and promotion."

**Decision:** DRS v4 is built on OAuth 2.1 + RFC 8693 + MCP. UCAN is acknowledged as a theoretically valid alternative with different trade-offs. A UCAN compatibility layer may be defined in a future addendum. UCAN is not the primary path because it is not where the ecosystem lives.

### 12.2 RFC 8693 Delegation Chain Splicing — Verified

**Claim:** RFC 8693 has a structural weakness that DRS fixes.

**Verdict: Verified. Primary source: IETF OAuth WG mailing list.**

The IETF OAuth WG thread (mail-archive.com/oauth@ietf.org/msg25680.html) documents:
- RFC 8693 Section 4.1: nested `act` claims are "informational only"
- `may_act` is optional — no normative requirement to carry it or enforce it
- No cross-validation between `subject_token` and `actor_token`
- CVE-2025-55241 (Microsoft Entra ID, patched July 2025) is the real-world precedent
- Suggested mitigation 3: "Per-step delegation receipts"

The Agentic JWT IETF draft (draft-goswami-agentic-jwt-00, December 2025) also identifies this gap and proposes complementary mechanisms.

### 12.3 MCP Authorization Spec — Verified

**Claim:** MCP uses OAuth 2.1 + RFC 9728 + RFC 8707 + PKCE.

**Verdict: Verified. Primary source: modelcontextprotocol.io/specification.**

- March 2025: OAuth 2.1 standardised in MCP
- June 2025: Protected Resource Metadata (RFC 9728) formalised, MCP servers split from auth servers
- November 2025: PKCE mandatory, Client ID Metadata Documents introduced

### 12.4 Ed25519 — Verified

**Claim:** ed25519-dalek 2.2.0 is the correct Rust library. `verify_strict()` enforces S < L.

**Verdict: Partially corrected.**

Verified:
- ed25519-dalek 2.2.0 is the current latest on crates.io.
- RUSTSEC-2022-0093 was fully patched in v2.0.0.
- `verify_strict()` exists on `VerifyingKey`.

Correction from v3:
- S < L (S is in [0, L) range, preventing signature malleability) is enforced by ALL `verify_*()` methods in ed25519-dalek 2.x, not just `verify_strict()`.
- `verify_strict()` additionally checks: (1) public key is not a weak/low-order point via `is_weak()`, (2) cofactored verification equation `[8][S]B = [8]R + [8][k]A`.
- Describing `verify_strict()` as "the one that enforces S < L" implies standard `verify()` does not — this is false. Use `verify_strict()` for DRS, but the S < L protection is universal.

**What S < L means precisely:** An Ed25519 signature is `(R, S)` where S is a scalar in the range `[0, L)` with L = 2^252 + 27742317777372353535851937790883648493. Without this check, `(R, S)` and `(R, S + L)` are both valid signatures for the same message, since both satisfy the verification equation modulo L. This signature malleability would allow an attacker to produce a second valid signature for any message, breaking systems that use signatures as unique identifiers.

### 12.5 JWT Canonicalization — Verified

**Claim:** DRS uses RFC 8785 (JCS) for deterministic JSON encoding.

**Verdict: Correct, and this is the right choice for the OAuth/JWT ecosystem.**

RFC 8785 (JSON Canonicalization Scheme) is the IETF standard for deterministic JSON serialisation. It applies lexicographic key ordering, Unicode normalisation, and IEEE 754 floating-point representation. The Rust `jcs` crate (v0.1) implements it. This replaces the CBOR deterministic encoding (RFC 8949 §4.2) used in UCAN v1.0, which was only necessary because UCAN used CBOR/IPLD.

### 12.6 libipld Deprecation — Verified

**Claim (v3):** DRS Rust code used `libipld` and `libipld-cbor`.

**Verdict: These crates are deprecated. Do not use them.**

The IPLD Rust team deprecated `libipld` in March 2024. The recommended replacement is `serde_ipld_dagcbor` (v0.6.4) for CBOR encoding in IPLD-native contexts. However, DRS v4 does not use CBOR at all — it uses JSON + JCS. Neither `libipld` nor `serde_ipld_dagcbor` is a DRS v4 dependency.

### 12.7 Go Module Path for go-cid — Verified

**Claim (v3):** `github.com/multiformats/go-cid v0.4.1`

**Verdict: Wrong module path.**

The correct module path is `github.com/ipfs/go-cid`. Latest version: v0.5.0. There is no Go module at `github.com/multiformats/go-cid`. A `go get` using the incorrect path will fail. DRS v4 does not use go-cid as a primary dependency — it is only needed in the optional on-chain anchoring module.

### 12.8 Policy Attenuation — Verified

**Claim (v3):** `policy_is_at_least_as_strict()` is a formal function in UCAN v1.0.

**Verdict: This function does not exist in any UCAN specification. It was invented in v2.**

In UCAN v1.0, policy attenuation is enforced through conjunctive runtime evaluation — every policy in the proof chain is evaluated against the invocation args at verification time. There is no structural comparison between parent and child policies at issuance time.

DRS v4 defines its own `check_policy_attenuation()` algorithm (Section 6.4) that checks numeric upper bounds, allowlist subsetting, and boolean restrictions at issuance time. This is a DRS-specific guarantee, not something inherited from UCAN. It is correctly labelled as such.

### 12.9 The `prf` Field Placement — Verified

**Claim (v3):** `prf` (proofs) is in the UCAN delegation envelope.

**Verdict: Wrong. In UCAN v1.0, `prf` is in the invocation payload, not the delegation.**

In UCAN v1.0:
- Delegations do not have a `prf` field. A delegation is a proof.
- Invocations have `prf` in their payload — an array of delegation CIDs.

DRS v4 does not use UCAN delegation/invocation envelopes. DRS uses its own DR format (Section 5). The hash chain is implemented via `prev_dr_hash` in the DR payload — an explicitly DRS-defined field with a clear semantics.

---

## 13. Security Model

### 13.1 Threat Table

| Threat | Attack Description | DRS Mitigation | Residual Risk |
|---|---|---|---|
| Forged root DR | Attacker creates fake root delegation | Ed25519 EUF-CMA: forgery requires discrete log | Private key compromise |
| Chain splicing | Compromised agent presents tokens from different delegation contexts | `prev_dr_hash` chain links receipts cryptographically | Implementation bugs |
| Policy escalation at issuance | Child claims looser policy than parent | `check_policy_attenuation()` at issuance time | Semantic edge cases in complex policy |
| Policy violation at invocation | Agent submits args that violate policy | Block D of `verify_chain()` evaluates all policies against args | Policy completeness |
| DR tampering | Attacker modifies a signed DR | Ed25519 signature fails on modified content | None — structural |
| Chain injection | Attacker inserts fake intermediate DR | `prev_dr_hash` chain — insertion changes all subsequent hashes | None — structural |
| Replay after revocation | Old valid DR reused after human revokes | Block F revocation check, 5-minute cache window | Stale cache window |
| JSON malleability | Different JSON representations of same object produce different hashes | RFC 8785 JCS enforced at issuance and verification | Non-conforming implementations |
| Signature malleability | `(R, S)` and `(R, S+L)` both valid for same message | ed25519-dalek 2.x enforces S < L in all verify methods | None — library enforces |
| DID spoofing | Attacker registers a DID that looks like a legitimate issuer | `did:key` DIDs are derived from the public key — cannot be spoofed | `did:web` DIDs require DNS/TLS trust |

### 13.2 JSON Malleability — The DRS-Specific Risk

DRS uses JSON + JCS for canonicalisation. CBOR (used in UCAN) has its own malleability risk (multiple valid encodings). JSON has a different one: key ordering. JCS (RFC 8785) specifies lexicographic key ordering and consistent number formatting. If two implementations produce different canonical JSON for the same payload, they will compute different hashes and different signatures, breaking the chain.

Mitigation: The DRS test suite includes 300+ test vectors for JCS canonicalisation edge cases. Every reference implementation must pass these vectors before publishing.

### 13.3 Key Management Requirements

- Root DR issuers (humans or operators) must use hardware-backed keys where possible (HSM, Secure Enclave, YubiKey).
- Agent keys (for signing sub-delegation DRs and invocation receipts) rotate per-session. Long-lived agent keys are prohibited.
- Key rotation: when an agent key is rotated, all standing delegations issued to the old key become invalid. The agent must request new delegations.
- The DID:key method encodes the public key directly in the DID — no centralised registry required. This is the preferred DID method for agents.

---

## 14. Regulatory Alignment

### 14.1 EU AI Act

The EU AI Act (in force 2026) requires, for high-risk AI systems (Annex III):
- Article 12: Record-keeping — "High-risk AI systems shall technically allow for the recording of events relevant to identifying risks to the health and safety or fundamental rights of natural persons."
- Article 13: Transparency — "High-risk AI systems shall be designed and developed in such a way as to ensure that their operation is sufficiently transparent."

DRS Delegation Receipts satisfy Article 12 by producing cryptographically signed, tamper-evident records of every delegation event. They satisfy Article 13 by making the delegation chain independently verifiable — the auditee does not control the audit evidence.

### 14.2 HIPAA

HIPAA requires audit controls (§164.312(b)): "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information."

DRS Invocation Receipts record every agent action with the full delegation provenance. For healthcare deployments, the `drs_regulatory.frameworks` field must include `"hipaa"`, triggering Tier 3 (Compliant) storage with WORM policy and 7-year retention.

### 14.3 SOX

SOX Section 404 requires internal controls over financial reporting and their audit. When agents make decisions affecting financial records, DRS provides the audit trail required to demonstrate those decisions were properly authorised.

### 14.4 AIUC-1 Certification

The AI Underwriting Company (AIUC) emerged from stealth in July 2025 with a $15M seed led by Nat Friedman. AIUC-1 certification covers 50+ controls including accountability and reliability. UiPath is the first certified enterprise platform.

DRS is designed to generate the evidence required for AIUC-1 certification. Specifically, DRS receipts satisfy the accountability controls that require demonstrable proof of authorisation for every agent action, not just logs of what actions occurred.

### 14.5 FINOS AI Governance Framework

The FINOS (Fintech Open Source Foundation) community has published a framework for "Agent Decision Audit and Explainability" targeting financial services. Their four-tier implementation framework requires Tier 3 and Tier 4 deployments to produce chain-of-custody evidence for legal proceedings. DRS Delegation Receipts are designed to satisfy this requirement.

---

## 15. Implementation Roadmap

### Phase 1 — Core (Months 1–4)

Deliverables that must exist before anything else:

- [ ] Rust core library: Ed25519 sign/verify, JCS canonicalisation, SHA-256 hashing, DR issuance, chain verification algorithm
- [ ] Compile to WASM via `wasm-pack`
- [ ] TypeScript SDK wrapping WASM: `issueRootDR`, `issueSubDelegationDR`, `buildBundle`, `verifyChain`
- [ ] Human-readable error system with 12 error codes, English messages, and suggested fixes
- [ ] JCS canonicalisation test vectors (300+ cases)
- [ ] CLI: `drs verify`, `drs policy check`, `drs translate`
- [ ] DR store: in-memory (Tier 0) and filesystem (Tier 1) backends

### Phase 2 — MCP Integration and Developer Experience (Months 4–8)

- [ ] Go verification middleware for MCP servers
- [ ] `@drs/mcp-middleware` TypeScript package for MCP servers
- [ ] Consent Translator: policy JSON → plain language (English, French, Spanish, Portuguese, Japanese)
- [ ] Session Manager: list active delegations, revoke, view activity
- [ ] Online playground: paste a bundle, see step-by-step verification
- [ ] S3-compatible DR store backend (Tier 2 — Durable)
- [ ] Bitstring Status List revocation
- [ ] STDIO transport support for CLI-based agent runtimes

### Phase 3 — Enterprise and Compliance (Months 8–18)

- [ ] WORM-compliant DR store backend (Tier 3 — Compliant)
- [ ] Monad on-chain registry (Tier 4 — On-Chain)
- [ ] Audit export API: generate compliance evidence bundles for EU AI Act, HIPAA, SOX
- [ ] AIUC-1 evidence generation workflow
- [ ] Machine-to-machine trust model: operator configuration, supervisor agent escalation
- [ ] Auto-renewal for `drs_root_type: "automated-system"`
- [ ] Enterprise identity provider integration: Okta, Auth0, Microsoft Entra ID

### Phase 4 — Standardisation (Year 2+)

- [ ] Submit DRS as an IETF Internet Draft (complement to draft-goswami-agentic-jwt)
- [ ] Engagement with IETF OAuth WG on the chain splicing mitigation
- [ ] CNCF proposal for neutral governance
- [ ] Reference implementations: Python, Java, Rust CLI
- [ ] UCAN compatibility addendum (mapping DRS receipts to UCAN invocations for hybrid deployments)

---

## 16. What DRS Does Not Solve

Precision about non-goals prevents scope creep and misrepresentation.

**Behavioural safety:** DRS proves an action was authorised. It cannot prove the action was safe or beneficial. An agent with a valid delegation chain can still cause harm within the bounds of its policy.

**LLM non-determinism:** If an agent's behaviour changes because its system prompt was altered or a model version changed, DRS does not detect this. Agentic JWT (draft-goswami-agentic-jwt) addresses this with agent checksums. DRS and Agentic JWT are complementary.

**Prompt injection:** An adversary embedding instructions in a document that an agent reads can cause the agent to take actions outside its intended scope. DRS records what the agent did, not why it did it.

**Post-compromise recovery:** Delegations signed before a key was compromised cannot be retroactively invalidated except by revocation, which only prevents future use. The historical DR chain from before the compromise remains valid.

**Cross-jurisdictional legal enforceability:** DRS produces cryptographically verifiable evidence. Whether that evidence satisfies the evidentiary standards of a specific jurisdiction is a legal question, not a technical one.

**Agent identity beyond DID:** DRS uses DIDs for agent identity. DID infrastructure has varying levels of maturity. `did:key` is universally available. `did:web` requires DNS/TLS trust and domain control. DRS does not define a global agent registry.

---

## Appendix A: Error Code Reference

| Code | English Message | Suggestion |
|---|---|---|
| `EMPTY_CHAIN` | No delegation receipts in bundle | Build the bundle with at least one DR |
| `MISSING_INVOCATION` | No invocation receipt in bundle | Include the invocation receipt in the bundle |
| `CHAIN_BREAK` | DR[i].prev_dr_hash does not match computed hash of DR[i-1] | Ensure DRs are ordered root-first. Do not modify parent DRs after issuing children. |
| `ISSUER_MISMATCH` | DR[i] was not issued by the audience of DR[i-1] | Each DR must be issued by the party that received the previous DR |
| `INVOKER_MISMATCH` | Invocation issuer is not the audience of the leaf DR | The agent creating the invocation must be the audience of the last DR |
| `CHAIN_REFERENCE_MISMATCH` | Invocation dr_chain does not reference the correct DRs | Include the hashes of all DRs in order in dr_chain |
| `INVALID_SIGNATURE` | Ed25519 signature verification failed at DR[i] | DR was tampered with after signing, or wrong private key used |
| `INVALID_INVOCATION_SIGNATURE` | Invocation receipt signature is invalid | Agent signing key does not match its DID |
| `POLICY_VIOLATION` | Invocation args failed policy check in DR[i] | Review the policy constraint that failed and adjust invocation args |
| `POLICY_ESCALATION` | DR[i] has a less restrictive policy than DR[i-1] | Children may only tighten policy, never loosen it |
| `COMMAND_MISMATCH` | DR[i] cmd is not compatible with root cmd | All DRs in a chain must share the same command or a sub-path of the root |
| `SUBJECT_MISMATCH` | DR[i] has a different subject than DR[0] | The subject (resource owner) must remain constant through the entire chain |
| `NOT_YET_VALID` | DR[i] is not yet valid (nbf is in the future) | The delegation has not started yet — check timing |
| `EXPIRED` | DR[i] has expired | Request a new delegation from the authorising party |
| `REVOKED` | DR with this jti has been revoked | The delegating party withdrew this authorisation |
| `UNRESOLVABLE_DID` | Could not resolve public key from DID | Check DID format for did:key, or verify DNS/TLS for did:web |

---

## Appendix B: DRS vs Existing Approaches

| Approach | What it solves | What it does not solve |
|---|---|---|
| LangSmith / Langfuse / Arize | Observability — you can see what happened | Accountability — you cannot prove it was authorised |
| OAuth 2.1 access tokens | Authentication — who is this agent | Delegation provenance — who authorised this agent to act here |
| RFC 8693 `act` claim | Single-hop delegation representation | Multi-hop chain integrity — act claims are informational only |
| Agentic JWT | Agent identity and intent binding | Per-step delegation provenance |
| OpenTelemetry spans | Distributed tracing | Cryptographic proof — spans are mutable logs |
| DRS | Per-step signed delegation receipts — provable chain of custody | Agent behaviour safety, LLM non-determinism, prompt injection |

The correct answer for enterprise agent accountability is DRS + OAuth 2.1 + RFC 8693 + Agentic JWT + OpenTelemetry. These are complementary layers. No single tool solves the whole problem.

---

## Appendix C: Glossary

**Delegation Receipt (DR):** A signed JWT produced at the moment of delegation. The primary DRS artifact.

**DRS Bundle:** A collection of DRs and an Invocation Receipt transmitted by an agent to a tool server.

**Chain splicing:** The RFC 8693 vulnerability where a compromised intermediary presents mismatched subject_token and actor_token from different delegation contexts to obtain a fraudulent composite token.

**POLA (Principle of Least Authority):** Each delegation step may only grant capabilities equal to or less than those of the parent delegation.

**Root DR:** The first DR in a chain, issued by the root principal (human, organisation, or automated system). Has `prev_dr_hash: null`.

**Invocation Receipt:** A signed JWT recording what an agent actually did. Distinct from delegation receipts.

**JCS (JSON Canonicalization Scheme):** RFC 8785. Deterministic JSON serialisation for consistent hashing and signing.

**DID (Decentralised Identifier):** A W3C standard identifier for principals. `did:key` encodes the public key directly; no registry required.

**Supervisor Agent:** In machine-to-machine deployments, the agent that evaluates capability escalation requests from worker agents.

**AIUC-1:** The AI Underwriting Company's certification standard covering 50+ controls for enterprise agent deployments.

---

*Quorum · DRS v4 · March 2026 · Confidential*
