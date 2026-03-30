# DRS — Complete Technical Report
## Tools · Mathematics · Algorithms · User Interaction · Market Context

**Product:** Delegation Receipt Standard (DRS)  
**Organisation:** Quorum  
**Author:** Okey  
**Date:** March 2026  
**Status:** Primary Technical Reference — v4.0  

---

> Every claim in this document comes from research conducted during this build.
> Market statistics are cited with source and date. Library versions are verified
> against their registries. Mathematical definitions come from the primary RFCs.
> Where something is uncertain or unverified, it is labelled as such.
> Nothing is invented.

---

## Table of Contents

1. [The Problem This Solves — With Real Numbers](#1-the-problem-this-solves--with-real-numbers)
2. [What Already Exists and Why It Is Not Enough](#2-what-already-exists-and-why-it-is-not-enough)
3. [What DRS Is and Is Not](#3-what-drs-is-and-is-not)
4. [Mathematics and Cryptographic Primitives](#4-mathematics-and-cryptographic-primitives)
5. [The DRS Data Model](#5-the-drs-data-model)
6. [Algorithms — Step by Step](#6-algorithms--step-by-step)
7. [User Interaction — All Five Actors](#7-user-interaction--all-five-actors)
8. [End-to-End Trace — One Complete Tool Call](#8-end-to-end-trace--one-complete-tool-call)
9. [Verified Tool Stack](#9-verified-tool-stack)
10. [False Positives from Earlier Versions — Corrected](#10-false-positives-from-earlier-versions--corrected)
11. [Security Model](#11-security-model)
12. [Storage Architecture](#12-storage-architecture)
13. [Regulatory Alignment](#13-regulatory-alignment)
14. [Market Timing and Revenue Honesty](#14-market-timing-and-revenue-honesty)
15. [Implementation Roadmap](#15-implementation-roadmap)
16. [What DRS Does Not Solve](#16-what-drs-does-not-solve)

---

## 1. The Problem This Solves — With Real Numbers

This section uses only numbers from named, dated sources. No estimates.

### 1.1 The Deployment Reality

Enterprise AI agent deployment has reached a threshold where the accountability
gap is no longer theoretical. These are the numbers as of Q1 2026:

- **75%** of C-suite leaders at $1B+ organisations rank security, compliance,
  and auditability as their top requirement for agent deployment
  *(KPMG Q4 2025 AI Quarterly Pulse Survey)*
- **79%** of enterprises operate with blindspots where agents invoke tools,
  touch data, or trigger actions that security teams cannot observe
  *(Akto, State of Agentic AI Security 2026)*
- **45.6%** of technical teams rely on shared API keys for agent-to-agent
  authentication — when agents share credentials, attribution is impossible
  *(Akto 2026)*
- Only **21.9%** of teams treat AI agents as independent, identity-bearing
  entities with their own access scopes and audit trails *(Akto 2026)*
- **88%** of organisations reported confirmed or suspected AI agent security
  incidents in the last year. In healthcare, that number is **92.7%**
  *(Akto 2026)*
- **82%** of executives report confidence that their existing policies protect
  against unauthorised agent actions. But only **14.4%** of organisations
  send agents to production with full security or IT approval *(AGAT/Pragatix 2026)*
- Only **17%** of enterprises continuously monitor agent-to-agent interactions
  *(Akto 2026)*

The Stanford Trustworthy AI Research Lab found that model-level guardrails alone
are insufficient: fine-tuning attacks bypassed Claude Haiku in **72%** of cases
and GPT-4o in **57%**. Model-layer safety does not extend to the execution layer.

IBM's analysis of enterprise agent deployments identifies four structural failures:
over-privilege without visibility, invisible delegation where agents reuse human
tokens, zero enforcement at runtime, and no accountability after incidents.

### 1.2 The Specific Technical Failure

RFC 8693 (OAuth 2.0 Token Exchange) is the current IETF standard for representing
delegation chains in OAuth. It defines the `act` (actor) claim for multi-hop
delegation — when Agent A acts on behalf of User B, the `act` claim records this.

Section 4.1 of RFC 8693 explicitly states that nested `act` claims are
**"informational only"** for access control. The `may_act` claim (Section 4.4)
is optional — there is no normative requirement that tokens carry it or that the
Security Token Service (STS) enforce it. There is no mechanism to verify that the
`subject_token` and `actor_token` presented to an STS belong to the same
delegation flow.

This creates the **delegation chain splicing** vulnerability: a compromised
intermediary can present a legitimate user's `subject_token` alongside an
unrelated `actor_token` from a different context. The STS validates each
independently, finds both valid, and issues a new properly-signed composite token
asserting a delegation chain that never actually occurred.

**This is not theoretical.** CVE-2025-55241 (Microsoft Entra ID, patched July 2025)
is a real-world exploitation of this class of vulnerability. The IETF OAuth
Working Group has an open thread discussing it
(mail-archive.com/oauth@ietf.org/msg25680.html). That thread identifies three
suggested mitigations. The third is:

> *"Per-step delegation receipts: Each STS that performs a token exchange includes
> a signed attestation of the delegation step, providing independently-verifiable
> provenance."*

**DRS is that third mitigation, built as an implementable open standard.**

---

## 2. What Already Exists and Why It Is Not Enough

### 2.1 The Observability Layer — What It Solves

Twenty or more observability tools exist as of Q1 2026:

| Tool | Status | What it solves |
|---|---|---|
| Langfuse | Acquired by ClickHouse, January 2026. Serves 19 Fortune 50 companies, 26M+ monthly SDK installs | LLM tracing, evaluation, prompt management |
| Arize AI | $70M Series C | ML observability, model performance monitoring |
| Datadog AI Agent Monitoring | GA 2025 | Interactive graphs mapping agent decision paths |
| LangSmith | Generally available | LangChain-native tracing, evaluation |
| W&B Weave | GA 2025 | Experiment tracking, agent evaluation |
| Patronus AI | Funded | Automated LLM evaluation |
| AgentOps | Active | Agent session replay, monitoring |

Every tool in this list solves the same category of problem: **observability**.
They can tell you what happened. None of them can prove what happened.

**Logs can be altered.** An observability tool records events. Those records live
in a database controlled by the organisation under investigation. An auditor
reviewing those logs must trust the deploying organisation. DRS receipts are
cryptographically signed — an auditor can verify them without contacting anyone.

### 2.2 The Execution Layer — What It Solves

A second category of tools operates at the execution layer:

**Pragatix by AGAT Software** (March 2026): Continuous discovery of every AI
agent and MCP server connection, runtime enforcement at the tool invocation layer
before execution, behavioural monitoring across the agent fleet, audit trails
attributing every agent action to a specific identity and policy decision. Supports
on-premise deployment. This is the closest thing to DRS currently in the market,
but it is a proprietary platform, not an open standard. It cannot provide
independently verifiable receipts that an auditor can check without Pragatix access.

**Cisco AI Defense** (expanded February 2026): Runtime protections at the
execution layer for agent tool invocations. No public specification for
delegation chain verification.

**Oasis Security, Coder, Reco**: Building agent governance solutions targeting
the Cursor/coding-agent problem specifically — security teams blocking AI coding
tools because local execution is ungovernable.

### 2.3 The Authorization Layer — What It Attempts

**Auth0 Token Vault** (Okta, active): Implements RFC 8693 On-Behalf-Of (OBO)
flows. An agent can exchange a user's token for a scoped downstream token. Records
the `act` claim in composite JWTs. This is the closest OAuth-native approach to
delegation chain representation. It still has the chain splicing vulnerability —
`act` claims remain informational only.

**ARIA framework** (described in ISACA, January 2026): A proposed graph-native
delegation model making delegations "first-class, observable objects" with dual
enforcement (synchronous constraints + asynchronous audit obligations). Integrates
OAuth Rich Authorization Requests, RFC 8693 token exchange, and OpenID AuthZEN.
This is an emerging framework specification, not a shipping product. DRS and ARIA
address the same gap from different angles — ARIA is graph-native and policy-rich;
DRS is receipt-based and independently verifiable.

**Agentic JWT** (IETF draft-goswami-agentic-jwt-00, December 2025): Active IETF
draft proposing three mechanisms: (1) agent checksums — SHA-256 hash of the
agent's system prompt + available tools + model configuration, (2) intent tokens —
JWTs binding user-authorised intent to a specific workflow, (3) workflow binding —
linking execution to declared intent to detect deviation. This solves the
**intent-execution separation problem** (the gap between what the user authorised
and what the agent actually did). DRS and Agentic JWT are **complementary, not
competing**: Agentic JWT handles identity and intent; DRS handles per-step
delegation provenance.

### 2.4 The Gap That Remains

After mapping everything that exists, one specific capability remains absent
across all tools:

**Cross-organisational, independently verifiable, per-step delegation provenance
that does not require trusting the deploying organisation.**

This is what DRS provides. The correct enterprise accountability stack is:

```
DRS                  — per-step delegation provenance (who authorised what)
+ Agentic JWT        — agent identity + intent binding (is this agent what it claims)
+ OAuth 2.1 + MCP    — authentication and tool access (who is this, what can they call)
+ OpenTelemetry      — distributed tracing (what happened, when, in what order)
```

No single layer replaces another. All four are needed.

---

## 3. What DRS Is and Is Not

### 3.1 One Sentence

DRS adds a cryptographically signed receipt to every step of an OAuth delegation
chain, so any party — regulator, auditor, tool server — can independently verify
the complete provenance of any agent action without contacting a central authority.

### 3.2 DRS Is

- A **per-step delegation receipt** standard built on top of OAuth 2.1 + RFC 8693 + MCP
- The "per-step delegation receipts" mitigation named in the IETF OAuth WG thread on chain splicing
- An open standard. Not a proprietary platform.
- A JWT-based format that works natively in the OAuth/MCP ecosystem
- The layer that turns "we can see what happened" into "we can prove what happened"

### 3.3 DRS Is Not

- Not a replacement for OAuth 2.1 (extends it)
- Not a replacement for MCP (adds accountability to it)
- Not an observability tool (Langfuse/Arize do that)
- Not UCAN (uses JWTs and OAuth, not CBOR/IPLD capability tokens)
- Not a blockchain product (blockchain anchoring is an optional Tier 4 choice for specific regulated customers, never a requirement or default)
- Not Agentic JWT (complementary — different layer, different problem)
- Not a replacement for OpenTelemetry (tracing and receipts are different things)

---

## 4. Mathematics and Cryptographic Primitives

### 4.1 Ed25519 — Elliptic Curve Digital Signatures

DRS uses Ed25519 for all signing. Every Delegation Receipt and every Invocation
Receipt is signed with Ed25519. The mathematics below come directly from
RFC 8032 (Edwards-Curve Digital Signature Algorithm, January 2017).

#### 4.1.1 The Curve

Ed25519 operates on the **twisted Edwards curve edwards25519**, defined over the
finite field GF(p).

**Field prime p:**
```
p = 2^255 − 19
  = 57896044618658097711785492504343953926634992332820282019728792003956564819949
```
This prime was chosen because 2^255 − 19 admits fast modular arithmetic on
64-bit processors (the "25519" in the name refers to the exponent 255 and
the subtracted value 19).

**Curve equation** (twisted Edwards form):
```
−x² + y² = 1 + d·x²·y²   over GF(p)
```

The coefficient a = −1 is the twist. This makes it a **twisted** Edwards curve.

**Curve constant d:**
```
d = −121665 · (121666)^(−1)  mod p
  = 37095705934669439343138083508754565189542113879843219016388785533085940283555
```

**Group order L** — the number of points in the prime-order subgroup generated
by base point B:
```
L = 2^252 + 27742317777372353535851937790883648493
  = 7237005577332262213973186563042994240857116359379907606001950938285454250989
```

This value L is verified in RFC 8032 §5.1.1 and confirmed against the code
in the reference Python implementation (function `sha512_modq` uses `q = L`).

**Cofactor h = 8.** The full curve has `8·L` points. The cofactor means there
are small subgroups of orders 1, 2, 4, and 8. This is why verification multiplies
by 8 — to project onto the prime-order subgroup and avoid small-subgroup attacks.

**Public key size:** 32 bytes  
**Signature size:** 64 bytes  
**Security level:** approximately 128 bits against classical computers

#### 4.1.2 Key Generation

A private key is a 32-byte random seed. The signing scalar is derived from it:

```
1. Compute h = SHA-512(seed)                         [h is 64 bytes]
   Split h into (h_low = h[0:32], h_high = h[32:64])

2. Clamp h_low to produce scalar a:
   h_low[0]  &= 0b11111000    (clear lowest 3 bits — cofactor clearing)
   h_low[31] &= 0b01111111    (clear highest bit)
   h_low[31] |= 0b01000000    (set second-highest bit)
   a = decode_little_endian(h_low)    [a is now a 255-bit scalar]

3. Nonce prefix b = h_high               [32 bytes, kept secret]

4. Public key A = a · B                  [scalar multiplication on edwards25519]
   Encode A as 32 bytes:
     Store y-coordinate in little-endian (255 bits)
     Set bit 255 = least significant bit of x-coordinate
```

The clamping in step 2 ensures a is always in a safe range regardless of the
random seed input, preventing certain implementation attacks.

#### 4.1.3 Signing

**Input:** Message M, private key seed  
**Output:** Signature σ = (R_encoded ∥ S_encoded), 64 bytes

```
1. Re-derive (a, b) from seed as above.

2. Compute deterministic nonce r:
   r = SHA-512(b ∥ M)           [b is the secret prefix]
   r = decode_little_endian(r) mod L    [reduce to scalar]
   
   WHY DETERMINISTIC: Using (b ∥ M) instead of a random nonce means
   the same key and message always produce the same r. This eliminates
   catastrophic nonce reuse (which breaks ECDSA — see the Sony PS3 hack).

3. Compute commitment point R:
   R = r · B                    [point on edwards25519]
   Encode R as 32 bytes.

4. Compute challenge scalar k:
   k = SHA-512(encode(R) ∥ encode(A) ∥ M)
   k = decode_little_endian(k) mod L

5. Compute signature scalar S:
   S = (r + k · a) mod L        [Schnorr-style signature equation]
   Encode S as 32-byte little-endian integer.

6. σ = encode(R) ∥ encode(S)   [64 bytes total]
```

This is pure EdDSA as specified in RFC 8032 §5.1. SHA-512 is applied internally
by the algorithm — not by the caller. The signer does NOT pre-hash the message.

#### 4.1.4 Verification

**Input:** Message M, public key A (32 bytes), signature σ (64 bytes)  
**Output:** valid / invalid

```
1. Decode R from σ[0:32] → curve point.     If decoding fails: INVALID.
2. Decode A from public key → curve point.  If decoding fails: INVALID.
3. Decode S from σ[32:64] → integer.

4. CRITICAL CHECK: Verify S < L
   If S ≥ L: INVALID.
   
   WHY: The verification equation holds modulo L. This means (R, S) and
   (R, S+L) both satisfy it — two valid signatures for the same message.
   Enforcing S < L gives exactly one valid signature per (message, key)
   pair, preventing signature malleability.
   
   IMPORTANT: In ed25519-dalek 2.x, S < L is enforced by ALL verify_*()
   methods, not just verify_strict(). The distinction of verify_strict()
   is that it ADDITIONALLY: (a) rejects weak/low-order public keys via
   is_weak(), and (b) uses the cofactored equation below instead of the
   non-cofactored equation. Use verify_strict() for DRS.

5. Compute challenge k:
   k = SHA-512(encode(R) ∥ encode(A) ∥ M) mod L

6. Cofactored verification equation (RFC 8032 §5.1.7):
   [8][S]B  =?=  [8]R + [8][k]A
   
   Left side:  scalar multiply B by S, then multiply result by 8
   Right side: multiply R by 8, multiply A by (8k mod L), add them
   
   If the two points are equal: VALID. Otherwise: INVALID.
   
   WHY MULTIPLY BY 8: The cofactor h=8 means there are small subgroups
   of orders 1, 2, 4, and 8. Multiplying by 8 projects all points onto
   the prime-order subgroup of order L, where the equation holds iff
   the signature is genuinely valid. Without cofactor multiplication,
   an adversary could craft a signature using a point from a small
   subgroup that passes verification while not being a valid Schnorr
   signature over the message.
```

#### 4.1.5 Why Ed25519 for DRS

Ed25519 was chosen over ECDSA (secp256k1, P-256) for three specific reasons
relevant to DRS:

**1. Deterministic signatures.** Ed25519's deterministic nonce means the same
DR signed twice produces identical bytes. This is essential for DRS because
`prev_dr_hash = SHA-256(dr_bytes)`. If signing were non-deterministic, the
same DR could produce different hashes on different machines, making the hash
chain unreliable.

**2. Complete addition formulas.** The twisted Edwards curve has complete
addition formulas — no exceptional cases. This eliminates an entire class of
implementation bugs where exceptional points cause wrong results.

**3. 64-byte signatures.** Compact signatures keep DRS bundle sizes small.
A bundle with 3 DRs and an invocation receipt adds approximately 300 bytes
of signature data — negligible overhead.

---

### 4.2 SHA-256 — Content Addressing and Hash Chaining

**Standard:** NIST FIPS 180-4 (Secure Hash Standard, 2015)

SHA-256 produces a 32-byte (256-bit) digest from arbitrary input. DRS uses
it for two purposes:

**1. Hash chain linking (prev_dr_hash):** Each DR includes the SHA-256 of
the previous DR's JWT bytes. This creates a tamper-evident chain — modify
any DR and its SHA-256 changes, breaking every subsequent DR's `prev_dr_hash`.

**2. Content addressing (dr_chain in Invocation Receipts):** The invocation
receipt lists SHA-256 hashes of all DRs in the chain. Tool servers can verify
the chain by resolving each hash from the DR store.

**Why SHA-256 and not SHA-3:** SHA-256 is universally available in all
runtime environments, hardware-accelerated via SHA-NI instructions on x86
and ARMv8, and is what OAuth/JWT infrastructure already uses. SHA-3 offers
no security advantage here — SHA-256 provides 128-bit collision resistance,
which is sufficient given that a DRS chain is verified within its own trust
boundary, not across adversarial hash collisions.

**Hash chain tamper-evidence — the formal property:**

Let DR₀, DR₁, ..., DRₙ be a sequence of Delegation Receipts.

```
DR₀.prev_dr_hash = null

For i ≥ 1:
  DRᵢ.prev_dr_hash = SHA-256(UTF-8 bytes of DRᵢ₋₁ JWT string)
```

**Claim:** If any byte of DRᵢ changes after DRᵢ₊₁ is issued, the chain
breaks at position i+1.

**Proof sketch:** SHA-256 is collision-resistant. A one-bit change in DRᵢ
produces a completely different SHA-256 output with overwhelming probability
(2⁻¹²⁸ collision probability). Therefore SHA-256(DRᵢ_modified) ≠ SHA-256(DRᵢ_original)
= DRᵢ₊₁.prev_dr_hash. The chain verification algorithm (Block B, step B3)
detects this and returns CHAIN_BREAK.

---

### 4.3 RFC 8785 — JSON Canonicalization Scheme (JCS)

**Standard:** RFC 8785, August 2020 (IETF)

Ed25519 signs bytes, not abstract data structures. JSON has multiple valid
byte representations of the same logical object:

```json
{"z":1,"a":2}      ≠ bytes   {"a":2,"z":1}
{"cost": 5.0}      ≠ bytes   {"cost": 5}   (in some implementations)
{"name": "x"}      ≠ bytes   { "name" : "x" }
```

Without a canonical form, two correct implementations of the same DR would
produce different bytes, different SHA-256 hashes, and signatures that fail
each other's verification. JCS solves this.

**JCS rules (RFC 8785 §3.2):**

1. **Object key ordering:** Keys sorted in ascending Unicode code point order
   of their UTF-16 encoding. For ASCII-only keys, this is simple lexicographic
   order. Example:
   ```
   {"z":1,"a":2,"m":3}  →  {"a":2,"m":3,"z":1}
   ```

2. **Number encoding:** Integers: standard decimal, no leading zeros, no
   trailing dot. Floating point: IEEE 754 double precision in shortest form
   that round-trips. NaN and Infinity are not valid JSON and are not addressed.

3. **String encoding:** Standard JSON with `\uXXXX` escaping for non-ASCII
   where required.

4. **No whitespace:** No spaces after `:` or `,`. No indentation.

5. **Recursive:** Rules apply to all nested objects and arrays at every depth.

**The result:** Given any JSON object, JCS produces exactly one byte sequence.
Two parties that implement JCS correctly produce identical bytes for the same
logical document. This is what makes Ed25519 signatures over JSON reproducible.

**How JCS is used in DRS:**
```
Issuance:
  1. Build DR payload as JSON object (any ordering, any whitespace)
  2. Apply JCS → canonical_bytes (deterministic)
  3. base64url(canonical_bytes) → JWT payload component
  4. Ed25519Sign(private_key, ASCII("header.payload")) → signature

Verification:
  1. Extract JWT payload → base64url_decode → canonical_bytes
  2. Reconstruct signing input: ASCII("header") + "." + JWT_payload_component
  3. Ed25519Verify(public_key, signing_input, signature)
```

Note: The Ed25519 signature in JWT format is computed over
`ASCII(base64url(header)) ∥ "." ∥ ASCII(base64url(payload))`,
not over the raw JSON bytes directly. This is the JWT standard (RFC 7515 §7.2.1).

---

### 4.4 The DRS Hash Chain — Properties

The hash chain is a DRS-specific construction built on top of SHA-256 and Ed25519.
It is not an existing standard; it is defined here.

**Visual representation:**

```
DR₀ (root)
  sig₀  = Ed25519Sign(human_key, JWT_input₀)
  hash₀ = SHA-256(JWT₀_bytes)
  prev_dr_hash = null
       │
       │  hash₀ stored in DR₁.prev_dr_hash
       ▼
DR₁ (sub-delegation)
  sig₁  = Ed25519Sign(agent1_key, JWT_input₁)
  hash₁ = SHA-256(JWT₁_bytes)
  prev_dr_hash = hash₀
       │
       │  hash₁ stored in DR₂.prev_dr_hash
       ▼
DR₂ (leaf)
  sig₂  = Ed25519Sign(agent2_key, JWT_input₂)
  hash₂ = SHA-256(JWT₂_bytes)
  prev_dr_hash = hash₁
       │
       ▼
Invocation Receipt
  dr_chain = [hash₀, hash₁, hash₂]
  sig_inv  = Ed25519Sign(agent2_key, JWT_input_inv)
```

**Properties:**
- **Linear, not a tree.** Correct for agent delegation chains which are always
  a sequence: Human → Agent₁ → Agent₂ → Tool.
- **Forward-only.** DR₀ does not know about DR₁ at the time of creation.
  New sub-delegations can be created without modifying existing DRs.
- **Insertion-resistant.** Inserting a fake DRᵢ between DRᵢ₋₁ and DRᵢ would
  change hash(DRᵢ₋₁), breaking DRᵢ.prev_dr_hash.
- **Independently verifiable.** A verifier with only the JWT strings can
  recompute every hash and verify every signature. No trusted third party needed.

---

## 5. The DRS Data Model

### 5.1 Delegation Receipt (DR)

A DR is a signed JWT. It is produced at the moment of delegation.
It is separate from the OAuth access token.

```
The OAuth access token proves: identity + scope (who this agent is and what
                                it can call in OAuth terms)
The DRS Delegation Receipt proves: provenance (who authorised this agent,
                                   under what constraints, with what consent)
```

**JWT header:**
```json
{"typ": "JWT", "alg": "EdDSA"}
```

**JWT payload (root DR — human-rooted):**
```json
{
  "iss": "did:key:z6MkHuman...",
  "sub": "did:key:z6MkHuman...",
  "aud": "did:key:z6MkAgent...",

  "drs_v": "4.0",
  "drs_type": "delegation-receipt",

  "cmd": "/mcp/tools/call",

  "policy": {
    "max_cost_usd": 50.00,
    "pii_access": false,
    "allowed_tools": ["web_search", "write_file"],
    "max_calls": 100,
    "write_access": false
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
  },

  "drs_status_list_index": 42
}
```

**Field semantics:**

`iss` — Issuer. The DID of the party granting this delegation.

`sub` — Subject. The resource owner. In a human-rooted chain, this is always
the human's DID, propagated unchanged through every hop. It never changes.

`aud` — Audience. The DID of the party receiving this delegation (the agent
or tool being authorised).

`drs_v` — DRS spec version. Enables forward compatibility.

`drs_type` — Must be `"delegation-receipt"` for DRs, `"invocation-receipt"`
for invocation receipts.

`cmd` — The command being delegated. Uses MCP command path format
(`/mcp/tools/call`, `/mcp/resources/read`, etc.).

`policy` — Constraints. A child DR may only have a policy that is equal or
more restrictive than its parent. POLA (Principle of Least Authority).

`jti` — Unique identifier for this DR. Used for revocation lookup.

`prev_dr_hash` — SHA-256 of the previous DR's complete JWT bytes. Null for
root. Creates the tamper-evident chain.

`drs_consent` — Human consent evidence. Required when `drs_root_type == "human"`.
The `policy_hash` is SHA-256 of the **human-readable translated text** shown
to the user — not the raw JSON policy. This allows an auditor to verify that
the user saw legible information, not machine syntax.

`drs_root_type` — `"human"`, `"organisation"`, or `"automated-system"`.
Determines trust model and escalation path.

`drs_regulatory` — Determines mandatory storage tier and retention period.

`drs_status_list_index` — Position in the Bitstring Status List for revocation.

### 5.2 Sub-Delegation Receipt

```json
{
  "iss": "did:key:z6MkAgent1...",
  "sub": "did:key:z6MkHuman...",
  "aud": "did:key:z6MkToolServer...",

  "drs_v": "4.0",
  "drs_type": "delegation-receipt",

  "cmd": "/mcp/tools/call",

  "policy": {
    "max_cost_usd": 2.00,
    "pii_access": false,
    "allowed_tools": ["web_search"],
    "write_access": false
  },

  "nbf": 1743000060,
  "exp": 1743000960,
  "iat": 1743000060,
  "jti": "dr:9g4b3c2d-...",

  "prev_dr_hash": "sha256:abc123def456...",
  "drs_status_list_index": 43
}
```

Differences from root DR: cost limit reduced from $50 to $2 (POLA),
allowed tools narrowed to one, expiry shortened to 15 minutes,
`prev_dr_hash` populated, no `drs_consent` (only root DR has consent evidence).

### 5.3 Invocation Receipt

Records what was actually done (not what was authorised — that is the DR).

```json
{
  "iss": "did:key:z6MkAgent1...",
  "sub": "did:key:z6MkHuman...",

  "drs_v": "4.0",
  "drs_type": "invocation-receipt",

  "cmd": "/mcp/tools/call",
  "args": {
    "tool": "web_search",
    "query": "EU AI Act agent accountability requirements 2026",
    "estimated_cost_usd": 0.02,
    "pii_access": false
  },

  "dr_chain": [
    "sha256:abc123...",
    "sha256:def456..."
  ],

  "tool_server": "did:key:z6MkToolServer...",
  "iat": 1743000300,
  "jti": "inv:7h5c4d3e-...",

  "result_hash": "sha256:ghi789...",
  "policy_evaluation": "pass"
}
```

`dr_chain` contains the SHA-256 hashes of all DRs, root first. The tool
server verifies the chain by resolving each hash and confirming structural
integrity, cryptographic validity, policy compliance, temporal validity,
and revocation status.

### 5.4 The DRS Bundle

What the agent sends to the tool server:

```json
{
  "bundle_version": "4.0",
  "invocation": "<invocation-receipt-jwt>",
  "receipts": [
    "<root-dr-jwt>",
    "<sub-delegation-dr-jwt>"
  ]
}
```

Transported in HTTP header: `X-DRS-Bundle: <base64url(JSON.stringify(bundle))>`

For STDIO transport (CLI-based agent runtimes with no HTTP layer): the bundle
is written to a well-known file path or passed via environment variable.
The MCP spec explicitly states STDIO transport should NOT follow HTTP
authorization specification and should retrieve credentials from the environment.

---

## 6. Algorithms — Step by Step

### 6.1 DR Issuance

```
ALGORITHM: issue_delegation_receipt

INPUTS:
  issuer_private_key   Ed25519 32-byte seed
  audience_did         DID string of the receiving party
  cmd                  Command path string e.g. "/mcp/tools/call"
  policy               JSON object of constraint fields
  ttl_seconds          Validity window
  parent_dr_jwt        JWT string of parent DR (null for root)
  consent_data         Consent evidence object (required if root + human)
  root_type            "human" | "organisation" | "automated-system"
  regulatory           Regulatory classification object (optional)

OUTPUTS:
  dr_jwt               Signed JWT string
  dr_hash              SHA-256 of dr_jwt bytes

STEPS:

Step 1 — Validate parent (if not root):
  1a. Decode parent_dr_jwt → verify Ed25519 signature
  1b. Confirm parent_dr.aud == issuer DID
      (you can only re-delegate what was delegated to you)
  1c. Check policy attenuation:
      run check_policy_attenuation(parent_dr.policy, policy)
      if violation: ABORT with POLICY_ESCALATION error
  1d. Confirm nbf >= parent_dr.nbf
  1e. Confirm exp <= parent_dr.exp (child cannot outlast parent)
  1f. prev_dr_hash = SHA-256(UTF-8 bytes of parent_dr_jwt)

Step 2 — Validate root (if root):
  2a. prev_dr_hash = null
  2b. If root_type == "human": require consent_data
  2c. Validate consent_data.policy_hash:
      Recompute SHA-256 of the translated policy text shown to user
      Must match consent_data.policy_hash

Step 3 — Build payload:
  {
    iss: issuer_did (derived from issuer_private_key),
    sub: parent_dr.sub (or issuer_did if root),
    aud: audience_did,
    drs_v: "4.0",
    drs_type: "delegation-receipt",
    cmd: cmd,
    policy: policy,
    nbf: unix_now(),
    exp: unix_now() + ttl_seconds,
    iat: unix_now(),
    jti: "dr:" + new_uuid_v4(),
    prev_dr_hash: (from step 1f or null),
    drs_consent: consent_data (if root + human, else omit),
    drs_root_type: root_type,
    drs_regulatory: regulatory,
    drs_status_list_index: allocate_from_status_list()
  }

Step 4 — Canonicalise:
  Apply RFC 8785 JCS to payload → canonical_bytes

Step 5 — Encode JWT:
  header_enc  = base64url({"typ":"JWT","alg":"EdDSA"})
  payload_enc = base64url(canonical_bytes)
  signing_input = ASCII(header_enc) || "." || ASCII(payload_enc)

Step 6 — Sign:
  sig_bytes = Ed25519Sign(issuer_private_key, signing_input)
  sig_enc   = base64url(sig_bytes)

Step 7 — Assemble:
  dr_jwt = header_enc + "." + payload_enc + "." + sig_enc

Step 8 — Hash:
  dr_hash = SHA-256(UTF-8 bytes of dr_jwt)

Step 9 — Store:
  dr_store.put(dr_hash, dr_jwt)
  determine_storage_tier(regulatory) → store accordingly

Return: (dr_jwt, dr_hash)
```

### 6.2 Chain Verification

```
ALGORITHM: verify_chain(bundle) → VerificationResult

Organised in labelled blocks. Each block can fail independently.
All blocks must pass for the result to be VALID.

━━━ BLOCK A — Completeness ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

A1. bundle.receipts.length > 0
    FAIL EMPTY_CHAIN

A2. bundle.invocation exists
    FAIL MISSING_INVOCATION

━━━ BLOCK B — Structural Integrity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

B1. For each DR at index i:
    Decode JWT. Confirm drs_type == "delegation-receipt". Confirm drs_v == "4.0".

B2. Root DR (index 0):
    Confirm prev_dr_hash == null.
    If drs_root_type == "human": confirm drs_consent is present.

B3. For each DR at index i ≥ 1:
    expected_hash = SHA-256(bundle.receipts[i-1])
    Confirm DRᵢ.prev_dr_hash == expected_hash
    FAIL CHAIN_BREAK [detailed message: which index, what was expected, what was found]

B4. For each DR at index i ≥ 1:
    Confirm DRᵢ.iss == DRᵢ₋₁.aud
    FAIL ISSUER_MISMATCH

B5. Confirm invocation.iss == receipts[last].aud
    FAIL INVOKER_MISMATCH

B6. Confirm invocation.dr_chain == [SHA-256(receipt₀), ..., SHA-256(receiptn)]
    FAIL CHAIN_REFERENCE_MISMATCH

━━━ BLOCK C — Cryptographic Validity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━

C1. For each DR:
    Resolve public key from DRᵢ.iss:
      did:key → decode directly from DID (no network)
      did:web → fetch /.well-known/did.json, cache with 1h TTL
    Reconstruct signing_input = header_enc + "." + payload_enc
    Ed25519Verify(public_key, signing_input, signature)
    FAIL INVALID_SIGNATURE

C2. For invocation:
    Ed25519Verify(invoker_public_key, signing_input, signature)
    FAIL INVALID_INVOCATION_SIGNATURE

━━━ BLOCK D — Semantic Validity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

D1. For every DR in the chain:
    evaluate_policy(DRᵢ.policy, invocation.args)
    ALL must pass (conjunctive evaluation).
    FAIL POLICY_VIOLATION [which constraint, what args were provided]

D2. For each DR at index i ≥ 1:
    check_policy_attenuation(DRᵢ₋₁.policy, DRᵢ.policy)
    FAIL POLICY_ESCALATION

D3. For each DR and the invocation:
    DRᵢ.cmd must equal DR₀.cmd or be a sub-path of DR₀.cmd.
    FAIL COMMAND_MISMATCH

D4. For each DR:
    DRᵢ.sub must equal DR₀.sub.
    FAIL SUBJECT_MISMATCH

━━━ BLOCK E — Temporal Validity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

now = unix_timestamp()

E1. For each DR:
    If nbf present: now ≥ DR.nbf     FAIL NOT_YET_VALID
    If exp not null: now ≤ DR.exp    FAIL EXPIRED

━━━ BLOCK F — Revocation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

F1. For each DR:
    Fetch Bitstring Status List (cache 5min TTL).
    Read bit at DR.drs_status_list_index.
    If bit == 1: FAIL REVOKED

━━━ RESULT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Return VerificationResult {
  valid: true,
  context: {
    root_principal: DR₀.iss,
    root_type:      DR₀.drs_root_type,
    consent_record: DR₀.drs_consent,
    regulatory:     DR₀.drs_regulatory,
    leaf_policy:    DRₙ.policy,
    chain_depth:    receipts.length,
    session_id:     DR₀.drs_consent?.session_id
  }
}
```

### 6.3 Policy Evaluation

```
ALGORITHM: evaluate_policy(policy, args) → PolicyResult

For each field in policy:

  "max_cost_usd": N
    CHECK: args.estimated_cost_usd <= N
    FAIL: "Cost limit exceeded. Max: $N. Provided: $X."

  "pii_access": false
    CHECK: args.pii_access == false  (or field absent from args)
    FAIL: "PII access not permitted by this delegation."

  "allowed_tools": [list]
    CHECK: args.tool ∈ list  (if args.tool present)
    FAIL: "Tool not permitted. Allowed: [list]. Requested: X."

  "max_calls": N
    CHECK: session_call_count <= N  (requires session state lookup)
    FAIL: "Call limit reached. Max: N. Current: C."

  "write_access": false
    CHECK: args.write_access == false  (or absent)
    FAIL: "Write access not permitted."

  "allowed_resources": [glob_patterns]
    CHECK: args.resource_uri matches at least one pattern
    FAIL: "Resource not permitted."

  "allowed_data_classes": [list]
    CHECK: args.data_class ∈ list  (if present)
    FAIL: "Data class not permitted."

Unknown fields: log and continue (forward compatibility).

If all checks pass: return { pass: true }
```

### 6.4 Policy Attenuation Check

```
ALGORITHM: check_policy_attenuation(parent, child) → AttenuationResult

For each numeric upper bound in parent:
  If same field in child: child[field] <= parent[field]
  VIOLATION: "Child loosens upper bound for [field]."

For each allowlist field in parent:
  If same field in child: child[field] ⊆ parent[field]
  VIOLATION: "Child adds [extra] to allowlist [field] not permitted by parent."

For each boolean restriction (false) in parent:
  If same field in child and child[field] != false:
  VIOLATION: "Child relaxes restriction on [field]."

Fields in child not in parent: always valid (child is adding more restrictions).

Return { valid: true } if no violations.
```

---

## 7. User Interaction — All Five Actors

### 7.1 Actor 1: End User (Human granting authority)

**Who they are:** A person using an application powered by an AI agent.
They may be a finance professional, a researcher, an enterprise user.
They are not technical. They never see a DID, JWT, or SHA-256 hash.

**What they see:**

The DRS Consent Translator converts the machine policy into plain language
before showing it. The `policy_hash` in the DR is SHA-256 of this text —
not the raw JSON. An auditor can later verify the user saw legible information.

```
┌─────────────────────────────────────────────────────────────────┐
│  Research Agent wants permission to:                            │
│                                                                 │
│  ✓  Search the web                                              │
│  ✓  Save files to your workspace                                │
│  ✗  Cannot access personal data                                 │
│  ✗  Cannot spend more than £50.00                               │
│  ✗  Cannot modify existing files                                │
│                                                                 │
│  This permission lasts 30 days. Revoke it at any time.          │
│                                                                 │
│            [ Authorise ]          [ Cancel ]                    │
└─────────────────────────────────────────────────────────────────┘
```

**The consent click:**
1. Application records: method, timestamp, locale, session ID
2. Computes `policy_hash = SHA-256(UTF-8 bytes of the text shown above)`
3. Issues root DR signed with user's private key
4. Stores DR in DR store
5. Returns DR JWT to agent

**The activity feed** (what they see while agent is running):
```
┌─────────────────────────────────────────────────────────────────┐
│  Research Agent · Active                                        │
│  £0.04 used of £50.00 · 3 actions                              │
│                                                                 │
│  14:22  web_search: "EU AI Act agent audit requirements" £0.02  ✓  │
│  14:23  write_file: research/eu-ai-act-summary.md     free  ✓     │
│  14:25  web_search: "FINOS AI governance framework"   £0.02  ✓     │
│                                                                 │
│            [ Revoke ]       [ View full log ]                   │
└─────────────────────────────────────────────────────────────────┘
```

**Revoking:** Clicking Revoke sets the DR's bit in the Bitstring Status List
to 1. Propagates to all tool servers within 5 minutes (cache TTL). The agent's
next tool call returns error REVOKED.

**What the user never does:** understand JWTs, DIDs, hash chains, or OAuth flows.
DRS is invisible infrastructure. They interact only with plain language, a clear
consent moment, a clear feed, and a clear revoke button.

---

### 7.2 Actor 2: Developer (integrating DRS into a tool server)

**Who they are:** An engineer building an MCP server, an agent runtime, or any
system that receives requests from agents.

**Integration — Day 1, Hour 1:**
```typescript
npm install @drs/sdk

import { DRS } from '@drs/sdk';
const drs = new DRS();

// In your MCP tool handler:
async function handleToolCall(req: MCPRequest) {
  const bundle = parseDRSBundle(req.headers['x-drs-bundle']);
  const result = await drs.verify(bundle);

  if (!result.valid) {
    return {
      status: 403,
      error: {
        code:       result.error.code,
        message:    result.error.message,    // Full English sentence
        suggestion: result.error.suggestion  // What to do about it
      }
    };
  }

  // All checks passed. Tool handler now knows:
  // result.context.root_principal    — the human or org that authorised this
  // result.context.root_type         — "human" | "organisation" | "automated-system"
  // result.context.consent_record    — when and how consent was given
  // result.context.regulatory        — regulatory classification
  // result.context.leaf_policy       — constraints in effect for this call
  // result.context.chain_depth       — number of delegation hops

  return executeTool(req.body, result.context);
}
```

**Error messages — full sentences, not codes alone:**
```
ERROR CODE: CHAIN_BREAK

  DR at index 1 has prev_dr_hash: sha256:abc123...

  But computing SHA-256 of DR at index 0 produces: sha256:def456...

  These do not match. Either DR[0] was modified after DR[1] was issued,
  or the wrong DR is at position 0.

SUGGESTION: Rebuild the bundle from the original DR store.
  Ensure DRs are in root-first order (index 0 = root DR).
  Do not modify a parent DR after issuing children that reference it.
```

**CLI tools:**
```bash
# Verify a bundle step by step
drs verify bundle.json

# Check if invocation args pass a policy
drs policy check dr.json --args '{"tool":"web_search","estimated_cost_usd":3.00}'

# Translate DR policy to plain English
drs translate dr.json --locale en-GB

# Retrieve and display full chain for an invocation
drs audit retrieve --inv-jti "inv:7h5c4d3e-..."
```

---

### 7.3 Actor 3: Agent Runtime (operating autonomously)

**Who they are:** A software system acting on behalf of a human or organisation.
In machine-to-machine deployments (like internal pipelines or CLI-based runtimes),
no human is present.

**Startup sequence:**
```
1. Load operator config (drs_operator.json)
2. Check for existing standing delegation in DR store
   - If found and not expired/revoked: use it
   - If expired and auto_renew=true: renew via operator key
   - If not found: issue new root DR from operator key
3. Load DR into runtime context as authoritative policy
4. Begin task processing
```

**Before every tool call:**
```
1. Build proposed_args for the intended action
2. evaluate_policy(standing_dr.policy, proposed_args)
   - PASS: proceed to issue sub-delegation and invoke
   - FAIL: write capability request to escalation channel
           route to supervisor_agent (not a human)
           wait for supervisor response
           if denied: complete partial work, log blocked task
```

**Escalation when hitting a policy boundary:**
```
Agent writes to escalation channel:
{
  "type": "CAPABILITY_REQUEST",
  "requesting_agent": "did:key:z6MkAgent...",
  "supervisor": "did:key:z6MkSupervisor...",
  "missing_capability": "/email/send",
  "proposed_policy": { "allowed_tools": ["email_send"], ... },
  "reason": "Task requires sending research summary to team",
  "work_completed": "7 of 12 steps complete",
  "can_resume": true
}

Supervisor agent evaluates against operator config.
If approved: issues new sub-delegation DR → agent resumes.
If denied:   agent completes partial work, records blocked status.

Agent NEVER self-escalates past its policy.
Agent NEVER silently ignores a boundary.
Agent NEVER fails without a record.
```

**At delegation expiry (automated-system root):**
```
If auto_renew == true and renewal_count < max_renewal_count:
  Issue new root DR from operator key
  Continue working

If auto_renew == false or max renewal exceeded:
  Stop all new tool calls immediately
  Preserve work-in-progress state
  Write to activity log: DELEGATION_EXPIRED
  Send notification to configured channel
  Wait
```

---

### 7.4 Actor 4: Tool Server (verifying before executing)

**Who they are:** An MCP server or API endpoint that executes agent requests.
They must verify the delegation chain before trusting any request.

**The verification call:**
```typescript
// Minimal MCP middleware integration
import { drsMiddleware } from '@drs/mcp-middleware';

app.use(drsMiddleware({ mode: 'require' }));

// After middleware, handler has access to:
app.post('/mcp/tools/call', (req, ctx) => {
  // ctx.drs.root_principal  — trace back any incident to root authority
  // ctx.drs.root_type       — was a human in the loop?
  // ctx.drs.leaf_policy     — check max_cost_usd before calling paid APIs
  // ctx.drs.chain_depth     — flag unusually long chains for review

  if (ctx.drs.leaf_policy.max_cost_usd < estimated_api_cost) {
    return { error: 'BUDGET_EXCEEDED' };
  }

  return executeToolCall(req.body);
});
```

**Rate limiting by chain identity (not just agent DID):**
```typescript
// Rate limit by root_principal, not just by iss (the leaf agent)
// This prevents a compromised agent from spinning up sub-agents
// to bypass per-agent rate limits

const key = `ratelimit:${ctx.drs.root_principal}:${toolName}`;
const count = await redis.incr(key);
await redis.expire(key, 3600);  // 1 hour window

if (count > HOURLY_LIMIT_PER_ROOT) {
  return { error: 'RATE_LIMIT_EXCEEDED_FOR_ROOT_PRINCIPAL' };
}
```

---

### 7.5 Actor 5: Auditor (reconstructing what happened)

**Who they are:** Internal audit, external regulator, legal counsel, or compliance
engineer. They may receive a case reference, an incident report, or a specific
invocation JTI. They need complete, independently verifiable evidence.

**Retrieval and verification:**
```bash
# Retrieve chain evidence for an invocation
drs audit retrieve --inv-jti "inv:7h5c4d3e-..." --output evidence.json

# Verify independently (no Quorum account needed)
drs verify evidence.json

Output:
──────────────────────────────────────────────────────────────────
DRS Chain Verification Report
Generated: 2026-03-28T17:30:00Z
Invocation: inv:7h5c4d3e-6f7a-8b9c-0d1e-2f3a4b5c6d7e

[DR-0] Root Delegation — dr:8f3a2b1c-...
  Issued by:  Human principal  did:key:z6MkH...
  Issued to:  Research Agent   did:key:z6MkA...
  Issued at:  2026-03-28T10:30:00Z
  Expires:    2026-04-27T10:30:00Z
  Consent:    explicit-ui-click  ·  en-GB  ·  sess:8f3a2b1c
  Policy:     max_cost=£50  pii=false  tools=[web_search,write_file]
  Signature:  VALID ✓
  Revoked:    No   ✓
  Chain hash: sha256:abc123... → verified by DR-1.prev_dr_hash ✓

[DR-1] Sub-Delegation — dr:9g4b3c2d-...
  Issued by:  Research Agent   did:key:z6MkA...
  Issued to:  Web Search Tool  did:key:z6MkT...
  Issued at:  2026-03-28T14:22:00Z
  Expires:    2026-03-28T14:37:00Z  (15-minute TTL)
  Policy:     max_cost=£2  pii=false  tools=[web_search]
  Attenuation: child policy ⊆ parent policy ✓
  Signature:  VALID ✓
  Revoked:    No   ✓

[Invocation] — inv:7h5c4d3e-...
  Invoker:   Research Agent  did:key:z6MkA...
  Subject:   Human           did:key:z6MkH...
  Tool:      web_search
  Query:     "EU AI Act agent accountability requirements 2026"
  Cost:      £0.02
  Policy:    PASS ✓
  Signature: VALID ✓
  Chain:     all hashes verified ✓

RESULT: CHAIN FULLY VERIFIED
Human consent confirmed:  2026-03-28T10:30:00Z  explicit-ui-click
Chain depth: 2 hops  (Human → Agent → Tool)
──────────────────────────────────────────────────────────────────

# Export as compliance evidence package
drs audit export --inv-jti "inv:7h5c4d3e-..." --format eu-ai-act
drs audit export --inv-jti "inv:7h5c4d3e-..." --format hipaa
```

**Key property:** The auditor does not need access to Quorum's systems, a Quorum
account, or cooperation from the deploying organisation. Public keys come from
DIDs. Every signature is independently verifiable. Every hash link is computable
from the data in the evidence bundle.

---

### 7.6 Actor 6: System Administrator (machine-to-machine setup)

**Who they are:** A DevOps engineer or platform architect deploying an internal
agent pipeline with no user-facing consent UI.

**Setup sequence:**
```bash
# Step 1: Generate operator keypair
drs keygen --output /secrets/operator_key.json
# Produces: { "did": "did:key:z6MkOrg...", "privateKey": "..." }

# Step 2: Write operator config
cat > drs_operator.json << EOF
{
  "drs_root_type": "automated-system",
  "operator_did": "did:key:z6MkOrg...",
  "operator_key_path": "/secrets/operator_key.json",
  "operator_key_management": "file",

  "standing_policy": {
    "max_cost_usd_per_session": 100.00,
    "pii_access": false,
    "allowed_tools": ["web_search", "write_file", "read_file"],
    "write_access": false,
    "allowed_external_apis": ["api.github.com"]
  },

  "renewal_rules": {
    "auto_renew": true,
    "session_ttl_hours": 8,
    "max_renewal_count": 10
  },

  "escalation": {
    "target_type": "supervisor_agent",
    "supervisor_did": "did:key:z6MkSupervisor...",
    "fallback": "log_and_stop"
  },

  "storage_tier": 2
}
EOF

# Step 3: Agent runtime reads config on startup, issues root DR
# All subsequent actions trace back to the operator DID
# Audit trails work. Revocation works. No human needed at runtime.
```

---

## 8. End-to-End Trace — One Complete Tool Call

Scenario: Human has granted Research Agent a 30-day delegation. Agent is
calling `web_search`. Full trace of every operation.

```
━━━ Step 1: Agent pre-checks its own policy ━━━━━━━━━━━━━━━━━━━━━

Agent loads root DR from DR store.

proposed_args = {
  tool: "web_search",
  estimated_cost_usd: 0.02,
  pii_access: false
}

evaluate_policy(root_dr.policy, proposed_args):
  max_cost_usd: 50.00 ≥ 0.02    → PASS
  pii_access:   false == false   → PASS
  allowed_tools: ["web_search",...] ∋ "web_search" → PASS

Agent proceeds.

━━━ Step 2: Agent issues sub-delegation ━━━━━━━━━━━━━━━━━━━━━━━━━

issue_delegation_receipt(
  issuer: agent_key,
  audience: tool_server_did,
  policy: { max_cost_usd: 2.00, pii_access: false, allowed_tools: ["web_search"] },
  ttl: 900,
  parent: root_dr_jwt
)

  Attenuation check: 2.00 ≤ 50.00 ✓, ["web_search"] ⊆ ["web_search","write_file"] ✓

  Build payload JSON.
  Apply JCS → canonical_bytes.

  Compute Ed25519 signature:
    h        = SHA-512(agent_seed)
    a, b     = clamp(h[0:32]), h[32:64]
    r        = SHA-512(b ∥ signing_input) mod L   [deterministic nonce]
    R        = r · B                               [curve point]
    k        = SHA-512(encode(R) ∥ encode(A) ∥ signing_input) mod L
    S        = (r + k·a) mod L
    σ        = encode(R) ∥ encode(S)               [64 bytes]

  JWT₁ = base64url(header) + "." + base64url(canonical_bytes) + "." + base64url(σ)
  hash₁ = SHA-256(UTF-8 bytes of JWT₁)
  dr_store.put(hash₁, JWT₁)

━━━ Step 3: Agent creates invocation receipt ━━━━━━━━━━━━━━━━━━━━━

invocation = {
  iss: agent_did,
  sub: human_did,
  drs_type: "invocation-receipt",
  cmd: "/mcp/tools/call",
  args: { tool: "web_search", query: "EU AI Act agent accountability requirements 2026",
          estimated_cost_usd: 0.02, pii_access: false },
  dr_chain: [hash₀, hash₁],
  tool_server: tool_server_did,
  jti: "inv:7h5c4d3e-...",
  iat: 1743000300
}

Apply JCS. Sign. Build JWT_inv.

━━━ Step 4: Agent transmits bundle ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

POST /mcp/tools/call HTTP/1.1
Authorization: Bearer <oauth_token>
X-DRS-Bundle: base64url({
  bundle_version: "4.0",
  invocation: JWT_inv,
  receipts: [JWT₀, JWT₁]
})
Content-Type: application/json

{"tool": "web_search", "query": "EU AI Act agent accountability requirements 2026"}

━━━ Step 5: Tool server runs verify_chain ━━━━━━━━━━━━━━━━━━━━━━━━

Block A: 2 receipts, invocation present ✓

Block B:
  DR₀.prev_dr_hash = null ✓
  SHA-256(JWT₀) = hash₀ == DR₁.prev_dr_hash ✓
  DR₁.iss = agent_did == DR₀.aud ✓
  inv.iss = agent_did == DR₁.aud ✓
  inv.dr_chain = [hash₀, hash₁] == computed chain ✓

Block C:
  DR₀ signature: resolve human_did → public key A₀
    k = SHA-512(R₀ ∥ A₀ ∥ signing_input₀) mod L
    [8][S₀]B =?= [8]R₀ + [8][k]A₀   ✓
  DR₁ signature: resolve agent_did → public key A₁
    [8][S₁]B =?= [8]R₁ + [8][k]A₁   ✓
  inv signature: [8][S_inv]B =?= [8]R_inv + [8][k]A₁   ✓

Block D:
  DR₀.policy vs inv.args:  50.00≥0.02, false==false, "web_search"∈list  ✓
  DR₁.policy vs inv.args:  2.00≥0.02,  false==false, "web_search"∈list  ✓
  Attenuation: 2.00≤50.00, ["web_search"]⊆[...]                          ✓
  cmd: all == "/mcp/tools/call"   ✓
  sub: all == human_did           ✓

Block E:
  now=1743000300. DR₀: [1743000000, 1745592000] ✓. DR₁: [1743000060, 1743000960] ✓

Block F:
  Bitstring at index 42: bit = 0  →  not revoked ✓
  Bitstring at index 43: bit = 0  →  not revoked ✓

RESULT: VALID

━━━ Step 6: Tool server executes and emits activity event ━━━━━━━━

Tool server calls web_search API.

Emits:
{
  type: "drs:tool-call",
  timestamp: "2026-03-28T14:25:00Z",
  root_principal: human_did,
  root_type: "human",
  inv_jti: "inv:7h5c4d3e-...",
  tool: "web_search",
  policy_result: "pass",
  chain_depth: 2
}

Activity feed updated. Human can see this action on their next login.
```

---

## 9. Verified Tool Stack

### 9.1 Rust (cryptographic core)

| Crate | Version | Registry | Role |
|---|---|---|---|
| `ed25519-dalek` | 2.2.0 | crates.io | Ed25519 sign and verify. RUSTSEC-2022-0093 patched in 2.0.0. Use `verify_strict()`. |
| `sha2` | 0.10.8 | crates.io | SHA-256 (hash chain, content addressing) and SHA-512 (used internally by Ed25519). |
| `jcs` | 0.1 | crates.io | RFC 8785 JCS canonicalisation. Deterministic JSON serialisation for signing. |
| `serde_json` | 1.0 | crates.io | JSON parse/serialise. Used alongside `jcs`. |
| `base64` | 0.22 | crates.io | base64url encoding for JWT components. |
| `wasm-bindgen` | 0.2.114 | crates.io | Compiles Rust crypto core to WASM for TypeScript SDK. |
| `cid` | 0.11.1 | crates.io | CID computation for optional Tier 4 Ethereum anchoring only. Not required for core DRS. |

**Note on `jsonwebtoken` in Rust:** The document lists it but `jsonwebtoken` crate
has limited EdDSA support. For DRS, sign and verify manually using ed25519-dalek
and base64url encoding per RFC 7515. Do not rely on the crate's EdDSA path.

### 9.2 Go (verification middleware)

| Module | Version | Import path | Role |
|---|---|---|---|
| `golang-jwt/jwt` | v5.2.1 | `github.com/golang-jwt/jwt/v5` | JWT parsing and claim extraction. |
| `golang.org/x/crypto` | v0.21.0 | stdlib | Ed25519 verify via `crypto/ed25519`. |
| `hashicorp/golang-lru` | v2.0.7 | `github.com/hashicorp/golang-lru/v2` | Bounded LRU cache for resolved DID public keys. |

SHA-256 via stdlib `crypto/sha256`. No external dependency.

### 9.3 TypeScript / npm (SDK, UI components)

| Package | Version | Role |
|---|---|---|
| `jose` | ^5.9.6 | JWT sign and verify with native EdDSA support. Use instead of `jsonwebtoken`. |
| `@noble/ed25519` | ^2.1.0 | Pure TypeScript Ed25519. Audited. For key generation and raw operations. |
| `did-resolver` | ^4.1.0 | DID document resolution. |
| `key-did-resolver` | ^3.1.0 | `did:key` resolution — decodes public key from DID string, no network. |
| `uint8arrays` | ^5.1.0 | Byte array utilities. |

---

## 10. False Positives from Earlier Versions — Corrected

Every item below was incorrect in DRS v1, v2, or v3. Corrections are verified
against primary sources.

| Error | What was claimed | What is correct | Source |
|---|---|---|---|
| `cid = "1.0"` | This Rust crate version exists | **Does not exist.** Latest is 0.11.1. `go get cid@1.0` will fail. | crates.io |
| `github.com/multiformats/go-cid` | Correct Go module path | **Wrong path.** Correct: `github.com/ipfs/go-cid`. Latest: v0.5.0 | pkg.go.dev |
| `policy_is_at_least_as_strict()` | Formal function in UCAN v1.0 | **Does not exist** in any UCAN spec. DRS v4 defines its own `check_policy_attenuation()`. | ucan-wg/spec |
| `libipld` + `libipld-cbor` | Correct Rust IPLD crates | **Deprecated March 2024.** Replacement: `serde_ipld_dagcbor 0.6.4`. But DRS v4 uses JSON + JCS, not CBOR at all. | crates.io |
| `serde_cbor` | Valid CBOR crate | **Archived and unmaintained** (RUSTSEC-2021-0127). Do not use. | rustsec.org |
| `verify_strict()` enforces S < L | Only `verify_strict()` checks S < L | **ALL `verify_*()` methods in ed25519-dalek 2.x enforce S < L.** `verify_strict()` additionally rejects weak public keys and uses cofactored verification. | docs.rs/ed25519-dalek |
| `prf` in UCAN delegation envelope | `prf` field is in the delegation | **Wrong.** In UCAN v1.0, delegations have no `prf` field. `prf` is in the **invocation payload** — an array of delegation CIDs. | ucan-wg/invocation |
| `libipld` is the CBOR library for DRS | `libipld` should be used | DRS v4 uses **JSON + JCS (RFC 8785)**, not CBOR. `libipld` is irrelevant to DRS v4. | — |
| UCAN `att` field | Still exists in v1.0 | **Removed.** v1.0 replaced `att[].with`, `att[].can`, `att[].nb` with `sub`, `cmd`, `pol` fields. | ucan-wg/delegation |
| `ed25519-dalek = "2.1"` | Latest version | **2.2.0** is the latest on crates.io as of Q1 2026. | crates.io |

---

## 11. Security Model

### 11.1 Threat Table

| Threat | Mechanism | DRS Mitigation | Residual Risk |
|---|---|---|---|
| Forged root DR | Attacker creates fake root delegation from scratch | Ed25519 EUF-CMA security: forgery requires solving discrete log on edwards25519 | Private key theft |
| **Chain splicing** (CVE-2025-55241 class) | Compromised agent presents `subject_token` and `actor_token` from different delegation contexts | `prev_dr_hash` chain: each DR cryptographically references its parent. A mismatched chain fails Block B. | Implementation bugs |
| Policy escalation | Child DR claims less restrictive policy than parent | `check_policy_attenuation()` at issuance + Block D at verification | Semantic policy edges (complex allowlists) |
| Policy violation at invocation | Agent passes args exceeding its policy | Block D evaluates all policies conjunctively against invocation args | Policy completeness (not all edge cases covered by policy fields) |
| DR tampering | Attacker modifies a signed DR after issuance | Ed25519 signature fails on modified content | None — structural |
| Chain injection | Attacker inserts a fake intermediate DR | `prev_dr_hash` chain — inserting a DR changes its hash, breaking all subsequent `prev_dr_hash` values | None — structural |
| Replay after revocation | Agent replays an expired-but-valid-signature DR | Block F: Bitstring Status List lookup. 5-minute cache window. | Stale cache: up to 5-minute window |
| JSON malleability | Two implementations produce different canonical bytes for same logical payload | RFC 8785 JCS enforced at both issuance and verification | Non-conforming JCS implementations |
| Signature malleability | `(R, S)` and `(R, S+L)` both verify for same message | ed25519-dalek 2.x enforces S < L in all `verify_*()` methods | None — library enforces |
| DID spoofing | Attacker uses a DID that looks like a legitimate issuer | `did:key` DIDs are derived from the public key — cannot be spoofed without the private key | `did:web` requires DNS/TLS trust |
| Prompt injection | Attacker embeds instructions in content the agent reads, causing it to invoke tools outside intended scope | DRS records every invocation with its DR chain (what was authorised). Does not prevent the injection. | Prompt injection is not a DRS problem — Agentic JWT addresses intent-execution separation |
| Model-level bypass | Fine-tuning or adversarial prompts bypass model safety | Stanford TrustAI Lab: 72% bypass rate against Claude Haiku, 57% against GPT-4o. Model safety ≠ execution safety. | Completely outside DRS scope |

### 11.2 Key Management

- **Human root keys:** HSM or Secure Enclave preferred. YubiKey minimum for individuals.
- **Operator keys (machine root):** HSM required for production deployments.
- **Agent keys:** Rotate per-session. Long-lived agent keys are prohibited. A compromised agent key should only expose that session's actions.
- **did:key** is the preferred DID method for agents — encodes the public key directly, requires no registry, no DNS, no network call to resolve.

---

## 12. Storage Architecture

### 12.1 Why the DR Store Is Not Optional

The chain verification algorithm resolves DRs by hash (`prev_dr_hash` and
`dr_chain`). Without a persistent store accessible to tool servers, verification
requires the agent to include all DRs in every request bundle. Both approaches
are supported. The bundle approach (include all DRs) works without a shared store.
The hash-resolution approach (tool server resolves from store) scales better for
large chains.

### 12.2 Why Blockchain Was Removed as a DRS Requirement

Earlier versions of this architecture included Monad as a "Tier 4" on-chain
anchor for delegation receipts. That decision was wrong for three specific reasons.

**First, it imposes cost on users.** Monad requires gas fees paid in MON tokens.
Every DR anchored on-chain means the deploying organisation pays a transaction
fee. For an accountability standard used by enterprises, a per-action cost
denominated in a cryptocurrency token is a blocker, not a feature.

**Second, Monad is too new for regulated contexts.** Monad mainnet launched
November 24, 2025. As of March 2026, it has approximately 200 validators and
very low on-chain activity. A regulator reviewing DRS evidence backed by a
Monad timestamp would ask: "What is Monad?" That is a question you do not want
to answer in a compliance hearing.

**Third, there is a 20-year-old IETF standard that solves the same problem
better.** The only thing blockchain was solving in DRS was: "produce a timestamp
that neither party controls, so a regulator cannot argue it was fabricated."
RFC 3161 (Internet X.509 PKI Time-Stamp Protocol, IETF 2001) solves exactly
this, is legally recognised under EU eIDAS and in US federal courts, requires
no token, no wallet, and no gas fee, and is available from DigiCert, GlobalSign,
and FreeTSA.org (free for non-commercial use) with sub-second response times.

Blockchain remains available as an optional Tier 4 choice for customers who
specifically require it — for example, blockchain-native enterprises whose
compliance teams are already comfortable with on-chain evidence. If required,
Ethereum mainnet is the only defensible choice for a regulated context:
it has the largest validator set (~1 million validators), has been in production
since 2015, and is the chain regulators have actual experience with. ZK rollups
are not the right fit here — ZK proofs verify computational correctness, not
data existence at a point in time. Monad is too early-stage.

The default architecture does not use blockchain at all.

### 12.3 Storage Tiers

| Tier | Trigger | Anchoring mechanism | User pays? | Retention |
|---|---|---|---|---|
| 0 — Session | Development / testing | In-process memory only | No | Session lifetime |
| 1 — Ephemeral | Default production | Local filesystem or Redis | No | 48 hours |
| 2 — Durable | `retention_days > 0` | S3-compatible object store | No (storage costs only) | As configured |
| 3 — Compliant | `sox`, `hipaa`, or `eu-ai-act-art13` | WORM object store + RFC 3161 timestamp | No | Framework-mandated minimum |
| 4 — Blockchain | Explicit customer requirement only | Tier 3 + Ethereum mainnet anchor | Yes (ETH gas) | Permanent |

**Tier 3 is the maximum that most regulated deployments need.** The RFC 3161
timestamp in Tier 3 provides legally defensible, independently verifiable
proof that a DR existed at a specific point in time — the same guarantee
that blockchain anchoring provides, without any gas cost, without any token,
and with 20 years of legal precedent.

### 12.4 RFC 3161 — Trusted Timestamping (Tier 3 Anchor)

**Standard:** RFC 3161, Internet X.509 PKI Time-Stamp Protocol, IETF 2001

A Timestamp Authority (TSA) receives a hash, signs it alongside the current
time using its own certificate chain (rooted in a trusted CA), and returns a
cryptographically bound timestamp token. The token proves the hash existed
before a specific moment. Neither the submitter nor the TSA can backdate it.

```
RFC 3161 anchor flow for a Delegation Receipt:

1. Compute hash_to_anchor = SHA-256(dr_jwt_bytes)

2. Send hash_to_anchor to TSA endpoint:
   POST https://timestamp.digicert.com
   Content-Type: application/timestamp-query
   Body: TimeStampRequest { hashAlgorithm: SHA-256, hashedMessage: hash_to_anchor }

3. TSA returns TimeStampToken (TST):
   TST = Sign(TSA_private_key, {
     hashAlgorithm:  SHA-256,
     hashedMessage:  hash_to_anchor,
     genTime:        2026-03-28T14:22:03.412Z,
     serialNumber:   TSA-assigned unique serial,
     tsa:            TSA certificate chain
   })

4. Store TST alongside the DR in the DR store.

5. Verification (by anyone, without contacting DRS or the TSA):
   a. Recompute SHA-256(dr_jwt_bytes) → must equal TST.hashedMessage
   b. Verify TST signature against TSA certificate
   c. Verify TSA certificate chain up to trusted root CA
   d. Read TST.genTime → this is the proven existence timestamp

Outcome: independently verifiable proof that the DR existed
at TST.genTime, signed by a trusted third party,
with no gas fee and no blockchain required.
```

**Legal recognition:**
- **EU eIDAS Regulation**: Qualified electronic timestamps from EU-accredited
  TSAs carry legal presumption of accuracy of the date and time indicated
  (Article 41). Several TSA providers (DigiCert, GlobalSign) hold EU qualified
  status.
- **US federal courts**: RFC 3161 timestamps are accepted as evidence of
  document existence under Federal Rules of Evidence.
- **ISO 18014**: International standard for trusted timestamping, aligns with
  RFC 3161.
- **ETSI EN 319 422**: European standard for timestamp generation, used by
  qualified TSAs under eIDAS.

**Available TSA providers:**

| Provider | Type | Cost | Notes |
|---|---|---|---|
| DigiCert | Commercial | ~$0.01/stamp | Qualified eIDAS TSA |
| GlobalSign | Commercial | ~$0.01/stamp | Qualified eIDAS TSA |
| Sectigo | Commercial | ~$0.005/stamp | Widely used |
| FreeTSA.org | Free | Free | Not eIDAS-qualified; suitable for non-regulated uses |
| Apple TSA | Free | Free | Available at timestamp.apple.com for code signing contexts |

For Tier 3 regulated deployments, DRS integrates with DigiCert or GlobalSign.
The cost is a fraction of a cent per DR — negligible for enterprise deployments.

### 12.5 Bitstring Status List — Revocation

W3C Bitstring Status List v1.0. A compressed bitstring where bit N represents
the revocation status of the DR at `drs_status_list_index = N`.

```
Revocation flow:
1. Issuer sets bit N = 1 in status list
2. Status list is re-signed by status list issuer
3. Updated list published to well-known URL
4. Tool servers fetch on next request (5-minute cache TTL)
5. Block F reads bit N — if 1: REVOKED

For Tier 3 (Compliant) deployments:
  Revocation events are additionally timestamped via RFC 3161.
  This proves the revocation occurred before a specific moment —
  important if a dispute arises about whether an agent had
  valid authority at the time of a specific action.

For Tier 4 (Blockchain, opt-in only):
  Revocation events are recorded on Ethereum mainnet via a
  simple mapping contract: keccak256(jti) → revocation_timestamp.
  This provides immutable on-chain proof of revocation timing.
  Users pay ETH gas for each revocation event.
```

---

## 13. Regulatory Alignment

### 13.1 EU AI Act (in force 2026)

For high-risk AI systems (Annex III):

**Article 12 — Record-keeping:** Systems must allow recording of events relevant
to identifying risks. DRS Delegation Receipts are cryptographically signed,
tamper-evident records of every delegation event and every tool invocation.

**Article 13 — Transparency:** Systems must be sufficiently transparent.
DRS chains are independently verifiable — the auditee does not control the
audit evidence.

### 13.2 HIPAA §164.312(b) — Audit Controls

Requires hardware, software, or procedural mechanisms to record and examine
activity in systems containing electronic protected health information.

DRS Invocation Receipts record every agent action with full delegation provenance.
Deployments touching PHI must include `"hipaa"` in `drs_regulatory.frameworks`,
triggering Tier 3 (Compliant) storage with WORM policy and 7-year retention.

### 13.3 AIUC-1 Certification

The AI Underwriting Company (AIUC) emerged from stealth July 2025 with a $15M
seed led by Nat Friedman. AIUC-1 certification covers 50+ controls including
accountability and reliability. UiPath is the first certified enterprise platform.

AIUC-1 requires demonstrable proof of authorisation for every agent action —
not just logs of what occurred. DRS Delegation Receipts provide exactly this.
The AIUC-1 certification path is identified as the primary near-term commercial
opportunity for DRS: every company seeking AIUC-1 certification needs tooling
to generate the required evidence.

### 13.4 FINOS AI Governance Framework

The Fintech Open Source Foundation has published a framework for "Agent Decision
Audit and Explainability" targeting financial services. Their Tier 3 and Tier 4
implementation levels require chain-of-custody evidence for legal proceedings.
DRS Delegation Receipts satisfy this requirement.

SR 11-7 (Federal Reserve model risk management guidance), EBA Guidelines,
and GDPR Article 22 (automated decision-making) all require explainability and
audit trails for automated systems in financial contexts. BFSI accounts for
25–47% of AI governance spending (varying by source) — the primary early market.

---

## 14. Market Timing and Revenue Honesty

This section is included because earlier versions of this document overstated
how close revenue is. Overconfidence here is worse than acknowledging the gap.

### 14.1 Where the Market Is

Only **5.2%** of enterprises have AI agents genuinely in production (Cleanlab/MIT,
n=1,837, 2025). LangChain's survey shows 57%, but that survey self-selects for
early adopters. Menlo Ventures found only **16%** of enterprise "agent deployments"
are true agents — the rest are basic if-then logic around model calls.

The pain is real. The paying customers exist. But they are leading-edge.
Enterprise agent deployment jumped from 11% to 26% through 2025–2026 (KPMG).
The curve is moving. But the broad enterprise wave that would generate volume
DRS revenue is 18–36 months out.

### 14.2 What Others Have Achieved

**Credo AI** — the AI governance category leader backed by Andrew Ng — had
approximately **$3.7M in revenue** after four years with $41M raised. This is
a slow-burn enterprise sale. Governance products take time.

Plan realistically for **18–24 months to first meaningful revenue** in any
governance product. This is not pessimism — it is the observed pace of the
category.

### 14.3 The Three Realistic Paths

**Path 1 — AIUC-1 compliance tooling (nearest term):**
Build the specific accountability infrastructure that produces AIUC-1
certification evidence. Clear buyer (every company seeking certification),
clear pain (producing audit-ready documentation), clear willingness to pay
(analogous to SOC 2 audits at $20K–$100K+). This is a feature set first,
then an extractable product.

**Path 2 — Regulated finance (12–18 months):**
BFSI spends 25–47% of AI governance budget. SR 11-7, EBA, GDPR Article 22
all require explainability and audit trails. FINOS framework is a ready-made
spec to align to. Target 2–3 banks deploying agents. $50K–$200K/year
enterprise contract range.

**Path 3 — Open standard (18–36 months, requires ecosystem):**
Submit DRS as an IETF Internet Draft. Engage the OAuth WG directly on the chain
splicing thread. Require multi-vendor contribution (Okta, Microsoft) to reach
the OpenTelemetry-style adoption trajectory. The market window for this is gated
on cross-organisational agent delegation becoming common — it is not there yet.

### 14.4 What the Stack Looks Like to a Buyer

A CISO approving an agent deployment in 2026 needs to answer:

| Question | Tool that answers it |
|---|---|
| What is this agent's identity? | OAuth 2.1 + Workload Identity |
| What is it authorised to do? | OAuth scopes + MCP server policies |
| Is its behaviour consistent with its declared identity? | Agentic JWT (agent checksums) |
| Can I see what it did in real time? | OpenTelemetry + observability platform |
| Can I prove what it was authorised to do, independently? | **DRS** |
| Can I prove it matches a certification framework? | DRS + AIUC-1 evidence export |

DRS fills one specific cell in that table. The buyer needs the whole table
filled. The pitch is not "DRS replaces everything" — it is "DRS fills the
one gap that nothing else fills."

---

## 15. Implementation Roadmap

### Phase 1 — Core (Months 1–4)

- [ ] Rust core: Ed25519 sign/verify with JCS canonicalisation, SHA-256 hash chain, DR issuance, verify_chain() algorithm
- [ ] Compile to WASM via `wasm-pack`
- [ ] TypeScript SDK: `issueRootDR`, `issueSubDelegationDR`, `buildBundle`, `verifyChain`
- [ ] Human-readable error system: 16 error codes, English messages, suggestions
- [ ] JCS canonicalisation test vectors: 300+ cases including edge cases
- [ ] CLI: `drs verify`, `drs policy check`, `drs translate`, `drs audit retrieve`
- [ ] DR store: Tier 0 (in-memory) and Tier 1 (filesystem) backends
- [ ] did:key resolution: pure computation, no network dependency

### Phase 2 — Integration and DX (Months 4–8)

- [ ] Go verification middleware: concurrent, goroutine-based, LRU DID cache
- [ ] `@drs/mcp-middleware` for MCP servers (HTTP and STDIO transport)
- [ ] Consent Translator: policy JSON → plain language (5 languages minimum)
- [ ] Session Manager: list active delegations, revoke, activity feed
- [ ] Bitstring Status List revocation with 5-minute cache
- [ ] Online playground: paste bundle, see step-by-step verification, try test args
- [ ] S3-compatible DR store backend (Tier 2 — Durable)
- [ ] AIUC-1 evidence export format

### Phase 3 — Enterprise and Compliance (Months 8–18)

- [ ] WORM-compliant DR store backend (Tier 3 — Compliant, 7-year retention)
- [ ] RFC 3161 trusted timestamp integration: DigiCert + GlobalSign + FreeTSA
- [ ] Ethereum mainnet anchor (Tier 4 — opt-in only, for blockchain-native enterprise customers)
- [ ] Audit export: EU AI Act, HIPAA, SOX, FINOS formats
- [ ] Machine-to-machine trust model: operator config, supervisor agent escalation
- [ ] Auto-renewal for `automated-system` root type
- [ ] Enterprise IdP integration: Okta, Auth0, Microsoft Entra ID
- [ ] Python reference implementation

### Phase 4 — Standardisation (Year 2+)

- [ ] Submit DRS as IETF Internet Draft (complement to draft-goswami-agentic-jwt)
- [ ] IETF OAuth WG engagement on chain splicing mitigation thread
- [ ] CNCF proposal for neutral governance (OpenTelemetry model)
- [ ] Java reference implementation
- [ ] UCAN compatibility addendum

---

## 16. What DRS Does Not Solve

**Behavioural safety:** DRS proves authorisation, not safety. An agent with a
valid chain can still cause harm within its policy bounds.

**LLM non-determinism:** Changing the model version or system prompt changes
the agent's behaviour without changing its delegation chain. Agentic JWT
(draft-goswami-agentic-jwt-00) addresses this with agent checksums. Use both.

**Prompt injection:** An adversary embedding instructions in content the agent
reads can cause unintended tool calls. DRS records the invocation with its
authorisation chain. It does not prevent the injection.

**Post-compromise historical records:** Delegations signed before a key was
compromised cannot be retroactively invalidated. Revocation only prevents
future use.

**Cross-jurisdictional legal enforceability:** DRS produces cryptographically
verifiable evidence. Whether it satisfies a specific jurisdiction's evidentiary
standards is a legal question, not a technical one.

**Agent registry:** DRS uses DIDs for identity. There is no global agent
registry. `did:key` is universally available and requires no infrastructure.
`did:web` requires DNS control. DRS does not define who is authorised to
operate a given DID.

**Model-level safety:** Stanford TrustAI Lab: fine-tuning attacks bypassed
model-level guardrails in 72% (Claude Haiku) and 57% (GPT-4o) of cases.
DRS is an execution-layer accountability primitive, not a model safety mechanism.

---

## Appendix A — Error Code Reference

| Code | Condition | Message | Suggestion |
|---|---|---|---|
| `EMPTY_CHAIN` | `receipts.length == 0` | No delegation receipts in bundle | Include at least one DR |
| `MISSING_INVOCATION` | No invocation field | No invocation receipt | Include the invocation receipt |
| `CHAIN_BREAK` | SHA-256(DRᵢ) ≠ DRᵢ₊₁.prev_dr_hash | Chain broken at index i+1 | Rebuild from DR store, root first |
| `ISSUER_MISMATCH` | DRᵢ.iss ≠ DRᵢ₋₁.aud | Wrong issuer at index i | Each DR must be issued by the audience of the previous DR |
| `INVOKER_MISMATCH` | inv.iss ≠ last DR.aud | Invoker is not leaf DR audience | Invocation must be signed by the leaf DR's audience |
| `CHAIN_REFERENCE_MISMATCH` | inv.dr_chain ≠ computed hashes | Invocation does not reference the correct chain | Include all DR hashes in dr_chain, root first |
| `INVALID_SIGNATURE` | Ed25519Verify fails on DR | DR was tampered with or wrong key used | Re-issue DR from original issuer |
| `INVALID_INVOCATION_SIGNATURE` | Ed25519Verify fails on invocation | Invocation signature invalid | Re-create invocation with correct agent key |
| `POLICY_VIOLATION` | evaluate_policy fails | Invocation args exceed a constraint | Adjust args or request delegation with broader policy |
| `POLICY_ESCALATION` | Child policy less restrictive than parent | Child DR loosens a constraint | Tighten child policy to be subset of parent |
| `COMMAND_MISMATCH` | DRᵢ.cmd incompatible with DR₀.cmd | Wrong command in chain | All DRs must use root cmd or a sub-path |
| `SUBJECT_MISMATCH` | DRᵢ.sub ≠ DR₀.sub | Subject changed mid-chain | Subject must be identical through entire chain |
| `NOT_YET_VALID` | now < DR.nbf | DR not yet valid | Wait until nbf, or re-issue with correct timing |
| `EXPIRED` | now > DR.exp | DR has expired | Request a new delegation from authorising party |
| `REVOKED` | Status list bit = 1 | DR was explicitly revoked | Issue a new delegation |
| `UNRESOLVABLE_DID` | DID decode fails | Cannot derive public key from DID | Check did:key format; verify DNS for did:web |

---

## Appendix B — DRS in Context

| Tool / Standard | Layer | What it provides | What it does not provide |
|---|---|---|---|
| OAuth 2.1 + MCP | Authentication | Identity and scope for agent tool access | Delegation chain provenance |
| RFC 8693 `act` claim | Token exchange | Single-hop delegation representation in JWT | Multi-hop chain integrity (act claims are informational only) |
| Agentic JWT | Intent binding | Agent identity (checksum), intent-execution linking, workflow binding | Per-step delegation provenance |
| OpenTelemetry | Distributed tracing | What happened, when, in what order | Cryptographic proof (OTel spans are mutable logs) |
| Langfuse / Arize / Datadog AI | Observability | Visibility into agent behaviour | Independently verifiable delegation evidence |
| Pragatix / AGAT | Execution layer | Runtime enforcement and audit attribution | Open standard, independent verifiability |
| ARIA framework | Graph-native IAM | Graph-native delegation with policy enforcement | Shipping product with open spec |
| **DRS** | Provenance | Per-step signed delegation receipts, tamper-evident chain, independent verification | Agent safety, intent binding, model behaviour |

The complete enterprise accountability stack is all of these working together.
No single layer is sufficient. DRS fills the cell that nothing else fills:
independently verifiable, per-step delegation provenance.

---

## Appendix C — Standards Referenced

| Standard | Authority | DRS Usage |
|---|---|---|
| RFC 8032 | IETF (Josefsson, Liusvaara, 2017) | Ed25519 signing and verification |
| RFC 8785 | IETF (Rundgren, Jordan, Erdtman, 2020) | JSON Canonicalization Scheme |
| RFC 7519 | IETF (Jones, Bradley, Sakimura, 2015) | JSON Web Token format |
| RFC 8037 | IETF (Liusvaara, 2017) | EdDSA in JOSE (alg: "EdDSA") |
| RFC 8693 | IETF (Jones et al., 2020) | OAuth Token Exchange — the gap DRS fills |
| RFC 9728 | IETF (Lodderstedt, Fett, 2025) | Protected Resource Metadata for MCP |
| RFC 8707 | IETF (Campbell, Bradley, Sakimura, 2020) | Resource Indicators — audience binding |
| RFC 3161 | IETF (Adams et al., 2001) | Trusted Timestamping — Tier 3 anchor. Legally recognised under EU eIDAS and US federal evidence rules. No gas fee, no token. |
| NIST FIPS 180-4 | NIST (2015) | SHA-256 / SHA-512 |
| ETSI EN 319 422 | ETSI (2016) | European standard for timestamp generation — used by eIDAS-qualified TSAs |
| ISO 18014 | ISO (2002, updated 2009) | International trusted timestamping standard |
| W3C Bitstring Status List v1.0 | W3C (2024) | Revocation |
| W3C DID Core v1.0 | W3C (2022) | Decentralised Identifiers |
| W3C DID-key method | W3C CCG | did:key encoding — no registry required |
| draft-goswami-agentic-jwt-00 | IETF (December 2025) | Complementary — agent checksums and intent tokens |

---

*Quorum · DRS Technical Report · March 2026*  
*Author: Okey*