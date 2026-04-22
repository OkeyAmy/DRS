# Delegation Receipt Standard (DRS) — Complete Architecture v3
### Built from human flows outward. Aligned to UCAN v1.0.0-rc.1.

> **Historical archive.** This document preserves an earlier UCAN-era design path. It is not the current implementation contract for the JWT/JCS/Ed25519 system in this repository.

**Version:** 3.0.0  
**Date:** March 2026  
**Author:** Okey  
**Prior versions:** v1 (invented delegation chains), v2 (wrong UCAN version, no human flows)  
**This version:** Correct spec, correct architecture, correct algorithms, correct language stack

---

## What Changed From v2 and Why

| v2 error | v3 fix | Why it matters |
|---|---|---|
| Built against UCAN 0.x (JWT, `att.nb`) | Rebuilt against UCAN v1.0.0-rc.1 (CBOR/IPLD, `cmd`/`pol`) | The uploaded spec is v1.0-rc.1 — v2 was entirely wrong encoding |
| No human-facing layer | Session manager, consent translator, activity feed | Without these, no human can actually use this product |
| No developer experience layer | DX error layer, playground, CLI verifier | Security middleware that is hard to debug gets turned off |
| No capability negotiation | Inline upgrade negotiation protocol | Agents need a way to ask for more permission mid-workflow |
| Optional audit storage | Mandatory storage tiers per regulatory classification | "Optional" is not an audit strategy |
| Binary Merkle tree (wrong) | UCAN CID-linked hash chain (correct) | Linear chains do not need trees |
| JCS on JSON | CBOR/IPLD canonicalisation | UCAN v1.0 uses CBOR not JSON |
| `drs/constraints` as nb fields | Policy Language expressions in UCAN `pol` | v1.0 replaced nb with a full Policy Language |
| TypeScript-only crypto | Rust core + Go middleware + TS SDK | GC pauses in V8 break crypto latency guarantees |

---

## Table of Contents

1. [The Five Actors and Their Needs](#1-the-five-actors-and-their-needs)
2. [UCAN v1.0 Data Model — Corrected](#2-ucan-v10-data-model--corrected)
3. [DRS Extension Fields](#3-drs-extension-fields)
4. [Complete Data Model Examples](#4-complete-data-model-examples)
5. [Core Algorithms — Research-Grounded](#5-core-algorithms--research-grounded)
6. [Policy Language — v1.0 Specification](#6-policy-language--v10-specification)
7. [Human Layer — What People Actually See](#7-human-layer--what-people-actually-see)
8. [Developer Layer — DX and Tooling](#8-developer-layer--dx-and-tooling)
9. [Protocol Adapters](#9-protocol-adapters)
10. [Storage Architecture — Mandatory Tiers](#10-storage-architecture--mandatory-tiers)
11. [Language and Runtime Architecture](#11-language-and-runtime-architecture)
12. [Capability Negotiation Protocol](#12-capability-negotiation-protocol)
13. [Security Model](#13-security-model)
14. [Scalability Architecture](#14-scalability-architecture)
15. [On-Chain Registry — Monad](#15-on-chain-registry--monad)
16. [Implementation Roadmap](#16-implementation-roadmap)
17. [What DRS Does Not Solve](#17-what-drs-does-not-solve)

---

## 1. The Five Actors and Their Needs

Every design decision in this document is anchored to one of these five people.
If a feature cannot be traced back to a named actor's need, it should not be built.

```
Actor             Need                                  Current gap
─────────────────────────────────────────────────────────────────────
End user (Amara)  Understand what she is approving.     Raw URIs shown, not language
                  See what agents are doing.            No activity feed
                  Revoke instantly.                     No revocation UI

Developer (Okey)  Integrate DRS in < 1 day.            Opaque error codes
                  Debug failures with clear traces.     No playground or CLI
                  Test without a live agent.            No test harness

Agent runtime     Know which capabilities it holds.    No session model
                  Request more permission mid-task.    No negotiation protocol
                  Handle expiry gracefully.            No renewal path

Tool owner        Trust the chain is legitimate.       No root principal trust levels
                  Rate-limit by chain identity.        No per-chain quotas
                  Block a specific agent.              No tool-side restriction

Auditor           Retrieve full delegation evidence.   Storage is optional
                  Prove human consent occurred.        No canonical consent spec
                  Meet multi-year retention.           IPFS not durable enough
```

---

## 2. UCAN v1.0 Data Model — Corrected

### 2.1 What Changed in v1.0.0-rc.1

UCAN v1.0 introduces four breaking changes from 0.x:

**Change 1 — Encoding:** JWT (base64url JSON) → UCAN Envelope (CBOR/IPLD)  
Every token is now CBOR-encoded, not JSON. This means:
- Canonicalisation uses CBOR deterministic encoding (RFC 8949 §4.2), not JCS
- CID computation is over CBOR bytes, not JSON bytes
- The `@ipld/dag-cbor` and `serde_cbor` crates replace `serde-json-canonicalizer`

**Change 2 — Capability structure:**  
v0.x: `att = [{ with: "mcp://tools/*", can: "mcp/call", nb: {...} }]`  
v1.0: `{ sub: DID, cmd: "/mcp/call", pol: [[...policy expressions...]] }`  
The `with` field is gone. `cmd` is the command path. `sub` is the subject.

**Change 3 — Policy Language replaces `nb`:**  
v0.x nb: `{ maxCostUSD: 5.00 }`  
v1.0 pol: `[["<=", ".cost_usd", 5.00]]`  
Constraints are now Lisp-style expressions operating on invocation arguments.

**Change 4 — Delegation/Invocation separation:**  
A delegation (`ucan/dlg@1.0.0-rc.1`) authorises.  
An invocation (`ucan/inv@1.0.0-rc.1`) exercises that authorisation.  
They are separate signed envelopes. An agent always presents both.

### 2.2 Delegation Envelope Structure (v1.0.0-rc.1)

```typescript
// Types reflecting the UCAN v1.0.0-rc.1 specification exactly

interface UCANDelegationPayload {
  iss:  DID;              // Issuer — who is granting this capability
  aud:  DID;              // Audience — who receives this capability  
  sub:  DID | null;       // Subject — the resource owner (null = iss is owner)
  cmd:  string;           // Command path e.g. "/mcp/call", "/a2a/task/create"
  pol:  PolicyExpression[]; // Policy constraints (UCAN Policy Language)
  nonce: Uint8Array;      // 12+ random bytes — prevents replay
  meta?: Record<string, unknown>; // Optional metadata — NOT delegated downstream
  nbf?: number;           // Not before (Unix seconds, optional)
  exp:  number | null;    // Expiry (Unix seconds, null = no expiry — avoid in DRS)
}

interface UCANDelegationEnvelope {
  tag: "ucan/dlg@1.0.0-rc.1";
  payload: UCANDelegationPayload; // CBOR-encoded before signing
  sig: Uint8Array;                // Ed25519 signature over CBOR(payload)
  prf: CID[];                     // CIDs of parent delegations (proof chain)
}
```

### 2.3 Invocation Envelope Structure (v1.0.0-rc.1)

```typescript
interface UCANInvocationPayload {
  iss:  DID;              // Invoker (must be audience of the delegation)
  sub:  DID;              // Subject being acted on
  cmd:  string;           // Command being invoked
  args: Record<string, unknown>; // Arguments to the command
  prf:  CID[];            // CIDs of delegations authorising this invocation
  nonce: Uint8Array;      // Unique per invocation
  meta?: Record<string, unknown>;
  nbf?: number;
  exp:  number | null;
}

interface UCANInvocationEnvelope {
  tag: "ucan/inv@1.0.0-rc.1";
  payload: UCANInvocationPayload;
  sig: Uint8Array;
}
```

### 2.4 The Proof Chain — How Delegation Links Work in v1.0

In v1.0, each delegation's identity is its CBOR CID. The `prf` array in an
invocation (or delegation) lists the CIDs of the delegations that grant authority.
Verifiers must resolve and verify every CID in the proof chain.

```
Human issues Delegation_A:
  { iss: humanDID, aud: agent1DID, cmd: "/mcp/call", pol: [[...]], prf: [] }
  CID_A = CIDv1(sha2-256(CBOR(Delegation_A_payload)))

Agent_1 issues Delegation_B (sub-delegation):
  { iss: agent1DID, aud: agent2DID, cmd: "/mcp/call", pol: [[stricter...]], prf: [CID_A] }
  CID_B = CIDv1(sha2-256(CBOR(Delegation_B_payload)))

Agent_2 creates Invocation_C:
  { iss: agent2DID, cmd: "/mcp/call", args: {...}, prf: [CID_B] }
  — verifier resolves CID_B → finds Delegation_B
  — Delegation_B.prf contains CID_A → resolves → Delegation_A
  — full chain: Human → Agent_1 → Agent_2 — all verified
```

The key difference from v0.x: the invocation does NOT carry the delegations inline.
It carries only their CIDs. Verifiers must resolve CIDs from the local bundle or
a content-addressed store. This is why the storage layer is mandatory, not optional.

---

## 3. DRS Extension Fields

DRS adds to the `meta` field of the UCAN delegation payload.
This is explicitly the correct placement — the UCAN spec says `meta` is optional
metadata that is NOT delegated downstream. DRS extensions are exactly that:
accountability metadata about the delegation act itself, not part of the capability.

```typescript
// DRS extensions live in delegation.payload.meta["drs"]
interface DRSMeta {
  "drs/v":          "3.0";        // DRS spec version
  "drs/consent"?:  DRSConsent;   // Human consent evidence (required at root)
  "drs/root-type"?: "human" | "organisation" | "automated-system";
  "drs/regulatory"?: DRSRegulatory;
  "drs/session"?:  string;       // Session ID linking to the session manager
}

interface DRSConsent {
  method:    "explicit-ui-click" | "voice-confirmation" | "hardware-key" | "biometric";
  timestamp: string;        // ISO 8601 UTC
  session_id: string;       // Session ID — links to consent UI capture
  policy_hash: string;      // SHA-256 of the HUMAN-READABLE policy text shown
                            // (not the raw pol[] array — the translated text)
  locale:    string;        // BCP 47 — what language was the consent shown in
}

interface DRSRegulatory {
  frameworks: Array<"eu-ai-act-art14" | "hipaa" | "sox" | "pci-dss" | "gdpr">;
  risk_level: "minimal" | "limited" | "high" | "unacceptable";
  retention_days: number;   // Minimum storage duration for this delegation
}
```

### Why `policy_hash` is over translated text, not raw `pol[]`

The `pol` array contains machine expressions like `["<=", ".cost_usd", 5.00]`.
What the user consented to is the human-readable text: "Agent may spend up to $5.00."
The `policy_hash` is the SHA-256 of that rendered text, in the locale shown.
This allows an auditor to verify not just that consent happened, but that the user
saw accurate, legible information — not obfuscated capability strings.

---

## 4. Complete Data Model Examples

### 4.1 Root Delegation — Human to Agent (Full v1.0 + DRS)

```json
{
  "tag": "ucan/dlg@1.0.0-rc.1",
  "payload": {
    "iss": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "aud": "did:key:z6MkjLrk73pkTkbyHnpjuiHTpPfMiRd5C7gEfELnBWRd2pim",
    "sub": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "cmd": "/mcp/call",
    "pol": [
      ["==", ".tool", "web_search"],
      ["<=", ".estimated_cost_usd", 5.00],
      ["==", ".pii_in_results", false],
      [">=", ".nbf", 1743000000]
    ],
    "nonce": "<12 random bytes as base64>",
    "nbf": 1743000000,
    "exp": 1743003600,
    "meta": {
      "drs": {
        "drs/v": "3.0",
        "drs/root-type": "human",
        "drs/consent": {
          "method": "explicit-ui-click",
          "timestamp": "2026-03-24T10:30:00Z",
          "session_id": "sess:8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
          "policy_hash": "sha256:abc123def456...",
          "locale": "en-GB"
        },
        "drs/regulatory": {
          "frameworks": ["eu-ai-act-art14"],
          "risk_level": "limited",
          "retention_days": 730
        },
        "drs/session": "sess:8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
      }
    },
    "prf": []
  },
  "sig": "<64-byte Ed25519 signature over CBOR(payload)>"
}
```

The CID of this delegation is:
`CIDv1(sha2-256(CBOR(payload))) = "bafyaaa..."`

### 4.2 Sub-Delegation — Agent to Tool Server

```json
{
  "tag": "ucan/dlg@1.0.0-rc.1",
  "payload": {
    "iss": "did:key:z6MkjLrk73pkTkbyHnpjuiHTpPfMiRd5C7gEfELnBWRd2pim",
    "aud": "did:key:z6MkToolServer...",
    "sub": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "cmd": "/mcp/call",
    "pol": [
      ["==", ".tool", "web_search"],
      ["<=", ".estimated_cost_usd", 2.00],
      ["==", ".pii_in_results", false]
    ],
    "nonce": "<12 random bytes>",
    "nbf": 1743000060,
    "exp": 1743000360,
    "meta": {
      "drs": {
        "drs/v": "3.0",
        "drs/session": "sess:8f3a2b1c-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
      }
    },
    "prf": ["bafyaaa..."]
  },
  "sig": "<Agent_1's Ed25519 signature>"
}
```

Note: cost limit reduced from $5.00 to $2.00 — this is POLA. The sub-delegation
tightens the policy, it never loosens it.

### 4.3 Invocation — Agent Exercises Capability

```json
{
  "tag": "ucan/inv@1.0.0-rc.1",
  "payload": {
    "iss": "did:key:z6MkjLrk73pkTkbyHnpjuiHTpPfMiRd5C7gEfELnBWRd2pim",
    "sub": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "cmd": "/mcp/call",
    "args": {
      "tool": "web_search",
      "query": "Monad blockchain throughput 2026",
      "estimated_cost_usd": 0.01,
      "pii_in_results": false
    },
    "prf": ["bafybbb..."],
    "nonce": "<12 random bytes>",
    "exp": 1743000420
  },
  "sig": "<Agent_1's Ed25519 signature>"
}
```

The tool server receives BOTH the invocation AND the delegation bundle.
It resolves CIDs `bafybbb...` → sub-delegation → `bafyaaa...` → root delegation.
Then it verifies the full chain before executing `/mcp/call`.

---

## 5. Core Algorithms — Research-Grounded

### 5.1 CBOR Encoding and CID Computation

```rust
// Rust — using dag-cbor encoding for UCAN v1.0 payloads
// Crate: libipld (IPLD implementation for Rust)
// Crate: multihash (multihash encoding)
// Crate: cid (CIDv1 generation)
//
// Source: IPLD spec, dag-cbor codec
// RFC 8949 §4.2 — deterministic CBOR encoding rules

use libipld::cbor::DagCborCodec;
use libipld::codec::Codec;
use multihash::{Code, MultihashDigest};
use cid::Cid;

/// Encodes a delegation payload to canonical CBOR and computes its CIDv1.
///
/// Deterministic CBOR (RFC 8949 §4.2) rules applied:
/// - Integer encoding: smallest encoding, no leading zeros
/// - Map key ordering: lexicographic by encoded key bytes
/// - No indefinite-length encoding
/// - Floats: IEEE 754 half/single/double, smallest fitting
///
/// The payload MUST NOT include the sig field — the CID is over the
/// unsigned content, matching how git commit IDs work.
pub fn compute_delegation_cid(payload: &DelegationPayload) -> Result<Cid, Error> {
    // 1. Encode to dag-cbor (deterministic)
    let cbor_bytes = DagCborCodec.encode(payload)?;

    // 2. Multihash: sha2-256 (code 0x12), 32-byte digest
    let mh = Code::Sha2_256.digest(&cbor_bytes);

    // 3. CIDv1 with dag-cbor codec (0x71)
    // Note: dag-cbor codec is 0x71, not 0x0129 (dag-json)
    // This was wrong in v2 — v1.0 UCAN uses dag-cbor
    Ok(Cid::new_v1(0x71, mh))
}
```

**Why 0x71 (dag-cbor) and not 0x0129 (dag-json):**  
v2 used dag-json because v2 was built against UCAN 0.x which used JSON.
UCAN v1.0 uses CBOR throughout. The codec prefix in the CID must match.
Using 0x0129 on CBOR content produces CIDs that no IPLD-aware system will recognise.

### 5.2 Ed25519 Signing Over CBOR

```rust
// Signing procedure for UCAN v1.0 delegations
// Source: RFC 8032 §5.1, UCAN v1.0.0-rc.1 spec
//
// CRITICAL: In UCAN v1.0, the message signed is the CBOR encoding of
// the payload — not the JCS-canonicalised JSON we used in v2.
// The UCAN spec is explicit: sig = Ed25519Sign(privateKey, dag-cbor(payload))

use ed25519_dalek::{SigningKey, Signer};

pub fn sign_delegation(
    payload: &DelegationPayload,
    signing_key: &SigningKey,
) -> Result<([u8; 64], Cid), Error> {
    // 1. CBOR-encode the payload (deterministic)
    let cbor_bytes = DagCborCodec.encode(payload)?;

    // 2. Ed25519 sign the CBOR bytes directly
    // RFC 8032 Pure EdDSA: SHA-512 is applied internally by the algorithm.
    // We do NOT pre-hash. We do NOT apply JCS. We sign the raw CBOR bytes.
    // ed25519-dalek 2.x enforces S < q (SUF-CMA property).
    let signature: ed25519_dalek::Signature = signing_key.sign(&cbor_bytes);

    // 3. Compute CID (same CBOR bytes, same hash)
    let cid = compute_delegation_cid(payload)?;

    Ok((signature.to_bytes(), cid))
}
```

### 5.3 Chain Verification Algorithm — v1.0 Correct

```rust
/// Verifies a DRS chain bundle against the UCAN v1.0.0-rc.1 specification.
///
/// Input: a ChainBundle containing delegations (root → leaf) and the invocation
/// Output: VerificationResult with full context for the tool handler
///
/// The algorithm verifies three things in order:
///   A. Structural integrity (CID chain links)
///   B. Cryptographic validity (Ed25519 signatures, one per delegation)
///   C. Semantic validity (policy attenuation, temporal validity, revocation)
///
/// Complexity: O(n) where n = chain depth + O(p) per delegation where
/// p = number of policy expressions. In practice n ≤ 10, p ≤ 20.

pub fn verify_chain(bundle: &DRSChainBundle) -> VerificationResult {
    let delegations = &bundle.delegations;
    let invocation  = &bundle.invocation;

    if delegations.is_empty() {
        return VerificationResult::invalid("EMPTY_BUNDLE",
            "Bundle contains no delegations. Every invocation needs at least one.");
    }

    // ── Block A: Structural integrity ─────────────────────────────────────

    // A1. Each delegation's CID must match what its child claims in prf[]
    for i in 1..delegations.len() {
        let expected_cid = compute_delegation_cid(&delegations[i-1].payload)?;
        let claimed_cid  = &delegations[i].payload.prf[0];

        if &expected_cid != claimed_cid {
            return VerificationResult::invalid("CHAIN_BREAK", &format!(
                "Delegation at index {} claims parent CID {} \
                 but computing CID of index {} gives {}. \
                 Either the parent delegation was modified or \
                 the wrong delegation was included in the bundle.",
                i, claimed_cid, i-1, expected_cid
            ));
        }
    }

    // A2. The invocation's prf must reference the leaf delegation
    let leaf_cid = compute_delegation_cid(&delegations.last().unwrap().payload)?;
    if !invocation.payload.prf.contains(&leaf_cid) {
        return VerificationResult::invalid("INVOCATION_UNLINKED",
            "The invocation does not reference the leaf delegation in its prf[].");
    }

    // A3. The invocation issuer must be the leaf delegation's audience
    let leaf_aud = &delegations.last().unwrap().payload.aud;
    if &invocation.payload.iss != leaf_aud {
        return VerificationResult::invalid("INVOKER_MISMATCH", &format!(
            "Invocation issuer {} is not the audience {} of the leaf delegation. \
             An agent can only invoke capabilities delegated TO it.",
            invocation.payload.iss, leaf_aud
        ));
    }

    // ── Block B: Cryptographic validity ───────────────────────────────────

    // B1. Verify each delegation's signature
    for (i, delegation) in delegations.iter().enumerate() {
        let cbor_payload = DagCborCodec.encode(&delegation.payload)?;
        let verifying_key = resolve_did_key(&delegation.payload.iss)?;

        let sig = ed25519_dalek::Signature::from_bytes(&delegation.sig);

        // enforce_s_lt_q = true: SUF-CMA, prevents signature malleability
        // Source: Brendel et al. 2021 "Provable Security of Ed25519"
        if verifying_key.verify_strict(&cbor_payload, &sig).is_err() {
            return VerificationResult::invalid("INVALID_SIGNATURE", &format!(
                "Ed25519 signature invalid at delegation index {}. \
                 Issuer DID: {}. \
                 This means either the delegation was tampered with after signing, \
                 or the wrong key was used to sign it.",
                i, delegation.payload.iss
            ));
        }
    }

    // B2. Verify the invocation's signature
    let cbor_inv = DagCborCodec.encode(&invocation.payload)?;
    let invoker_key = resolve_did_key(&invocation.payload.iss)?;
    let inv_sig = ed25519_dalek::Signature::from_bytes(&invocation.sig);

    if invoker_key.verify_strict(&cbor_inv, &inv_sig).is_err() {
        return VerificationResult::invalid("INVALID_INVOCATION_SIGNATURE",
            "The invocation signature is invalid. The agent's signing key \
             does not match the key for its DID.");
    }

    // ── Block C: Semantic validity ─────────────────────────────────────────

    // C1. Policy attenuation — each child policy must be at least as strict
    // as its parent. No child can loosen what a parent constrained.
    for i in 1..delegations.len() {
        let parent_pol = &delegations[i-1].payload.pol;
        let child_pol  = &delegations[i].payload.pol;

        if !policy_is_at_least_as_strict(child_pol, parent_pol) {
            return VerificationResult::invalid("POLICY_ESCALATION", &format!(
                "Delegation at index {} has a policy that is LESS restrictive \
                 than its parent at index {}. \
                 Children can only tighten policy, never loosen it. \
                 Parent policy: {:?}. Child policy: {:?}.",
                i, i-1, parent_pol, child_pol
            ));
        }
    }

    // C2. Invocation args must satisfy the leaf delegation's policy
    let leaf_pol  = &delegations.last().unwrap().payload.pol;
    let inv_args  = &invocation.payload.args;

    match evaluate_policy(leaf_pol, inv_args) {
        PolicyResult::Pass => {},
        PolicyResult::Fail(reason) => {
            return VerificationResult::invalid("POLICY_VIOLATION", &format!(
                "Invocation arguments do not satisfy the leaf delegation's policy. \
                 Failing expression: {}. \
                 Args provided: {:?}",
                reason, inv_args
            ));
        }
    }

    // C3. Command must match through the entire chain
    let root_cmd = &delegations[0].payload.cmd;
    for (i, d) in delegations.iter().enumerate() {
        if &d.payload.cmd != root_cmd && !command_is_sub_path(root_cmd, &d.payload.cmd) {
            return VerificationResult::invalid("COMMAND_MISMATCH", &format!(
                "Delegation at index {} has command {} which is not a sub-path \
                 of root command {}.",
                i, d.payload.cmd, root_cmd
            ));
        }
    }
    if &invocation.payload.cmd != root_cmd
        && !command_is_sub_path(root_cmd, &invocation.payload.cmd) {
        return VerificationResult::invalid("INVOCATION_COMMAND_MISMATCH",
            "The invocation command does not match the delegation chain's command.");
    }

    // C4. Temporal validity — check nbf and exp for every delegation + invocation
    let now = unix_timestamp();
    for (i, d) in delegations.iter().enumerate() {
        if let Some(nbf) = d.payload.nbf {
            if now < nbf {
                return VerificationResult::invalid("NOT_YET_VALID", &format!(
                    "Delegation {} is not valid until {} (now: {}). \
                     The agent attempted to use a delegation before its start time.",
                    i, nbf, now
                ));
            }
        }
        if let Some(exp) = d.payload.exp {
            if now > exp {
                return VerificationResult::expired(&format!(
                    "Delegation {} expired at {} (now: {}). \
                     The human's authorisation window has closed. \
                     Request a new delegation.",
                    i, exp, now
                ));
            }
        }
    }

    // C5. Revocation check (requires status list — Go layer fetches this)
    for delegation in delegations {
        let cid = compute_delegation_cid(&delegation.payload)?;
        if is_revoked(&cid) {
            return VerificationResult::revoked(&format!(
                "Delegation {} has been explicitly revoked by the issuer. \
                 The human withdrew this authorisation.",
                cid
            ));
        }
    }

    // ── All checks passed ──────────────────────────────────────────────────
    VerificationResult::valid(VerificationContext {
        root_principal:    delegations[0].payload.iss.clone(),
        root_type:         drs_meta(&delegations[0])
                               .and_then(|m| m.root_type.clone()),
        consent_record:    drs_meta(&delegations[0])
                               .and_then(|m| m.consent.clone()),
        regulatory:        drs_meta(&delegations[0])
                               .and_then(|m| m.regulatory.clone()),
        leaf_policy:       delegations.last().unwrap().payload.pol.clone(),
        invocation_args:   invocation.payload.args.clone(),
        chain_depth:       delegations.len(),
        session_id:        drs_meta(&delegations[0])
                               .and_then(|m| m.session_id.clone()),
    })
}
```

### 5.4 Policy Evaluation Algorithm

```rust
/// Evaluates UCAN v1.0 Policy Language expressions against invocation args.
///
/// Policy Language: Lisp-style prefix notation.
/// Selectors: JSONPath-like dot notation (".field", ".field.sub")
/// Operators: ==, !=, <, <=, >, >=, like, not, and, or, all, any
///
/// Source: UCAN v1.0.0-rc.1 specification, Policy Language section

pub fn evaluate_policy(
    policy: &[PolicyExpression],
    args: &serde_json::Value,
) -> PolicyResult {
    for expr in policy {
        match evaluate_expression(expr, args) {
            Ok(true)  => continue,   // expression satisfied
            Ok(false) => return PolicyResult::Fail(format!("{:?}", expr)),
            Err(e)    => return PolicyResult::Fail(format!("eval error: {}", e)),
        }
    }
    PolicyResult::Pass
}

fn evaluate_expression(
    expr: &PolicyExpression,
    context: &serde_json::Value,
) -> Result<bool, PolicyError> {
    match expr {
        // Equality: ["==", ".field", value]
        PolicyExpression::Eq(selector, expected) => {
            let actual = resolve_selector(selector, context)?;
            Ok(&actual == expected)
        }

        // Inequality: ["!=", ".field", value]
        PolicyExpression::Ne(selector, expected) => {
            let actual = resolve_selector(selector, context)?;
            Ok(&actual != expected)
        }

        // Numeric comparisons: ["<=", ".field", 5.00]
        PolicyExpression::Lt(selector, threshold) => {
            let val = resolve_selector_as_f64(selector, context)?;
            Ok(val < *threshold)
        }
        PolicyExpression::Lte(selector, threshold) => {
            let val = resolve_selector_as_f64(selector, context)?;
            Ok(val <= *threshold)
        }
        PolicyExpression::Gt(selector, threshold) => {
            let val = resolve_selector_as_f64(selector, context)?;
            Ok(val > *threshold)
        }
        PolicyExpression::Gte(selector, threshold) => {
            let val = resolve_selector_as_f64(selector, context)?;
            Ok(val >= *threshold)
        }

        // Glob matching: ["like", ".email", "*@example.com"]
        // Glob rules: * matches any sequence, ? matches one character
        PolicyExpression::Like(selector, pattern) => {
            let val = resolve_selector_as_str(selector, context)?;
            Ok(glob_match(pattern, &val))
        }

        // Logical NOT: ["not", [...inner_expr...]]
        PolicyExpression::Not(inner) => {
            Ok(!evaluate_expression(inner, context)?)
        }

        // Logical AND: ["and", [[expr1], [expr2], ...]]
        PolicyExpression::And(exprs) => {
            for e in exprs {
                if !evaluate_expression(e, context)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        // Logical OR: ["or", [[expr1], [expr2], ...]]
        PolicyExpression::Or(exprs) => {
            for e in exprs {
                if evaluate_expression(e, context)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        // Universal quantification: ["all", ".items", [inner_expr]]
        // True if the inner expression holds for every element of the array
        PolicyExpression::All(selector, inner) => {
            let arr = resolve_selector_as_array(selector, context)?;
            for item in &arr {
                if !evaluate_expression(inner, item)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }

        // Existential quantification: ["any", ".items", [inner_expr]]
        PolicyExpression::Any(selector, inner) => {
            let arr = resolve_selector_as_array(selector, context)?;
            for item in &arr {
                if evaluate_expression(inner, item)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Resolves a dot-notation selector against a JSON value.
/// ".field" → value["field"]
/// ".field.sub" → value["field"]["sub"]
/// "." → the value itself
fn resolve_selector(
    selector: &str,
    context: &serde_json::Value,
) -> Result<serde_json::Value, PolicyError> {
    if selector == "." {
        return Ok(context.clone());
    }
    let parts: Vec<&str> = selector.trim_start_matches('.').split('.').collect();
    let mut current = context;
    for part in &parts {
        current = current.get(part)
            .ok_or_else(|| PolicyError::SelectorNotFound(selector.to_string()))?;
    }
    Ok(current.clone())
}
```

### 5.5 Policy Attenuation Check

```rust
/// Determines if child_policy is at least as strict as parent_policy.
///
/// This is the POLA (Principle of Least Authority) enforcement.
/// In UCAN v1.0, "attenuation" means the child policy must be at least
/// as restrictive as the parent — it can add more constraints but not remove any.
///
/// The algorithm: for every parent expression, there must exist a child expression
/// that is at least as restrictive. We model this as:
///   - Same selector, same or stricter operator, same or stricter value
///
/// This is necessarily conservative. Semantic equivalence between arbitrary
/// Policy Language expressions is undecidable in general. We detect obvious
/// violations and pass the rest to runtime evaluation.

pub fn policy_is_at_least_as_strict(
    child: &[PolicyExpression],
    parent: &[PolicyExpression],
) -> bool {
    // For each parent expression, find a child expression that covers it
    for parent_expr in parent {
        let covered = child.iter().any(|child_expr|
            expression_is_at_least_as_strict(child_expr, parent_expr)
        );
        if !covered {
            return false;
        }
    }
    true
}

fn expression_is_at_least_as_strict(
    child: &PolicyExpression,
    parent: &PolicyExpression,
) -> bool {
    match (child, parent) {
        // Same selector, numeric upper bound — child must be <=  parent
        (PolicyExpression::Lte(cs, cv), PolicyExpression::Lte(ps, pv)) if cs == ps => {
            cv <= pv  // e.g. child: cost <= 2.00, parent: cost <= 5.00 ✓
        }
        (PolicyExpression::Lt(cs, cv), PolicyExpression::Lte(ps, pv)) if cs == ps => {
            cv <= pv
        }
        // Same selector, exact equality — child must equal parent
        (PolicyExpression::Eq(cs, cv), PolicyExpression::Eq(ps, pv)) if cs == ps => {
            cv == pv
        }
        // Same selector, glob — child must be a sub-pattern of parent
        (PolicyExpression::Like(cs, cp), PolicyExpression::Like(ps, pp)) if cs == ps => {
            glob_is_sub_pattern(cp, pp)
        }
        // Identical expressions — always OK
        _ => child == parent
    }
}
```

---

## 6. Policy Language — v1.0 Specification

This section shows how DRS constraint needs map to UCAN v1.0 Policy Language.
Every constraint that was a key-value pair in v2 becomes a Policy expression.

```
v2 (wrong)                         v3 UCAN v1.0 (correct)
──────────────────────────────────────────────────────────
maxCostUSD: 5.00              →    ["<=", ".estimated_cost_usd", 5.00]
piiAccessAllowed: false       →    ["==", ".pii_in_results", false]
dataClassification: ["public"]→    ["any", ".data_classes",
                                     ["or", [["==", ".", "public"]]]]
maxCallsPerSession: 20        →    ["<=", ".call_count", 20]
allowedTimeWindow: ...        →    implemented at session layer, not in pol
```

### DRS Standard Policy Vocabulary

These are the standard `args` field names that DRS tool adapters expose.
If a tool uses these names consistently, policies are portable across tools.

| Field | Type | Description |
|---|---|---|
| `.estimated_cost_usd` | number | Estimated cost of this invocation |
| `.pii_in_results` | boolean | Whether results may contain PII |
| `.data_classes` | string[] | Data classification levels accessed |
| `.call_count` | integer | Running total of calls in session |
| `.tool` | string | Specific tool being called |
| `.resource_uri` | string | Resource URI being accessed |
| `.write_access` | boolean | Whether this modifies state |

---

## 7. Human Layer — What People Actually See

### 7.1 Consent UI Translator

The most important component for end-user trust. It runs before the consent
dialog renders and converts raw UCAN policy into language a human can evaluate.

```typescript
// @drs/consent-translator/src/index.ts

interface TranslatedPolicy {
  summary: string;            // One sentence: what this agent can do
  permissions: Permission[];  // Bullet list the human reads
  restrictions: string[];     // What the agent cannot do
  riskLevel: "low" | "medium" | "high";
  humanReadableText: string;  // Full text — SHA-256 of this = policy_hash in consent
}

interface Permission {
  icon:  "tool" | "read" | "write" | "spend" | "data";
  label: string;   // e.g. "Search the web (up to 20 times)"
  limit: string;   // e.g. "Max cost: $5.00"
}

export function translatePolicy(
  cmd: string,
  pol: PolicyExpression[],
  locale: string = "en"
): TranslatedPolicy {
  const permissions: Permission[] = [];
  const restrictions: string[] = [];

  // Translate command
  const cmdLabel = translateCommand(cmd, locale);

  // Walk each policy expression and produce human text
  for (const expr of pol) {
    const translated = translateExpression(expr, locale);
    if (translated.type === "permission") permissions.push(translated.permission);
    if (translated.type === "restriction") restrictions.push(translated.text);
  }

  const summary = buildSummary(cmdLabel, permissions, locale);
  const humanReadableText = buildFullText(summary, permissions, restrictions, locale);

  return {
    summary,
    permissions,
    restrictions,
    riskLevel: assessRisk(cmd, pol),
    humanReadableText  // SHA-256 of this becomes policy_hash in DRSConsent
  };
}

function translateExpression(expr: PolicyExpression, locale: string): Translation {
  // ["<=", ".estimated_cost_usd", 5.00] → "Spend up to $5.00"
  if (expr[0] === "<=" && expr[1] === ".estimated_cost_usd") {
    return { type: "permission", permission: {
      icon: "spend",
      label: t("can_spend_up_to", locale),
      limit: formatCurrency(expr[2], locale)
    }};
  }
  // ["==", ".pii_in_results", false] → "Cannot access personal data"
  if (expr[0] === "==" && expr[1] === ".pii_in_results" && expr[2] === false) {
    return { type: "restriction", text: t("no_pii_access", locale) };
  }
  // ["==", ".tool", "web_search"] → "Use: web search"
  if (expr[0] === "==" && expr[1] === ".tool") {
    return { type: "permission", permission: {
      icon: "tool",
      label: `${t("use_tool", locale)}: ${translateToolName(expr[2], locale)}`,
      limit: ""
    }};
  }
  // Default: show raw but formatted
  return { type: "permission", permission: {
    icon: "read",
    label: formatRawExpression(expr),
    limit: ""
  }};
}
```

### 7.2 Session Manager

Tracks every active delegation for a user across all apps. The end user has one
place to see all their agent authorisations and revoke any of them.

```typescript
// @drs/session-manager/src/index.ts

interface ActiveDelegation {
  cid:           string;          // CID of the root delegation
  app_name:      string;          // Human-readable app name
  agent_name:    string;          // Human-readable agent name
  granted_at:    string;          // ISO 8601
  expires_at:    string | null;   // ISO 8601 or "Never"
  summary:       string;          // e.g. "Can search the web, spend up to $5.00"
  call_count:    number;          // How many times the agent has acted
  last_used_at:  string | null;   // ISO 8601
  status:        "active" | "expired" | "revoked";
}

interface DRSSessionManager {
  // List all delegations for the current user
  listActive(): Promise<ActiveDelegation[]>;

  // Revoke a specific delegation by its CID
  revoke(cid: string): Promise<void>;

  // Revoke all delegations from a specific app
  revokeAllFromApp(appName: string): Promise<void>;

  // Get the activity feed for a delegation
  getActivity(cid: string): Promise<AgentAction[]>;
}

interface AgentAction {
  timestamp:    string;
  tool_called:  string;
  args_summary: string;   // Human-readable, not raw args
  cost_usd:     number | null;
  result:       "success" | "policy_blocked" | "error";
}
```

The session manager is the answer to Amara's problem. It is a standalone
UI component (`@drs/session-manager-ui`) that apps embed. Every DRS root
delegation registers with the session manager via the `drs/session` field
in the meta payload.

### 7.3 Activity Feed

Every tool call that passes DRS verification emits an activity event. The
event is captured by the session manager and displayed to the user in real time.

```typescript
// Emitted by @drs/mcp-adapter after every successful tool call
interface DRSActivityEvent {
  type:          "drs:action";
  session_id:    string;
  root_cid:      string;
  timestamp:     string;
  cmd:           string;
  tool:          string | null;
  args_summary:  string;      // Sanitised: no raw data, just what happened
  cost_usd:      number | null;
  policy_result: "pass" | "blocked";
  block_reason?: string;      // If blocked, what policy expression triggered
}
```

---

## 8. Developer Layer — DX and Tooling

### 8.1 Human-Readable Error System

Every error from `verifyChain()` carries three things: a code (for programmatic
handling), a human message (for debugging), and a suggested fix.

```typescript
// @drs/core/src/errors.ts

interface DRSError {
  code:       DRSErrorCode;
  message:    string;   // Complete English explanation — what went wrong
  suggestion: string;   // What the developer should do about it
  context?:   Record<string, unknown>; // CIDs, DIDs, values involved
}

const ERRORS: Record<DRSErrorCode, Omit<DRSError, "code" | "context">> = {
  EMPTY_BUNDLE: {
    message: "The chain bundle contains no delegations.",
    suggestion: "Build the bundle with DRS.buildBundle([rootDelegation, ...subDelegations])."
  },
  CHAIN_BREAK: {
    message: "A delegation's parent CID does not match the computed CID of the previous delegation.",
    suggestion: "Ensure delegations are ordered root-to-leaf in the bundle array. " +
                "Check that parent delegations are not modified after sub-delegations reference them."
  },
  INVALID_SIGNATURE: {
    message: "An Ed25519 signature failed verification.",
    suggestion: "The delegation may have been tampered with after signing. " +
                "Re-issue the delegation from the original issuer. " +
                "Ensure the CBOR encoding is deterministic — use @ipld/dag-cbor."
  },
  POLICY_ESCALATION: {
    message: "A child delegation has a less restrictive policy than its parent.",
    suggestion: "Children can only tighten policy, never loosen it. " +
                "Check that cost limits, tool restrictions, and other constraints " +
                "in the sub-delegation are equal or stricter than in the parent."
  },
  POLICY_VIOLATION: {
    message: "The invocation arguments do not satisfy the delegation's policy.",
    suggestion: "Check the policy expressions in the leaf delegation against " +
                "the args being passed in the invocation. " +
                "Use DRS.explainPolicy(delegation, args) for a step-by-step evaluation trace."
  },
  EXPIRED: {
    message: "A delegation in the chain has expired.",
    suggestion: "Request a new delegation from the human via the capability negotiation flow. " +
                "See DRS.requestCapabilityUpgrade()."
  },
  REVOKED: {
    message: "A delegation has been explicitly revoked by its issuer.",
    suggestion: "The human withdrew this authorisation. Request a new delegation."
  },
  INVOKER_MISMATCH: {
    message: "The invocation issuer does not match the leaf delegation's audience.",
    suggestion: "The agent creating the invocation must be the same DID that " +
                "received the leaf delegation. Check that the right agent key is signing."
  },
  UNRESOLVABLE_DID: {
    message: "A DID in the chain cannot be resolved to a public key.",
    suggestion: "For did:key DIDs, check the base58btc encoding is valid. " +
                "For did:web DIDs, check the DID document is accessible at the well-known URL."
  }
};
```

### 8.2 CLI Verifier

```bash
# Install
npm install -g @drs/cli

# Verify a bundle from a file
drs verify bundle.json

# Output:
# ✓ Chain structure: 2 delegations, root → leaf
# ✓ Signatures: all valid (Ed25519)
# ✓ Policy attenuation: each delegation tightens or maintains parent policy
# ✓ Temporal validity: all delegations within valid window
# ✗ REVOKED: Delegation bafyaaa... was revoked at 2026-03-24T11:00:00Z

# Explain a policy against test args
drs policy explain delegation.json '{"tool":"web_search","estimated_cost_usd":3.50}'

# Output (expression-by-expression):
# [1/3] ["==", ".tool", "web_search"]  →  "web_search" == "web_search"  ✓
# [2/3] ["<=", ".estimated_cost_usd", 5.00]  →  3.50 <= 5.00  ✓
# [3/3] ["==", ".pii_in_results", false]  →  arg not provided  ✗ FAIL
#
# Suggestion: Add pii_in_results: false to your invocation args

# Translate a delegation's policy to human language
drs consent translate delegation.json --locale en-GB

# Output:
# Summary: Agent can search the web with a $5.00 budget
# Permissions:
#   - Use tool: web search
#   - Spend up to: $5.00
# Restrictions:
#   - Cannot access personal data
```

### 8.3 Online Playground

`delegationreceipt.org/playground` — a browser tool where developers paste a
JSON bundle and receive:
- Visual chain diagram (root → leaf with signers)
- Expression-by-expression policy evaluation against test args
- "What would fail?" mode — try different arg values and see which policy blocks
- CBOR/JSON toggle — see the actual encoded bytes

---

## 9. Protocol Adapters

### 9.1 MCP Adapter — v1.0 Correct

In UCAN v1.0, the agent sends BOTH the delegation bundle AND the invocation.
The adapter verifies both. The old header `X-DRS-Bundle` becomes two headers:

```
X-DRS-Delegations: <base64url(CBOR([delegation_0, delegation_1, ...]))>
X-DRS-Invocation:  <base64url(CBOR(invocation))>
```

```typescript
// @drs/mcp-adapter/src/index.ts

import { verifyChain, DRSChainBundle } from '@drs/core-wasm';

export function drsMiddleware(opts: DRSMiddlewareOptions) {
  return async (req: MCPRequest, ctx: MCPContext, next: () => Promise<void>) => {

    const dlgHeader = req.headers?.['x-drs-delegations'];
    const invHeader = req.headers?.['x-drs-invocation'];

    if (!dlgHeader || !invHeader) {
      if (opts.onMissing === 'reject') {
        throw new DRSError('MISSING_ENVELOPE',
          'DRS requires both X-DRS-Delegations and X-DRS-Invocation headers.',
          'Build the bundle with DRS.buildBundle() and attach both headers.'
        );
      }
      return next(); // 'warn' or 'skip' mode
    }

    const bundle: DRSChainBundle = {
      delegations: decodeCBOR(base64urlDecode(dlgHeader)),
      invocation:  decodeCBOR(base64urlDecode(invHeader))
    };

    const result = await verifyChain(bundle);

    if (!result.valid) {
      const err = result.error;
      if (opts.onFailure === 'reject') {
        throw new DRSVerificationError(err.code, err.message, err.suggestion);
      }
      ctx.drsWarning = err;
      return next();
    }

    // Attach full context to the handler
    ctx.drs = result.context;

    // Emit activity event for session manager
    emitActivityEvent({
      type: "drs:action",
      session_id: result.context.sessionId ?? "unknown",
      root_cid: computeDelegationCid(bundle.delegations[0]),
      timestamp: new Date().toISOString(),
      cmd: bundle.invocation.payload.cmd,
      tool: bundle.invocation.payload.args?.tool ?? null,
      args_summary: summariseArgs(bundle.invocation.payload.args),
      cost_usd: bundle.invocation.payload.args?.estimated_cost_usd ?? null,
      policy_result: "pass"
    });

    return next();
  };
}
```

---

## 10. Storage Architecture — Mandatory Tiers

v2 said "optionally store to IPFS." That is wrong for any regulated deployment.

### 10.1 Storage Tiers

| Tier | Trigger | Storage | Retention | Retrieval guarantee |
|---|---|---|---|---|
| 0 — Session | All delegations | Agent session memory | Session duration | Immediate, no network |
| 1 — Ephemeral | Default | IPFS local node | 48 hours | Best effort |
| 2 — Durable | `retention_days > 0` in meta | IPFS + pinning service (Pinata/Web3.Storage) | As specified | Guaranteed via pinning |
| 3 — Compliant | EU AI Act high-risk, HIPAA, SOX | Pinned IPFS + Monad anchor | Framework-mandated minimum | On-chain CID proves content existed |
| 4 — Archival | `retention_days > 1825` (5yr+) | S3-compatible + Monad | 7 years (SOX) | S3 SLA + on-chain verification |

### 10.2 Mandatory Storage Policy

```typescript
// @drs/storage/src/policy.ts

export function determineStorageTier(
  delegation: UCANDelegationEnvelope
): StorageTier {
  const meta = delegation.payload.meta?.drs as DRSMeta | undefined;
  const regulatory = meta?.['drs/regulatory'];

  if (!regulatory) return StorageTier.Ephemeral;

  const { frameworks, retention_days } = regulatory;

  if (frameworks.includes('sox') || frameworks.includes('hipaa')) {
    return StorageTier.Archival;  // 7-year minimum
  }
  if (frameworks.includes('eu-ai-act-art14') && regulatory.risk_level === 'high') {
    return StorageTier.Compliant; // On-chain anchor required
  }
  if (retention_days > 0) {
    return StorageTier.Durable;
  }
  return StorageTier.Ephemeral;
}

export async function storeWithPolicy(
  delegation: UCANDelegationEnvelope
): Promise<StorageReceipt> {
  const tier = determineStorageTier(delegation);
  const cbor  = DagCborCodec.encode(delegation.payload);
  const cid   = computeDelegationCid(delegation.payload);

  switch (tier) {
    case StorageTier.Ephemeral:
      await ipfsLocal.add(cbor);
      return { cid, tier, pinned: false };

    case StorageTier.Durable:
      await ipfsLocal.add(cbor);
      await pinningService.pin(cid);   // Pinata/Web3.Storage API
      return { cid, tier, pinned: true };

    case StorageTier.Compliant:
      await ipfsLocal.add(cbor);
      await pinningService.pin(cid);
      const txHash = await monadRegistry.anchorChain(cidToBytes32(cid));
      return { cid, tier, pinned: true, onChainTx: txHash };

    case StorageTier.Archival:
      await ipfsLocal.add(cbor);
      await pinningService.pin(cid);
      await s3Client.putObject({ bucket: archiveBucket, key: cid.toString(), body: cbor });
      const tx = await monadRegistry.anchorChain(cidToBytes32(cid));
      return { cid, tier, pinned: true, s3Key: cid.toString(), onChainTx: tx };
  }
}
```

---

## 11. Language and Runtime Architecture

### 11.1 The Stack — Each Language Does Its Job

```
Layer              Language    Why
──────────────────────────────────────────────────────────────────────────
Crypto core        Rust        No GC, stack-allocated byte arrays,
                               constant-time ops, CBOR/IPLD native,
                               compiles to WASM (same source, browser+edge)

Verification       Go          Goroutines handle 10k concurrent verifications.
middleware                     Predictable 1-2ms GC vs V8's 50-1500ms pauses.
                               net/http, CBOR libraries, LRU cache, sync.Once.

Developer SDK      TypeScript  Low-frequency (issuance, not verification).
                               Developers live in npm. The WASM module handles
                               all crypto — TS is only the API wrapper.

Consent UI         TypeScript  React component. No crypto here.
Session manager    TypeScript  React component. REST API to Go backend.

Solidity (Monad)   Solidity    EVM requirement. No alternative.
```

### 11.2 CBOR Dependencies (Corrected From v2)

```toml
# Rust Cargo.toml — replaces serde-json-canonicalizer from v2
[dependencies]
libipld          = "0.16"   # IPLD implementation, dag-cbor codec
libipld-cbor     = "0.16"   # dag-cbor specifically
ed25519-dalek    = "2.1"    # RFC 8032 Pure EdDSA, SUF-CMA enforced
sha2             = "0.10"   # SHA-256 for multihash
cid              = "1.0"    # CIDv1 generation
multihash        = "0.19"   # Multihash encoding
subtle           = "2.5"    # Constant-time comparisons
wasm-bindgen     = "0.2"    # WASM compilation target
```

```go
// Go go.mod — replaces previous naive JSON approach
require (
    github.com/ipld/go-ipld-prime      v0.21.0  // IPLD for Go
    github.com/fxamacker/cbor/v2       v2.6.0   // CBOR encode/decode
    github.com/multiformats/go-cid     v0.4.1   // CIDv1
    github.com/hashicorp/golang-lru/v2 v2.0.7   // LRU cache for DID keys
    golang.org/x/crypto                v0.21.0  // ed25519 stdlib
)
```

```json
// TypeScript package.json
{
  "dependencies": {
    "@drs/core-wasm":       "*",    // Rust WASM module (crypto + verification)
    "@ipld/dag-cbor":       "^9",   // CBOR encoding in JS
    "multiformats":         "^13",  // CID, multihash
    "uint8arrays":          "^5"    // Uint8Array utilities
  }
}
```

### 11.3 Memory Profile at Scale

| Component | Memory | Bound mechanism |
|---|---|---|
| DID LRU cache (Go, 10k entries) | ~640KB | Hard cap — LRU eviction |
| Status list cache (single pointer) | ~2–16KB | One copy at a time |
| Per-request working memory (n=5 chain) | ~15KB | Stack in Rust, freed on return |
| CBOR decode buffer (per request) | ~4KB | Arena allocator, reused |
| In-flight requests (10k/sec, 0.8ms) | ~3MB | Predictable, no growth |
| **Total steady state** | **~4MB** | Does not grow over time |

---

## 12. Capability Negotiation Protocol

This was entirely missing from v1 and v2. It answers the agent runtime's need:
"I need capability X but only have Y — what do I do?"

### 12.1 The Four Cases

```
Case 1: Agent has sufficient capability
  → Proceed with invocation. No negotiation needed.

Case 2: Agent has insufficient capability (new tool needed)
  → Agent sends CAPABILITY_REQUEST to session manager
  → Session manager notifies human via activity feed
  → Human approves/denies in the consent UI
  → If approved: new sub-delegation issued, session updated
  → Agent retries with new delegation

Case 3: Delegation is expired mid-task
  → Same as Case 2, but with a RENEWAL_REQUEST flag
  → Human sees: "Research Agent's authorisation expired. Renew?"
  → Human clicks Renew: new delegation issued with fresh expiry
  → Agent continues from where it stopped

Case 4: Capability denied (human says no or is unavailable)
  → Agent completes as much of the task as possible within current capability
  → Returns partial result with explanation: "Could not access X — not authorised"
  → Does NOT fail silently. Does NOT proceed anyway.
```

### 12.2 Negotiation Message Types

```typescript
// Messages the agent runtime sends to the session manager

type NegotiationMessage =
  | {
      type: "CAPABILITY_REQUEST";
      session_id: string;
      root_cid: string;
      requested_cmd: string;
      requested_pol: PolicyExpression[];
      reason: string;        // Human-readable: "Task requires sending an email"
      urgency: "blocking" | "optional";
    }
  | {
      type: "RENEWAL_REQUEST";
      session_id: string;
      expired_cid: string;
      suggested_ttl_seconds: number;
      work_remaining: string; // Human-readable: "3 of 10 research steps complete"
    };

// Responses the session manager sends back

type NegotiationResponse =
  | { type: "APPROVED"; new_delegation: UCANDelegationEnvelope }
  | { type: "DENIED";   reason: string }
  | { type: "DEFERRED"; poll_after_seconds: number };
```

---

## 13. Security Model

### 13.1 Threat Table

| Threat | What can go wrong | DRS mitigation | Residual risk |
|---|---|---|---|
| Forged delegation | Attacker creates fake root delegation | Ed25519 EUF-CMA: forgery requires discrete log on edwards25519 | Private key theft |
| Policy escalation | Child claims looser policy than parent | `policy_is_at_least_as_strict()` at issuance + verification | Semantic escalation within stated policy |
| Chain injection | Attacker inserts fake intermediate | CBOR CID linking — modification changes CID, breaks children | None — structural |
| Replay after revocation | Old (valid-sig) delegation re-used | Bitstring Status List check (step C5) | Stale cache window (up to 5 min) |
| CBOR malleability | Different CBOR representations of same data produce different CIDs | RFC 8949 §4.2 deterministic encoding enforced in `libipld` | Implementation bugs in non-conforming libraries |
| Signing oracle attack | Adversary calls sign() with arbitrary messages | DRS spec: signing is internal only, never exposed as API | Library misuse by implementer |
| Status list compromise | Attacker marks active delegation as revoked (DoS) | Status list is a signed VC — tampering breaks its signature | Registry key compromise → Monad fallback |
| Session fixation | Attacker reuses a session_id from a different user | session_id is bound to the root delegation CID | Cross-session attack requires CID collision |

### 13.2 The CBOR Malleability Problem

This is new to v3 and was not a concern in v2 (which used JSON + JCS).

CBOR has multiple valid encodings for some values (e.g. integers can use 1, 2, or
4 bytes). If two implementations encode the same payload with different byte representations,
they compute different CIDs. This breaks the chain — a delegation CID computed by
library A will not match the same delegation's CID computed by library B.

**The fix:** All DRS implementations MUST use deterministic CBOR encoding as defined in
RFC 8949 §4.2. The `libipld` crate and `@ipld/dag-cbor` both implement this.
The CLI verifier includes a "malleability check" that re-encodes a received delegation
and confirms the CID matches — this catches non-conforming implementations.

---

## 14. Scalability Architecture

### 14.1 Horizontal Scalability

`verifyChain()` in Rust is completely stateless. It takes bytes in, returns a result.
No locks, no shared state, no database calls for the crypto path. Scale horizontally
without coordination. The Go middleware layer holds only:
- LRU DID cache (hard-bounded, per process)
- Status list pointer (single pointer replaced atomically on refresh)

### 14.2 Verification Latency Budget

| Operation | Per-delegation cost | Source |
|---|---|---|
| CBOR decode (libipld) | ~0.05ms | libipld benchmarks |
| SHA-256 + CID check | ~0.003ms | Hardware SHA-NI |
| Ed25519 verify (dalek 2.x) | ~0.05ms | ~20k ops/sec single core |
| Policy evaluation (n=5 exprs) | ~0.01ms | Linear in expression count |
| DID LRU lookup (Go) | ~0.001ms | Hash table |
| Status list check (bitstring) | ~0.001ms | Bit index |
| **Per delegation total** | **~0.12ms** | |
| **n=5 chain + invocation** | **~0.72ms** | 6 items × 0.12ms |
| **n=10 chain + invocation** | **~1.32ms** | 11 items × 0.12ms |

This is a 5× improvement over v2 estimates and eliminates V8 GC variance entirely.

---

## 15. On-Chain Registry — Monad

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// DRSRevocationRegistry
///
/// Stores revocation records for DRS delegations.
/// Input: keccak256(abi.encodePacked(cid_string))
/// where cid_string is the base32-encoded CIDv1 string, e.g. "bafyaaa..."
///
/// One-way: revocation is permanent and cannot be undone.
/// This is intentional — revocation must be irrefutable for regulatory purposes.

contract DRSRevocationRegistry {

    // delegationHash → revocation timestamp (0 = active)
    mapping(bytes32 => uint256) public revocations;

    event DelegationRevoked(
        bytes32 indexed delegationHash,
        address indexed revoker,
        uint256 indexed timestamp
    );

    function revokeDelegation(bytes32 delegationHash) external {
        require(revocations[delegationHash] == 0, "DRS: already revoked");
        revocations[delegationHash] = block.timestamp;
        emit DelegationRevoked(delegationHash, msg.sender, block.timestamp);
    }

    function revokeChain(bytes32[] calldata hashes) external {
        uint256 ts = block.timestamp;
        for (uint256 i = 0; i < hashes.length; i++) {
            if (revocations[hashes[i]] == 0) {
                revocations[hashes[i]] = ts;
                emit DelegationRevoked(hashes[i], msg.sender, ts);
            }
        }
    }

    function isRevoked(bytes32 h) external view returns (bool, uint256) {
        uint256 ts = revocations[h];
        return (ts != 0, ts);
    }

    /// Computes the hash used for registration, matching the off-chain computation.
    /// Input: CID string as bytes, e.g. abi.encodePacked("bafyaaa...")
    function hashCID(string calldata cidStr) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(cidStr));
    }
}
```

---

## 16. Implementation Roadmap

### Phase 1 — Core (Months 1–4)

- [ ] Rust core: CBOR encoding, CID computation, Ed25519 sign/verify, Policy Language evaluator
- [ ] Compile to WASM via `wasm-pack`
- [ ] Go middleware: `verifyChain()`, LRU DID cache, status list cache with `sync.Once`
- [ ] TypeScript SDK wrapping WASM: `issueRootDelegation`, `issueSubDelegation`, `buildBundle`
- [ ] DX error system with human messages and suggestions
- [ ] 300+ test vectors including CBOR malleability cases
- [ ] CLI: `drs verify`, `drs policy explain`, `drs consent translate`
- [ ] UCAN v1.0.0-rc.1 interoperability test against `ucanto` library

### Phase 2 — Human and Developer Layer (Months 4–8)

- [ ] Consent UI translator component (`@drs/consent-translator`)
- [ ] Session manager API + React UI (`@drs/session-manager-ui`)
- [ ] Activity feed emitter + WebSocket stream
- [ ] Online playground at `delegationreceipt.org/playground`
- [ ] MCP adapter (`@drs/mcp-adapter`) — v1.0 envelope format
- [ ] A2A adapter (`@drs/a2a-adapter`)
- [ ] Capability negotiation protocol (`@drs/negotiation`)
- [ ] OpenClaw plugin

### Phase 3 — Storage and Compliance (Months 8–18)

- [ ] Mandatory storage policy (`@drs/storage`)
- [ ] Pinning service integration (Pinata + Web3.Storage)
- [ ] `DRSRevocationRegistry.sol` deployed to Monad mainnet
- [ ] S3-compatible archival adapter
- [ ] Audit export API (EU AI Act, HIPAA, SOX formats)
- [ ] `did:monad` DID method spec

### Phase 4 — Standardisation (Year 2+)

- [ ] Submit to UCAN Working Group as DRS Profile proposal
- [ ] W3C CCG community group proposal
- [ ] Linux Foundation governance model
- [ ] Reference implementations: Go, Python, Rust CLI
- [ ] EU AI Act compliance guidance document

---

## 17. What DRS Does Not Solve

Precision matters for a standard. These are explicit non-goals.

- **Behavioural confinement** — tracking every downstream sub-delegation in real time requires a centralised registry, which contradicts the decentralised design
- **Semantic capability enforcement** — if an agent has `/mcp/call` with a benign policy, it can call a tool with harmful queries. Policy evaluates structure, not intent.
- **Agent authentication** — confirming that an agent DID is operated by a trustworthy party is a reputation/trust registry problem, not a delegation problem
- **Post-compromise recovery** — delegations signed before a key was compromised cannot be retroactively invalidated except by revocation, which only prevents future use
- **Quantitative privacy** — chain bundles are readable by any party that holds them. BBS+ selective disclosure is Phase 3 research, not v3 spec

---

*Research sources:*
*— UCAN v1.0.0-rc.1 specification (uploaded March 2026)*
*— Brendel, Cremers, Jackson, Zhao: "Provable Security of Ed25519" — IACR 2020/823*
*— Grierson, Chalkias, Buchanan: "Double Public Key Signing Oracle Attack" — arXiv:2308.15009*
*— W3C Data Integrity EdDSA Cryptosuites v1.0 — W3C Recommendation May 2025*
*— UCAN Delegation Spec — ucan-wg/spec v0.10.0 (for backward compat context)*
*— IPLD dag-cbor specification — ipld.io*
*— RFC 8949: CBOR Deterministic Encoding (§4.2)*
*— RFC 8032: Edwards-Curve Digital Signature Algorithm*
*— W3C Bitstring Status List v1.0*

*— Okey, March 2026*
