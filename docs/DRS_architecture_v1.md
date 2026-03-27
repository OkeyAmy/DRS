# Delegation Receipt Standard (DRS) — Architecture v2
### Corrected, Research-Grounded, Interaction-Complete

**Version:** 0.2.0  
**Status:** Architecture Proposal — Revised  
**Author:** Okey  
**Date:** March 2026  

> **Correction Notice:** v1 of this document contained three false positives.  
> They are documented explicitly in §1 before we build anything.  
> Every algorithm in this version cites the paper it comes from.

---

## Table of Contents

1. [Corrections to v1 — False Positives Named](#1-corrections-to-v1--false-positives-named)
2. [What DRS Actually Is (Repositioned Honestly)](#2-what-drs-actually-is-repositioned-honestly)
3. [Prior Art We Build ON (Not Around)](#3-prior-art-we-build-on-not-around)
4. [Cryptographic Foundations — Research-Grounded](#4-cryptographic-foundations--research-grounded)
5. [Data Model](#5-data-model)
6. [Chain Linking — Hash Chain, Not Binary Merkle Tree](#6-chain-linking--hash-chain-not-binary-merkle-tree)
7. [Core Algorithms — With Sources](#7-core-algorithms--with-sources)
8. [Capability Attenuation — POLA Formally Defined](#8-capability-attenuation--pola-formally-defined)
9. [Revocation Architecture](#9-revocation-architecture)
10. [Interaction Flows — How Developers Actually Use This](#10-interaction-flows--how-developers-actually-use-this)
11. [System Architecture — Full Stack](#11-system-architecture--full-stack)
12. [Protocol Adapters](#12-protocol-adapters)
13. [On-Chain Registry (Monad)](#13-on-chain-registry-monad)
14. [Security Model — Threat by Threat](#14-security-model--threat-by-threat)
15. [Scalability Architecture](#15-scalability-architecture)
16. [Implementation Roadmap](#16-implementation-roadmap)
17. [What DRS Does Not Solve](#17-what-drs-does-not-solve)
18. [Open Research Questions](#18-open-research-questions)

---

## 1. Corrections to v1 — False Positives Named

This section is not optional reading. Every serious architecture document must be honest about what it got wrong. These are the three false positives in v1.

---

### False Positive 1 — "We Are Inventing Delegation Chains"

**What v1 claimed:** A novel data model for delegation chains with DIDs, capability scoping, and revocation.

**What the research actually shows:**

UCAN (User Controlled Authorization Network) — `ucan.xyz/specification` — already defines exactly this. UCAN is a trustless, secure, local-first, user-originated, distributed authorization scheme providing public-key verifiable, delegable, expressive, openly extensible capabilities. UCANs achieve public verifiability with late-bound certificate chains and principals represented by decentralized identifiers (DIDs).

ZCAP-LD (Authorization Capabilities for Linked Data) — W3C CCG draft — also defines this. ZCAP-LD is closely related to UCAN. The primary differences are in formatting, addressing by URL instead of CID, the mechanism of separating invocation from authorization, and single versus multiple proofs.

**The honest position:** DRS does not invent delegation chains. DRS is a **UCAN Profile** — a constrained, extended application of UCAN for the specific problem of agentic accountability with human-consent records and regulatory compliance metadata. We build ON UCAN, not alongside it.

---

### False Positive 2 — "Binary Merkle Tree for Chain Integrity"

**What v1 claimed:** A binary Merkle tree (Bitcoin-style, with last-node duplication for odd counts) is needed to make the receipt chain tamper-evident.

**Why this is wrong — two reasons:**

**Reason A — The structure is not a tree.** A delegation chain is linear: A → B → C → D. A binary Merkle tree is designed for parallel leaf nodes (transactions in a block, files in a directory). Applying a tree structure to a linear sequence adds computation and complexity with no benefit. The Merkle root of a linear chain is just the hash of the last node — identical to what a plain hash chain gives you.

**Reason B — The Bitcoin duplication is a known vulnerability.** The `last_leaf = last_leaf * 2` trick used in Bitcoin-style Merkle trees has a documented CVE (CVE-2012-2459). Duplicating the last node allows a valid Merkle root to correspond to two different trees of different sizes. Including this in v1 without noting the vulnerability was wrong.

**The correct structure:** A hash chain, as used by UCAN via IPLD Content Identifiers (CIDs). CIDs provide a common language for referring to content-addressed data; IPLD defines common formats as formal schemas for structuring and communicating content-addressed data structures — systems that can parse IPLD data and CIDs can reference content from other systems.

In a CID-linked chain: each delegation's `id` IS the SHA-256 (via SHA2-256 multihash) of its content. The `proof` field contains the CID of the parent delegation. If you modify any delegation, its CID changes, breaking every child that references it. This is tamper-evident, simpler, and the approach UCAN actually uses.

---

### False Positive 3 — "Ed25519 Is Simply Secure"

**What v1 claimed:** Ed25519 is secure, fast, and deterministic. Full stop.

**What the research actually shows:**

Surprisingly, full proofs of any security properties have never been given for Ed25519 in the original publications. The original papers focused on efficiency of computation and do not contain a precise statement on the security property offered by the scheme. Because the scheme is said to be constructed via the Fiat-Shamir transform, it should follow that Ed25519-Original at least provides EUF-CMA security, but full details were never provided.

The first formal proofs came in Brendel, Cremers, Jackson, and Zhao (BCJZ), "The Provable Security of Ed25519: Theory and Practice" (IACR 2020/823, published IEEE S&P 2021). Their findings, which we must acknowledge:

- Ed25519 **does** provide EUF-CMA security (Existential Unforgeability under Chosen Message Attack) — signatures cannot be forged. This is the property DRS actually requires.
- The BCJZ proof uses a random oracle model for the hash function. SHA-512 is not a random oracle, which means the reduction has limits.
- There are **five distinct variants** of Ed25519 in deployment (Ed25519-Original, Ed25519ctx, Ed25519ph, the RFC 8032 version, and the FIPS 186-5 version). They have subtly different security properties.

Additionally, a 2023 paper (Grierson, Chalkias, Buchanan — arXiv:2308.15009) describes the **Double Public Key Signing Function Oracle Attack**: if an implementation exposes the Ed25519 signing function as a public oracle (callable by a third party), an attacker can recover the private key. This affects some library APIs, not the algorithm itself.

**The honest position for DRS:** We use Ed25519 as defined in RFC 8032, specifically the "Pure Ed25519" variant (no pre-hashing, no context), which corresponds to the FIPS 186-5 approved variant. This approach is accepted by the U.S. National Institute of Standards in FIPS-186-5 and meets U.S. Federal Information Processing requirements when using cryptography to secure digital information. We acknowledge the signing oracle attack and specify that DRS implementations MUST NOT expose the signing function as a callable API to external parties.

---

## 2. What DRS Actually Is (Repositioned Honestly)

With the false positives corrected, here is the honest definition:

**DRS is a UCAN Profile with three additions that UCAN does not provide:**

| Gap in UCAN | What DRS Adds |
|---|---|
| No concept of human consent evidence | `humanConsentRecord` field — captures how and when a human approved the delegation |
| No regulatory compliance metadata | `regulatoryContext` field — EU AI Act Article 14, HIPAA, SOX citations per delegation |
| No MCP/A2A native adapters | Protocol adapters for the current agent layer |
| No on-chain revocation for high-stakes actions | Monad-anchored revocation registry with agent-specific semantics |
| No cost/budget constraints in standard vocabulary | Standard `constraints` vocabulary including `maxCostUSD`, `dataClassification`, `piiAllowed` |

Everything else — the chain structure, the DID-based identity, the capability attenuation, the expiry semantics — we inherit from UCAN and do not re-implement.

**This is not a weakness. It is the right call.** UCAN has already gone through the W3C CCG process. Building on it means we inherit its interoperability, its existing implementations, and its existing community. DRS adds the accountability layer that the agentic web specifically needs and that UCAN was never designed for.

---

## 3. Prior Art We Build ON (Not Around)

### UCAN (User Controlled Authorization Network)
**Spec:** `ucan.xyz/specification` | **Working Group:** `github.com/ucan-wg/spec`  
**What we inherit:** Chain structure, CID-based content addressing, DID identity, capability delegation semantics, attenuation rules, JWT-compatible encoding.  
**Key concept from UCAN we use directly:** The principle of least authority SHOULD be used when delegating — minimizing the amount of time that a capability is valid for and reducing authority to the bare minimum required for the delegate to complete their task.

### ZCAP-LD (Authorization Capabilities for Linked Data)
**Spec:** `w3c-ccg.github.io/zcap-spec` | **W3C CCG Work Item**  
**What we inherit:** The `invoker`/`controller` model for capabilities, caveat representation, the distinction between delegation and invocation.  
**Key insight that resolves the v1 confusion about VCs vs capabilities:** Use Verifiable Credentials in a reasoning system (most commonly human reasoning) as a path to make judgements about whether to hand an entity a set of initial capabilities. Use capabilities (ZCAP-LD) as the mechanism to grant and exercise authority through computing systems. DRS uses VCs for the human consent record (identity claim: "this human approved this") and UCAN-style capabilities for the actual authority chain. These are different things.

### W3C Data Integrity EdDSA Cryptosuites v1.0
**Spec:** `w3.org/TR/2025/REC-vc-di-eddsa-20250515`  
**W3C Recommendation, May 2025**  
**What we inherit:** The `eddsa-rdfc-2022` proof suite — Ed25519 signing over RDF-normalized content. The cryptosuite property of the proof MUST be `eddsa-rdfc-2022` or `eddsa-jcs-2022`. We use `eddsa-jcs-2022` (JCS = JSON Canonicalization Scheme, RFC 8785) for its simpler implementation profile.

### W3C Bitstring Status List v1.0
**Spec:** `w3.org/TR/vc-bitstring-status-list`  
**What we inherit:** The entire revocation mechanism.

### IPLD / CIDs
**Spec:** `ipld.io` | **Multiformat spec for CIDs**  
**What we inherit:** Content-addressed identifiers for receipt linking.

---

## 4. Cryptographic Foundations — Research-Grounded

### 4.1 The Signing Algorithm: Ed25519 (RFC 8032 Pure Variant)

**What Ed25519 is, mechanically:**

Ed25519 operates over edwards25519, a twisted Edwards curve defined by:
```
-x² + y² = 1 - (121665/121666) · x²y²
```
over the prime field `F_p` where `p = 2^255 - 19`.

The base point `G` has order `q = 2^252 + 27742317777372353535851937790883648493`, a large prime.

A private key is a 32-byte random seed. The actual signing scalar is derived as:
```
(a, prefix) = SHA-512(seed)
a = clamp(a[0:32])     # clamp sets/clears specific bits to ensure cofactor safety
```

**Signing** a message `M` with private key `a` and public key `A = a·G`:
```
1. r = SHA-512(prefix || M) mod q        # deterministic nonce — NO random number generator needed
2. R = r·G                               # nonce commitment point
3. S = (r + SHA-512(R || A || M) · a) mod q  # signature scalar
4. signature = (R_compressed, S)         # 64 bytes total
```

**Verification** given `(R, S)`, message `M`, public key `A`:
```
Check: S·G == R + SHA-512(R || A || M)·A
```

This is the "Pure EdDSA" variant from RFC 8032 §5.1. It must be used as-is — no pre-hashing of `M`.

**Why deterministic nonce generation matters for DRS:**

In ECDSA, the nonce `k` must be random and secret. If `k` is reused or predictable, the private key is recoverable. Sony's PlayStation 3 was broken this way (same `k` for every signature). Ed25519 computes `r = SHA-512(prefix || M)` — the nonce is a deterministic hash, not a random number. This means:
- No dependency on a CSPRNG at signing time
- Two signatures on the same message are identical (this is a feature for DRS: receipts are deterministically reproducible)
- The signing oracle attack (Grierson et al., 2023) is about calling the signing function with adversary-controlled messages to extract key material — **DRS implementations MUST restrict signing to internally-generated receipt content only**

**Security properties of the RFC 8032 variant:**
- EUF-CMA: Proven by BCJZ (2021), assuming hardness of the Discrete Log problem on edwards25519 and SHA-512 modeled as a random oracle
- SUF-CMA (Strong Unforgeability): Holds when the additional check `0 ≤ S < q` is enforced. Strong unforgeability implies that an adversary not only cannot sign new messages, but also cannot find a new signature on an old message. DRS implementations MUST enforce this check.
- Malleability resistance: The `S < q` check prevents signature malleability. Without it, for any valid `(R, S)`, `(R, S + q)` is also a valid signature (since both reduce to the same value mod q). With the check, each message has exactly one valid signature per key.

**Reference implementation library for DRS:** `@noble/ed25519` v2.x (Paul Miller). Audited by Cure53, zero runtime dependencies, correct implementation of RFC 8032 Pure Ed25519 with the `S < q` check enforced.

### 4.2 Hashing: SHA-256 for Content Addressing, SHA-512 Internally in Ed25519

SHA-256 is used for:
- CID generation (via SHA2-256 multihash, producing a `bafy...` CID)
- Receipt content fingerprinting for audit logs

SHA-512 is used **internally** by Ed25519 (embedded in the algorithm above). DRS does not call SHA-512 directly — it is hidden inside the Ed25519 implementation.

**Why not BLAKE2 or BLAKE3?** BLAKE3 is faster and arguably more secure. However, SHA2-256 is what IPLD CIDs use in their `sha2-256` multihash codec, and SHA-512 is what RFC 8032 mandates internally. For interoperability with IPFS/IPLD content addressing (which DRS chains use), SHA-256 is the right choice for CIDs. If the community moves to BLAKE3 CIDs, DRS chains follow, since the multihash format is self-describing.

### 4.3 Key Identity: DIDs

DRS uses the same DID resolution model as UCAN:

```
did:key:z6Mk...    # Ed25519 key embedded in the DID itself
                   # z prefix = base58btc multibase
                   # 0xed01 multicodec prefix = Ed25519 public key type

did:web:agent.example.com   # DID document served at well-known URL
did:monad:0x...             # Phase 3: on-chain DID anchored to Monad
```

`did:key` for Ed25519: the DID IS the public key, encoded as:
```
key_bytes = ed25519_public_key  (32 bytes)
multikey  = 0xed01 || key_bytes  (34 bytes, 0xed01 = Ed25519 multicodec)
did       = "did:key:z" + base58btc(multikey)
```

Resolution requires no network call — the public key is derivable from the DID string itself. This is the zero-infrastructure option for Phase 1.

### 4.4 Content Addressing: CIDv1 with SHA2-256

Every DRS delegation is identified by its CID — the content-addressed hash of its canonical representation:

```
content_bytes = encode_dag_json(delegation_without_proof)
multihash     = 0x12 || 0x20 || SHA-256(content_bytes)
              # 0x12 = sha2-256 function code
              # 0x20 = 32 byte digest length
CID           = CIDv1(multicodec=dag-json, multihash)
              = "bafy..." (base32 encoded, CIDv1)
```

The `proof` field of each delegation contains the CID of its parent delegation. This is the UCAN approach and it is correct: modifying any delegation changes its CID, which breaks all child delegations that reference it.

---

## 5. Data Model

DRS extends the UCAN Delegation format. The key additions over baseline UCAN are:
1. `humanConsentRecord` — evidence a human approved this delegation
2. `regulatoryContext` — compliance citations
3. Standard `constraints` vocabulary
4. `rootPrincipalType` — explicit tagging of human vs automated root

```typescript
// ---- Core UCAN fields (inherited, not invented) ----
interface UCANDelegation {
  v:   "0.10.0";          // UCAN spec version
  iss: DID;               // issuer DID (who is granting this)
  aud: DID;               // audience DID (who receives this)
  att: Capability[];      // attenuated capabilities (what is granted)
  prf: CID[];             // proofs — CIDs of parent delegations
  exp: number | null;     // expiry (Unix timestamp, null = no expiry)
  nbf?: number;           // not before (Unix timestamp, optional)
  nnc?: string;           // nonce — prevents replay if needed
}

// ---- DRS Extensions (what we actually build) ----
interface DRSDelegation extends UCANDelegation {
  
  // The DRS-specific additions:
  "drs/v":    "1.0";
  
  // 1. Human consent record — who approved this and how
  "drs/consent"?: HumanConsentRecord;
  
  // 2. Root principal type — is this chain ultimately from a human or an org?
  "drs/root-type"?: "human" | "organisation" | "automated-system";
  
  // 3. Regulatory context — which compliance frameworks apply
  "drs/regulatory"?: RegulatoryContext;
  
  // 4. Standard constraints vocabulary
  "drs/constraints"?: DRSConstraints;
}

interface HumanConsentRecord {
  method:    "explicit-ui-click" | "voice-confirmation" | "hardware-key" | "biometric";
  timestamp: string;       // ISO 8601 UTC
  sessionId: string;       // links to the UI session where consent was given
  uiHash?:   string;       // SHA-256 of the rendered UI element shown to the user
                           // allows auditors to verify what the user actually saw
  locale?:   string;       // BCP 47 language tag — what language was the consent in
}

interface RegulatoryContext {
  frameworks: Array<"eu-ai-act-art14" | "hipaa" | "sox" | "pci-dss" | "gdpr">;
  riskLevel:  "minimal" | "limited" | "high" | "unacceptable";
  auditRetentionDays: number;   // how long to retain delegation evidence
}

interface DRSConstraints {
  maxCostUSD?:                   number;
  requireHumanApprovalAboveUSD?: number;
  piiAccessAllowed?:             boolean;
  dataClassification?:           Array<"public" | "internal" | "confidential" | "restricted">;
  allowedTimeWindowUTC?: {
    start: string;   // "HH:MM"
    end:   string;   // "HH:MM"
    tz:    string;   // IANA timezone name
  };
}

// ---- Capability format (UCAN-standard) ----
interface Capability {
  with: string;    // resource URI — "mcp://tools/web_search" or "a2a://tasks/*"
  can:  string;    // ability — "mcp/call" or "a2a/task/create" or "*"
  nb?:  Record<string, unknown>;  // nb = "narrowing by" — additional constraints
}
```

### 5.1 Complete Example — Human Delegates to Research Agent

```json
{
  "v":   "0.10.0",
  "drs/v": "1.0",

  "iss": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
  "aud": "did:key:z6MkjLrk73pkTkbyHnpjuiHTpPfMiRd5C7gEfELnBWRd2pim",

  "att": [
    {
      "with": "mcp://tools/web_search",
      "can":  "mcp/call",
      "nb": {
        "maxCallsPerSession": 20,
        "piiInResultsAllowed": false
      }
    },
    {
      "with": "a2a://tasks/*",
      "can":  "a2a/task/create"
    }
  ],

  "prf": [],
  "exp": 1743000600,
  "nbf": 1743000000,
  "nnc": "xK9mP2qR",

  "drs/v": "1.0",
  "drs/consent": {
    "method":    "explicit-ui-click",
    "timestamp": "2026-03-24T10:30:00Z",
    "sessionId": "sess:8f3a2b1c-4d5e-6f7a-8h9i-0j1k2l3m4n5o",
    "uiHash":    "sha256:abc123def456...",
    "locale":    "en-GB"
  },
  "drs/root-type": "human",
  "drs/regulatory": {
    "frameworks":         ["eu-ai-act-art14"],
    "riskLevel":          "limited",
    "auditRetentionDays": 730
  },
  "drs/constraints": {
    "maxCostUSD":    5.00,
    "piiAccessAllowed": false,
    "dataClassification": ["public", "internal"]
  }
}
```

The signature (using `eddsa-jcs-2022`) is added by calling the UCAN signing function with the issuer's Ed25519 private key. The resulting CID of the signed delegation becomes the proof reference in any child delegation.

---

## 6. Chain Linking — Hash Chain, Not Binary Merkle Tree

This is the correction of False Positive 2.

### 6.1 How the Chain Actually Works

Each delegation's `prf` array contains the CID(s) of its parent delegation(s). Because the CID of any delegation is the SHA-256 hash of its content, the entire chain is tamper-evident by construction.

```
Delegation_1 (root)
  iss: Human DID
  aud: Agent_1 DID
  att: [full_capability]
  prf: []
  → CID_1 = SHA-256(canonical(Delegation_1)) = "bafyaaa..."

Delegation_2 (hop 1)
  iss: Agent_1 DID
  aud: Agent_2 DID
  att: [reduced_capability]  ← POLA applied
  prf: ["bafyaaa..."]        ← CID of Delegation_1
  → CID_2 = SHA-256(canonical(Delegation_2)) = "bafybbb..."

Delegation_3 (leaf)
  iss: Agent_2 DID
  aud: Tool_server DID
  att: [minimal_capability]  ← POLA applied again
  prf: ["bafybbb..."]        ← CID of Delegation_2
  → CID_3 = SHA-256(canonical(Delegation_3)) = "bafyccc..."
```

### 6.2 Why This Is Tamper-Evident Without a Merkle Tree

If an attacker modifies Delegation_1 (the root):
- The canonical encoding of Delegation_1 changes
- SHA-256 of that encoding changes → CID_1 changes
- Delegation_2's `prf` field references the old CID_1
- Delegation_2's own CID (CID_2) was computed over content that included the old CID_1
- Therefore both CID_1 and CID_2 are now invalid
- The chain verification algorithm detects this immediately

This is exactly how Git commit history works. It does not need a Merkle tree — it is a hash chain.

### 6.3 The Chain Bundle

When an agent presents to a resource server, it sends a ChainBundle:

```typescript
interface DRSChainBundle {
  delegations: DRSDelegation[];   // ordered root-to-leaf
  root: CID;                      // CID of delegations[0]  
  leaf: CID;                      // CID of delegations[last]
}
```

The verifier only needs the bundle — no network calls required for structural verification.

---

## 7. Core Algorithms — With Sources

### 7.1 CID Computation

```python
import hashlib
import json
import struct

def compute_cid(delegation: dict) -> str:
    """
    Computes CIDv1 for a DRS delegation object.
    
    Standard: IPLD CID spec (https://github.com/multiformats/cid)
    Multihash: https://github.com/multiformats/multihash
    Multicodec: 0x0129 = dag-json
    
    The delegation MUST NOT include the proof field when computing CID
    (the proof signs over the unsigned content, and is not part of the
    identity hash — same as how a VC's id is computed before the proof
    is added). In UCAN this is standard: CID = hash of the token
    header+payload, the signature is separate.
    """
    # 1. Produce canonical JSON (RFC 8785 — JCS)
    # JCS: sort keys lexicographically, no extra whitespace, UTF-8 encoded
    canonical = json.dumps(delegation, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    # 2. SHA-256 digest
    digest = hashlib.sha256(canonical).digest()  # 32 bytes
    
    # 3. Multihash encoding: <varint function_code> <varint digest_length> <digest>
    # sha2-256 function code = 0x12
    # digest length = 32 = 0x20
    multihash = bytes([0x12, 0x20]) + digest
    
    # 4. CIDv1 bytes: <version> <codec> <multihash>
    # version = 1
    # codec = 0x0129 (dag-json), encoded as uvarint
    version_byte = bytes([0x01])
    codec_bytes  = encode_uvarint(0x0129)
    cid_bytes    = version_byte + codec_bytes + multihash
    
    # 5. Base32 encode with 'b' prefix (CIDv1 default)
    import base64
    # Note: CID uses base32 lower-case without padding
    b32 = base64.b32encode(cid_bytes).decode('ascii').lower().rstrip('=')
    return 'b' + b32

def encode_uvarint(n: int) -> bytes:
    """
    Encodes n as an unsigned varint (Protocol Buffers style).
    Used for CID codec field encoding.
    """
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n != 0:
            byte |= 0x80
        result.append(byte)
        if n == 0:
            break
    return bytes(result)
```

### 7.2 Delegation Issuance Algorithm

```python
from dataclasses import dataclass
from typing import Optional
import time, uuid

def issue_delegation(
    issuer_did:         str,
    issuer_private_key: Ed25519PrivateKey,   # @noble/ed25519 PrivKey type
    audience_did:       str,
    capabilities:       list[Capability],
    parent_delegation:  Optional[DRSDelegation],
    ttl_seconds:        int,
    consent_record:     Optional[HumanConsentRecord],
    constraints:        Optional[DRSConstraints],
    regulatory:         Optional[RegulatoryContext]
) -> DRSDelegation:
    """
    Issues a DRS delegation.
    
    Sources:
    - UCAN Delegation spec §3.2 (token construction)
    - RFC 8032 §5.1 (Ed25519 signing)
    - W3C Data Integrity EdDSA Cryptosuites v1.0 §3.2 (eddsa-jcs-2022)
    
    POLA enforcement: capabilities MUST be a subset of parent's capabilities.
    This is checked here and again during verification.
    """
    
    # Step 1: Validate capability attenuation (Principle of Least Authority)
    # Source: UCAN spec §5.2.3 "Attenuation" 
    if parent_delegation is not None:
        for cap in capabilities:
            if not is_attenuated_subset(cap, parent_delegation['att']):
                raise CapabilityEscalationError(
                    f"Capability {cap['can']} on {cap['with']} "
                    f"is not a subset of parent capabilities. "
                    f"Per POLA, delegation cannot escalate authority."
                )
    
    # Step 2: Build proof array (CIDs of parent delegations)
    proofs = []
    if parent_delegation is not None:
        proofs = [compute_cid(parent_delegation)]
    
    # Step 3: Assemble the unsigned delegation payload
    now = int(time.time())
    delegation = {
        "v":   "0.10.0",
        "drs/v": "1.0",
        "iss": issuer_did,
        "aud": audience_did,
        "att": [cap.__dict__ for cap in capabilities],
        "prf": proofs,
        "exp": now + ttl_seconds,
        "nbf": now,
        "nnc": uuid.uuid4().hex[:8]   # nonce: prevents identical tokens for replay detection
    }
    
    # Step 4: Add DRS extensions
    if consent_record:
        delegation["drs/consent"] = consent_record.__dict__
        if not parent_delegation:
            # Root delegation from a human — require explicit root type
            delegation["drs/root-type"] = "human"
    
    if constraints:
        delegation["drs/constraints"] = constraints.__dict__
    
    if regulatory:
        delegation["drs/regulatory"] = regulatory.__dict__
    
    # Step 5: Sign using eddsa-jcs-2022
    # JCS canonicalization (RFC 8785): deterministic JSON encoding
    canonical = jcs_canonicalize(delegation)  # produces UTF-8 bytes
    
    # Ed25519 signing: sign over the canonical bytes directly
    # RFC 8032 Pure EdDSA — no pre-hashing of the message
    # (SHA-512 is applied internally by the Ed25519 algorithm)
    signature_bytes = ed25519_sign(issuer_private_key, canonical)  # 64 bytes
    
    # Step 6: Attach the signature as a UCAN-style header.payload.signature
    # UCAN encodes as: base64url(header) + "." + base64url(payload) + "." + base64url(sig)
    # For DRS we additionally expose the raw JSON for human readability
    delegation["sig"] = base64url_encode(signature_bytes)
    
    return delegation
```

### 7.3 Chain Verification Algorithm

The most critical function in the entire system. Called by any resource server, MCP tool handler, or A2A executor before processing an agent action.

```python
def verify_chain(bundle: DRSChainBundle) -> VerificationResult:
    """
    Verifies a DRS chain bundle.
    
    Sources:
    - UCAN spec §6 "Validation"
    - UCAN spec §5.2.3 "Attenuation" (capability subset check)
    - RFC 8032 §5.1.7 (Ed25519 verification)
    - W3C Bitstring Status List v1.0 §4 (revocation check)
    
    Complexity: O(n) where n = chain length.
    Expected n: 1–10 for typical agentic workflows.
    """
    
    delegations = bundle['delegations']
    
    # --- Guard clauses ---
    if not delegations:
        return VerificationResult.invalid("EmptyBundle")
    
    # --- Step 1: Structural integrity check ---
    # Each delegation's CID must equal what the next delegation claims as its proof.
    # This verifies the hash chain is intact.
    for i in range(1, len(delegations)):
        computed_cid = compute_cid(delegations[i-1])
        claimed_parent_cid = delegations[i]['prf'][0]   # first proof is the direct parent
        
        if computed_cid != claimed_parent_cid:
            return VerificationResult.invalid(
                code="CHAIN_BREAK",
                detail=f"Delegation at index {i} claims parent CID {claimed_parent_cid} "
                       f"but computed CID of delegation {i-1} is {computed_cid}"
            )
    
    # --- Step 2: Cryptographic signature verification ---
    # Each delegation must be signed by the key corresponding to its `iss` DID.
    for i, delegation in enumerate(delegations):
        issuer_public_key = resolve_did_to_public_key(delegation['iss'])
        
        if issuer_public_key is None:
            return VerificationResult.invalid(
                code="UNRESOLVABLE_DID",
                detail=f"Cannot resolve DID {delegation['iss']} at chain index {i}"
            )
        
        # Reconstruct the signed content: the delegation WITHOUT the sig field
        signed_content = {k: v for k, v in delegation.items() if k != 'sig'}
        canonical = jcs_canonicalize(signed_content)
        
        signature = base64url_decode(delegation['sig'])
        
        # Ed25519 verify — Pure EdDSA, RFC 8032 §5.1.7
        # IMPORTANT: The implementation MUST check that S < q (SUF-CMA property)
        # Reference: Brendel et al. 2021 §5.3 — this check is what provides 
        # strong unforgeability over plain unforgeability
        is_valid = ed25519_verify(
            public_key=issuer_public_key,
            message=canonical,
            signature=signature,
            enforce_s_lt_q=True   # MANDATORY: enables SUF-CMA
        )
        
        if not is_valid:
            return VerificationResult.invalid(
                code="INVALID_SIGNATURE",
                detail=f"Ed25519 signature verification failed at chain index {i}. "
                       f"Issuer: {delegation['iss']}"
            )
    
    # --- Step 3: Capability attenuation check ---
    # Each delegation's capabilities must be a subset of its parent's.
    # A child cannot grant more than its parent gave it.
    for i in range(1, len(delegations)):
        parent_caps = delegations[i-1]['att']
        child_caps  = delegations[i]['att']
        
        for child_cap in child_caps:
            if not is_attenuated_subset(child_cap, parent_caps):
                return VerificationResult.invalid(
                    code="CAPABILITY_ESCALATION",
                    detail=f"Delegation at index {i} contains capability "
                           f"{child_cap['can']} on {child_cap['with']} which "
                           f"is not a subset of the parent's capabilities. "
                           f"This is a POLA violation."
                )
    
    # --- Step 4: Temporal validity ---
    now = int(time.time())
    for i, delegation in enumerate(delegations):
        if delegation.get('nbf') and now < delegation['nbf']:
            return VerificationResult.invalid(
                code="NOT_YET_VALID",
                detail=f"Delegation at index {i} is not valid until "
                       f"{delegation['nbf']} (now: {now})"
            )
        if delegation.get('exp') and now > delegation['exp']:
            return VerificationResult.expired(
                code="EXPIRED",
                detail=f"Delegation at index {i} expired at {delegation['exp']} "
                       f"(now: {now})"
            )
    
    # --- Step 5: DRS constraint check (optional, depends on resource server policy) ---
    leaf = delegations[-1]
    constraints = leaf.get('drs/constraints', {})
    # Resource servers MAY enforce constraints here.
    # Example: if this is a billing context, check maxCostUSD.
    # DRS does not enforce — it exposes. The executor enforces.
    
    # --- Step 6: Revocation check (online, optional for offline contexts) ---
    for delegation in delegations:
        cid = compute_cid(delegation)
        revocation_status = check_revocation(cid)  # bitstring status list lookup
        if revocation_status == RevocationStatus.REVOKED:
            return VerificationResult.revoked(
                code="REVOKED",
                detail=f"Delegation {cid} has been revoked"
            )
    
    # --- All checks passed ---
    return VerificationResult.valid(
        root_principal      = delegations[0]['iss'],
        root_type           = delegations[0].get('drs/root-type'),
        leaf_capabilities   = delegations[-1]['att'],
        leaf_constraints    = delegations[-1].get('drs/constraints'),
        consent_record      = delegations[0].get('drs/consent'),
        chain_depth         = len(delegations),
        regulatory_context  = delegations[0].get('drs/regulatory')
    )
```

---

## 8. Capability Attenuation — POLA Formally Defined

The Principle of Least Authority (POLA) is the core security property of capability systems. Every delegation MUST reduce or maintain authority — never increase it.

### 8.1 The `is_attenuated_subset` Function

```python
def is_attenuated_subset(child_cap: Capability, parent_caps: list[Capability]) -> bool:
    """
    Returns True iff child_cap is a valid attenuation of some capability in parent_caps.
    
    Sources:
    - UCAN Delegation spec §5.2.3
    - UCAN spec: "Each direct delegation leaves the action at the same level or diminishes it"
    - ZCAP-LD: attenuation via caveats
    
    Attenuation rules:
    1. RESOURCE: child's resource must equal or be narrower than parent's
       "mcp://tools/*"  ← parent allows all tools
       "mcp://tools/web_search"  ← child narrows to one tool (VALID)
       "a2a://tasks/*"  ← unrelated resource (INVALID — no parent covers this)
    
    2. ABILITY: child's ability must equal or be narrower than parent's
       Parent "can": "*"  → child can be anything (full authority)
       Parent "can": "mcp/call" → child can be "mcp/call" but NOT "mcp/read" or "*"
    
    3. NB (narrowing-by): child can add narrowing constraints, never remove them.
       Parent nb: {}  → child can add nb constraints freely
       Parent nb: {"maxCallsPerSession": 20}  → child can only reduce this, never increase
    """
    
    for parent_cap in parent_caps:
        
        # Check resource scope: does the parent's resource cover the child's?
        if not resource_covered_by(child_cap['with'], parent_cap['with']):
            continue   # this parent_cap doesn't cover this child_cap's resource
        
        # Check ability scope
        if not ability_covered_by(child_cap['can'], parent_cap['can']):
            continue   # this parent_cap doesn't cover this child_cap's ability
        
        # Check narrowing-by constraints: child must not relax parent's constraints
        if not nb_constraints_maintained(
            child_nb=child_cap.get('nb', {}),
            parent_nb=parent_cap.get('nb', {})
        ):
            continue   # this parent_cap's constraints are violated
        
        return True  # found a valid parent capability that covers this child capability
    
    return False  # no parent capability covers this child capability


def resource_covered_by(child_resource: str, parent_resource: str) -> bool:
    """
    Checks if parent_resource covers child_resource.
    
    Coverage rules (UCAN-compatible):
    - Exact match: "mcp://tools/web_search" covers "mcp://tools/web_search"
    - Wildcard: "mcp://tools/*" covers "mcp://tools/web_search" and "mcp://tools/anything"
    - Universal: "*" covers everything
    - No upward expansion: "mcp://tools/web_search" does NOT cover "mcp://tools/*"
    """
    if parent_resource == "*":
        return True
    if parent_resource == child_resource:
        return True
    if parent_resource.endswith("/*"):
        prefix = parent_resource[:-1]   # strip the '*', keep the '/'
        return child_resource.startswith(prefix)
    return False


def ability_covered_by(child_ability: str, parent_ability: str) -> bool:
    """
    Checks if parent_ability covers child_ability.
    
    "*" in UCAN means "top" — the full ability namespace.
    "mcp/call" is narrower than "mcp/*" which is narrower than "*".
    
    The ability hierarchy:
    "*" > "<namespace>/*" > "<namespace>/<specific-ability>"
    """
    if parent_ability == "*":
        return True
    if parent_ability == child_ability:
        return True
    if parent_ability.endswith("/*"):
        ns = parent_ability[:-2]   # strip "/*"
        return child_ability.startswith(ns + "/")
    return False


def nb_constraints_maintained(child_nb: dict, parent_nb: dict) -> bool:
    """
    Checks that child_nb does not relax any constraint in parent_nb.
    
    Relaxation means: child removes a constraint that parent requires,
    OR child sets a looser value (higher maxCalls, broader data access, etc.)
    
    The semantics of "tighter" vs "looser" are domain-specific per constraint key.
    DRS defines semantics for the standard constraint vocabulary.
    For unknown keys, we apply a conservative rule: child value must equal parent value.
    """
    for key, parent_value in parent_nb.items():
        child_value = child_nb.get(key)
        
        if child_value is None:
            # Child does not carry this constraint at all.
            # This is AMBIGUOUS — it could mean "no constraint" (looser)
            # or "constraint was removed" (violation).
            # DRS conservative rule: treat absence of a parent constraint as a violation.
            return False
        
        # For numeric upper-bound constraints: child must be <= parent
        if key in NUMERIC_UPPER_BOUND_CONSTRAINTS:  # {"maxCostUSD", "maxCallsPerSession", etc.}
            if child_value > parent_value:
                return False  # child is relaxing an upper bound — violation
        
        # For boolean "allowed" constraints: child can only be more restrictive
        if key in BOOLEAN_RESTRICTION_CONSTRAINTS:  # {"piiAccessAllowed", etc.}
            if child_value is True and parent_value is False:
                return False  # parent says NO, child says YES — violation
        
        # For classification lists: child cannot add classifications not in parent
        if key == "dataClassification":
            if not set(child_value).issubset(set(parent_value)):
                return False
    
    return True
```

---

## 10. Interaction Flows — How Developers Actually Use This

This is the section missing from v1. Three flows covering the full developer surface.

### 10.1 Flow A — Human Delegates to an Agent (UI Layer)

This is the moment the chain begins. The human is sitting at a UI.

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: User opens an agent-powered app                    │
│          App requests: "Authorise Research Agent?"           │
│          Shows: scope summary, cost limit, expiry           │
│          UI element hash is computed before display         │
└──────────────────────┬──────────────────────────────────────┘
                       │ user clicks "Authorise"
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Client SDK calls issueRootDelegation()             │
│                                                              │
│  import { DRS } from '@drs/core'                            │
│                                                              │
│  const delegation = await DRS.issueRootDelegation({         │
│    issuerDID:   userDID,                                     │
│    issuerKey:   userPrivKey,       // from user's wallet     │
│    audienceDID: agentDID,                                    │
│    capabilities: [                                           │
│      { with: "mcp://tools/*",  can: "mcp/call"  },          │
│      { with: "a2a://tasks/*",  can: "a2a/task/create" }     │
│    ],                                                        │
│    ttlSeconds: 3600,                                         │
│    consent: {                                                │
│      method: "explicit-ui-click",                           │
│      timestamp: new Date().toISOString(),                   │
│      sessionId: currentSessionId,                           │
│      uiHash: computedUIHash        // hash of what user saw  │
│    },                                                        │
│    constraints: {                                            │
│      maxCostUSD: 5.00,                                       │
│      piiAccessAllowed: false                                 │
│    }                                                         │
│  })                                                          │
│                                                              │
│  // delegation is now a signed DRSDelegation object         │
│  // CID = "bafy..." — the receipt of this authorisation     │
└──────────────────────┬──────────────────────────────────────┘
                       │ delegation stored in agent session
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Delegation CID stored for audit                    │
│                                                              │
│  // Optionally anchor to IPFS for long-term audit trail     │
│  const cid = await ipfs.add(JSON.stringify(delegation))      │
│                                                              │
│  // Optionally anchor CID on Monad for compliance timestamping
│  await drsRegistry.anchorChain(cid)                         │
└─────────────────────────────────────────────────────────────┘
```

### 10.2 Flow B — Agent Sub-Delegates to a Tool or Child Agent

The agent has a delegation. It needs to give a subset of its authority to a tool server.

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Agent has parentDelegation (from Flow A above)     │
│                                                              │
│  // Agent sub-delegates to a specific tool — narrowing scope│
│  const toolDelegation = await DRS.issueSubDelegation({      │
│    issuerDID:  agentDID,                                     │
│    issuerKey:  agentPrivKey,                                 │
│    audienceDID: toolServerDID,                               │
│    capabilities: [                                           │
│      // Must be a subset of parentDelegation's capabilities  │
│      { with: "mcp://tools/web_search", can: "mcp/call",     │
│        nb: { maxCallsPerSession: 5 } }                       │
│      // NOTE: cannot add "a2a://tasks/*" here               │
│      // even though parent had it — POLA says only grant    │
│      // what's needed for THIS sub-task                     │
│    ],                                                        │
│    ttlSeconds: 300,   // 5 min — much shorter than parent   │
│    parentDelegation: parentDelegation                        │
│  })                                                          │
│  // DRS checks: toolDelegation capabilities ⊆ parent caps  │
│  // If not: CapabilityEscalationError thrown immediately     │
└──────────────────────┬──────────────────────────────────────┘
                       │ agent builds the chain bundle
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: Agent assembles the ChainBundle                    │
│                                                              │
│  const bundle = DRS.buildBundle([                           │
│    parentDelegation,     // index 0: root (human → agent)   │
│    toolDelegation        // index 1: leaf (agent → tool)    │
│  ])                                                          │
│                                                              │
│  // bundle = {                                               │
│  //   delegations: [...],                                    │
│  //   root: "bafy...",                                       │
│  //   leaf: "bafy..."                                        │
│  // }                                                        │
└──────────────────────┬──────────────────────────────────────┘
                       │ agent calls the tool with bundle attached
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: MCP Tool Call with DRS bundle in header            │
│                                                              │
│  // If using @drs/mcp-adapter, this is automatic            │
│  // The adapter attaches the bundle to every outgoing call  │
│                                                              │
│  // Raw HTTP equivalent:                                     │
│  fetch("https://tool-server.example.com/mcp", {             │
│    method: "POST",                                           │
│    headers: {                                                │
│      "Content-Type": "application/json",                     │
│      "X-DRS-Bundle": base64url(JSON.stringify(bundle))      │
│    },                                                        │
│    body: JSON.stringify({ method: "web_search", params: {   │
│      query: "Monad blockchain throughput"                    │
│    }})                                                       │
│  })                                                          │
└─────────────────────────────────────────────────────────────┘
```

### 10.3 Flow C — Tool Server Verifies the Chain (The Resource Side)

The tool server receives the call. This is what runs on the verifier side.

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1: Tool server receives MCP call with bundle          │
│                                                              │
│  // Using @drs/mcp-adapter middleware (Express-style)       │
│                                                              │
│  import { drsMiddleware } from '@drs/mcp-adapter'            │
│                                                              │
│  server.use(drsMiddleware({                                  │
│    requiredCapabilities: [                                   │
│      { with: "mcp://tools/web_search", can: "mcp/call" }    │
│    ],                                                        │
│    revocationCheckMode: "cached",  // or "online" or "skip" │
│    onFailure: "reject"             // or "warn"             │
│  }))                                                         │
└──────────────────────┬──────────────────────────────────────┘
                       │ middleware runs verify_chain()
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 2: verifyChain() runs all 6 checks (O(n), n=2 here)  │
│                                                              │
│  CHECK 1: CID chain ✓ (bafy_parent links correctly)        │
│  CHECK 2: Ed25519 sig ✓ (human key + agent key both valid)  │
│  CHECK 3: POLA ✓ (tool has narrower scope than parent)      │
│  CHECK 4: Expiry ✓ (both within valid window)               │
│  CHECK 5: Constraints (piiAccessAllowed: false — noted)     │
│  CHECK 6: Revocation ✓ (not in status list)                 │
└──────────────────────┬──────────────────────────────────────┘
                       │ verification passes → req.drs populated
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Step 3: Tool handler receives verified context             │
│                                                              │
│  server.tool("web_search", async (params, context) => {     │
│                                                              │
│    // context.drs is populated by the middleware            │
│    const { rootPrincipal, leafCapabilities,                 │
│            consentRecord, regulatoryContext } = context.drs  │
│                                                              │
│    // Audit log: who ultimately authorised this call?       │
│    auditLog.write({                                          │
│      action:        "web_search",                           │
│      rootPrincipal: rootPrincipal,    // the human's DID    │
│      consentMethod: consentRecord?.method,                  │
│      chainDepth:    context.drs.chainDepth,                 │
│      timestamp:     new Date().toISOString()                │
│    })                                                        │
│                                                              │
│    // Enforce PII constraint from the leaf delegation       │
│    const result = await doWebSearch(params.query)           │
│    if (!leafCapabilities.nb?.piiAccessAllowed) {            │
│      return redactPII(result)                               │
│    }                                                         │
│    return result                                             │
│  })                                                          │
└─────────────────────────────────────────────────────────────┘
```

### 10.4 Flow D — Revocation

The human decides to revoke the agent's authority mid-session.

```
┌─────────────────────────────────────────────────────────────┐
│  Revocation via Bitstring Status List (off-chain, fast)     │
│                                                              │
│  import { DRSRevocationClient } from '@drs/core'             │
│                                                              │
│  await revocationClient.revoke(delegationCID)               │
│                                                              │
│  // This calls the DRS Status List Service API              │
│  // which sets bit[statusListIndex] = 1 in the bitstring    │
│  // Next time a verifier checks, this delegation is revoked │
│                                                              │
│  // Propagation time: < 5 minutes (CDN cache refresh)       │
│  // Offline verifiers using cached status: up to 1 hour     │
└──────────────────────┬──────────────────────────────────────┘
                       │ optionally, for compliance use cases
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  On-chain revocation via Monad (auditable, timestamped)     │
│                                                              │
│  // The Solidity contract (Phase 2):                        │
│  await drsRevocationRegistry.revokeReceipt(                 │
│    ethers.utils.id(delegationCID)  // bytes32 keccak hash   │
│  )                                                          │
│                                                              │
│  // Result: immutable, timestamped, publicly verifiable     │
│  // Any auditor can call isRevoked(hash) on the contract    │
│  // Monad finality: ~500ms, cost: fractions of a cent       │
└─────────────────────────────────────────────────────────────┘
```

---

## 11. System Architecture — Full Stack

```
┌──────────────────────────────────────────────────────────────────────┐
│                     LAYER 0 — STANDARDS WE INHERIT                   │
│                                                                        │
│  UCAN Delegation spec    ZCAP-LD    W3C DI EdDSA v1.0 (May 2025)    │
│  RFC 8032 (Ed25519)      RFC 8785 (JCS)    IPLD CIDs                 │
│  W3C Bitstring Status List v1.0     W3C DID Core                     │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ extended by
┌───────────────────────────────▼──────────────────────────────────────┐
│                     LAYER 1 — DRS PROFILE SPEC                        │
│                                                                        │
│  drs/consent field         drs/root-type field                        │
│  drs/regulatory field      drs/constraints vocabulary                 │
│  DRSChainBundle format     Agent-specific revocation semantics        │
└────────────────┬──────────────────────────┬─────────────────────────┘
                 │                          │
     ┌───────────▼───────────┐    ┌────────▼─────────────┐
     │  LAYER 2A             │    │  LAYER 2B             │
     │  @drs/core (TS)       │    │  drs-python           │
     │                       │    │                       │
     │  issueRootDelegation  │    │  issue_delegation()   │
     │  issueSubDelegation   │    │  verify_chain()       │
     │  verifyChain          │    │  (same API, Python)   │
     │  buildBundle          │    │                       │
     │  computeCID           │    └───────────────────────┘
     │  isAttenuatedSubset   │
     └────────────┬──────────┘
                  │
     ┌────────────▼────────────────────────────────────────┐
     │  LAYER 3 — PROTOCOL ADAPTERS                        │
     │                                                      │
     │  @drs/mcp-adapter     @drs/a2a-adapter              │
     │  @drs/http-adapter    @drs/openclaw-plugin          │
     └────────────┬────────────────────────────────────────┘
                  │
     ┌────────────▼────────────────────────────────────────┐
     │  LAYER 4 — STORAGE + REGISTRY                       │
     │                                                      │
     │  Bitstring Status List Service (CDN-cached)          │
     │  IPFS (optional: long-term receipt archival)         │
     │  Monad DRSRevocationRegistry.sol (Phase 2)           │
     └─────────────────────────────────────────────────────┘
```

---

## 12. Protocol Adapters

### 12.1 MCP Middleware Adapter

```typescript
// File: packages/mcp-adapter/src/index.ts

import { verifyChain, extractBundleFromRequest } from '@drs/core'
import type { MCPServer, MCPContext } from '@modelcontextprotocol/sdk/server'

export interface DRSMiddlewareOptions {
  requiredCapabilities: Array<{ with: string; can: string }>
  revocationCheckMode:  'online' | 'cached' | 'skip'
  onFailure:           'reject' | 'warn'
  trustedRootTypes?:   Array<'human' | 'organisation' | 'automated-system'>
}

export function drsMiddleware(opts: DRSMiddlewareOptions) {
  return async (request: MCPRequest, context: MCPContext, next: () => Promise<void>) => {
    
    // 1. Extract bundle from request header
    const bundleHeader = request.headers?.['x-drs-bundle']
    if (!bundleHeader) {
      if (opts.onFailure === 'reject') {
        throw new DRSError('MISSING_BUNDLE', 'No X-DRS-Bundle header present')
      }
      return next()  // warn mode: proceed without DRS context
    }
    
    // 2. Deserialise
    const bundle = JSON.parse(base64urlDecode(bundleHeader))
    
    // 3. Verify chain
    const result = await verifyChain(bundle, {
      revocationCheckMode: opts.revocationCheckMode
    })
    
    if (!result.valid) {
      if (opts.onFailure === 'reject') {
        throw new DRSError(result.code, result.detail)
      }
      console.warn('[DRS] Chain verification failed:', result.code, result.detail)
      return next()
    }
    
    // 4. Check required capabilities
    for (const required of opts.requiredCapabilities) {
      const leafCaps = result.leafCapabilities
      const covered = leafCaps.some(cap =>
        resourceCoveredBy(required.with, cap.with) &&
        abilityCoveredBy(required.can, cap.can)
      )
      if (!covered) {
        throw new DRSError(
          'INSUFFICIENT_CAPABILITY',
          `Tool requires ${required.can} on ${required.with} but chain does not grant this`
        )
      }
    }
    
    // 5. Check root type if required
    if (opts.trustedRootTypes && result.rootType) {
      if (!opts.trustedRootTypes.includes(result.rootType)) {
        throw new DRSError(
          'UNTRUSTED_ROOT_TYPE',
          `Root type ${result.rootType} not in trusted set`
        )
      }
    }
    
    // 6. Attach DRS context to the request context
    context.drs = result
    
    return next()
  }
}
```

### 12.2 A2A Adapter

The A2A Task object carries the bundle in the `extensions` field:

```typescript
// Outgoing (agent building an A2A task with DRS)
const task = {
  id:      taskId,
  message: { role: "user", content: [{ type: "text", text: "..." }] },
  extensions: {
    drs: { bundle: base64urlEncode(JSON.stringify(chainBundle)) }
  }
}

// Incoming (executor verifying before accepting)
import { drsA2AInterceptor } from '@drs/a2a-adapter'
server.use(drsA2AInterceptor({
  requiredCapabilities: [{ with: "a2a://tasks/*", can: "a2a/task/create" }],
  revocationCheckMode: "cached"
}))
```

### 12.3 OpenClaw Integration

Every ClawHub agent can declare DRS support in its `openclaw.json`:

```json
{
  "id": "my-research-agent",
  "name": "Research Agent",
  "workspace": "ws://my-workspace",
  "model": "claude-sonnet-4-6",
  "drs": {
    "enabled": true,
    "required": false,
    "rootTypeRequired": "human",
    "defaultConstraints": {
      "maxCostUSD": 10.00,
      "piiAccessAllowed": false
    }
  }
}
```

When `required: true`, the OpenClaw runtime rejects invocations without a valid DRS bundle.

---

## 13. On-Chain Registry (Monad)

### 13.1 Why Monad

The on-chain registry is optional for most use cases but required for the highest compliance tier (HIPAA, SOX, EU AI Act high-risk). The requirements are:
- Sub-second finality (so revocation propagates fast)
- Near-zero transaction cost (revocations happen frequently)
- EVM compatibility (existing tooling ecosystem)

Monad delivers 10,000 TPS with ~500ms finality and EVM equivalence. Ethereum L1 is too slow (12s) and too expensive for frequent revocation operations.

### 13.2 Contract

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * DRSRevocationRegistry
 * 
 * Provides on-chain revocation for DRS delegations.
 * Receipt hashes are keccak256 hashes of the delegation CID string.
 * 
 * Revocation is one-way: once revoked, cannot be un-revoked.
 * This is intentional — revocation should be permanent and auditable.
 */
contract DRSRevocationRegistry {
    
    // delegationHash => revocationTimestamp (0 = not revoked)
    mapping(bytes32 => uint256) public revocations;
    
    // Events for off-chain indexing
    event DelegationRevoked(
        bytes32 indexed delegationHash,
        address indexed revoker,
        uint256 timestamp
    );
    
    event ChainRevoked(
        bytes32[] delegationHashes,
        address indexed revoker,
        uint256 timestamp
    );
    
    // Revoke a single delegation
    function revokeDelegation(bytes32 delegationHash) external {
        require(revocations[delegationHash] == 0, "DRS: already revoked");
        revocations[delegationHash] = block.timestamp;
        emit DelegationRevoked(delegationHash, msg.sender, block.timestamp);
    }
    
    // Revoke an entire chain at once (gas-efficient batch)
    function revokeChain(bytes32[] calldata delegationHashes) external {
        for (uint256 i = 0; i < delegationHashes.length; i++) {
            bytes32 h = delegationHashes[i];
            if (revocations[h] == 0) {
                revocations[h] = block.timestamp;
                emit DelegationRevoked(h, msg.sender, block.timestamp);
            }
        }
        emit ChainRevoked(delegationHashes, msg.sender, block.timestamp);
    }
    
    // View function: is this delegation revoked?
    function isRevoked(bytes32 delegationHash) 
        external view returns (bool revoked, uint256 revokedAt) 
    {
        uint256 ts = revocations[delegationHash];
        return (ts != 0, ts);
    }
    
    // Compute the hash used for registration (matches off-chain computation)
    // Input: the CID string of the delegation, e.g. "bafyabc..."
    function hashCID(string calldata cid) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(cid));
    }
}
```

---

## 14. Security Model — Threat by Threat

| Threat | Attack Vector | DRS Mitigation | Limitation |
|---|---|---|---|
| Forged receipt | Attacker creates delegation without issuer's key | Ed25519 EUF-CMA: forgery requires solving discrete log on edwards25519 | Private key compromise breaks this — key management is outside DRS scope |
| Capability escalation | Child delegation grants more than parent | `is_attenuated_subset()` checked at issuance AND at verification | Semantic escalation (doing more within stated capability) is out of scope |
| Chain injection | Attacker inserts fake intermediate delegation | CID linking: modifying any delegation changes its CID, breaking all children | N/A |
| Replay after revocation | Old (still-valid-signature) delegation re-presented | Bitstring Status List revocation check (Step 6) | Offline verifiers with stale cache may accept for up to `cacheMaxAge` seconds |
| Signing oracle attack | Adversary calls sign() with controlled messages to recover key | DRS spec MUST NOT expose signing function to external callers | Implementation bug could still expose this — requires correct library usage |
| Key compromise | Issuer's private key is stolen | Revoke the parent delegation — invalidates entire downstream chain | No post-compromise recovery of already-executed actions |
| Status list manipulation | Attacker tampers with bitstring to un-revoke a delegation | Status list is a Verifiable Credential signed by the registry key | Registry key compromise breaks this — mitigated by on-chain fallback |
| Confinement violation | Agent sub-delegates to parties unknown to parent | DRS explicitly does NOT provide confinement — see §15 | Fundamental limitation of all capability systems without online tracking |

### On Confinement

UCANs do not offer confinement (as that would require all processes to be online), so it is impossible to guarantee knowledge of all of the sub-delegations that exist. DRS inherits this property. Confinement — meaning "the principal can always know what sub-delegations exist downstream" — requires a centralised registry that tracks every delegation. DRS is explicitly decentralised. This is the right tradeoff for a durable standard, but architects using DRS must understand this limitation.

---

## 15. Scalability Architecture

### 15.1 Verification is Stateless and Horizontally Scalable

`verifyChain()` requires:
- The ChainBundle (travels with the request)
- The public keys corresponding to the DIDs in the chain (resolved from DID strings — for `did:key`, this is pure computation, zero network)
- The revocation status list (CDN-cached, fetched at most every `cacheMaxAge` seconds)

No shared state. No database lookup. No coordination between verifier instances. Scale horizontally without limit.

### 15.2 Verification Latency Budget

For a chain of depth n, all operations:

| Operation | Per-delegation cost | Notes |
|---|---|---|
| JCS canonicalisation | ~0.3ms | JSON key sorting + serialisation |
| SHA-256 (CID check) | ~0.01ms | Hardware-accelerated on modern CPUs |
| Ed25519 verification | ~0.05ms | ~20,000 verifications/sec per core |
| DID key resolution (`did:key`) | ~0.001ms | Pure computation — no network |
| Status list lookup (cached) | ~0.001ms | Bitstring index operation |
| **Total per delegation** | **~0.36ms** | |
| **n=5 chain** | **~1.8ms** | |
| **n=10 chain** | **~3.6ms** | |

These numbers are conservative. In practice, batch Ed25519 verification (RFC 8032 §5.1.7 mentions this) can verify 64 signatures at once with better throughput.

### 15.3 Status List Scaling

The Bitstring Status List CDN layer handles all revocation lookups. The list is refreshed every 5 minutes (configurable). A 16KB compressed bitstring covers 131,072 delegations — one file, globally cached, millions of lookups/second.

For high-churn scenarios: partition the status list by time window (one per day, one per week). Old windows are immutable once the window closes.

---

## 16. Implementation Roadmap

### Phase 1 — Core Spec + Reference Library (Months 1–4)
- [ ] Finalize DRS JSON schema (extends UCAN Delegation 0.10.0)
- [ ] Publish DRS context document to `delegationreceipt.org/contexts/v1`
- [ ] `@drs/core` TypeScript — full algorithm suite
- [ ] 200+ test vectors including adversarial cases
- [ ] Compatibility test against existing UCAN libraries (`@ucanto/*`)
- [ ] Submit as a UCAN Working Group extension proposal

### Phase 2 — Adapters + Community (Months 4–8)
- [ ] `@drs/mcp-adapter`, `@drs/a2a-adapter`, `@drs/http-adapter`
- [ ] OpenClaw plugin for ClawHub
- [ ] `drs-python` SDK
- [ ] Interactive receipt explorer at `delegationreceipt.org/explorer`
- [ ] DRS Bitstring Status List service

### Phase 3 — Monad + Enterprise (Months 8–18)
- [ ] `DRSRevocationRegistry.sol` deployed to Monad mainnet
- [ ] `did:monad` DID method spec and resolver
- [ ] Enterprise compliance pack (EU AI Act audit export, HIPAA)
- [ ] W3C CCG proposal for DRS as a formal work item

---

## 17. What DRS Does Not Solve

Be explicit. These are outside scope and building them into DRS would make it fragile.

- **Behavioural confinement** — tracking what sub-delegations exist is a centralised problem
- **Agent authentication** — verifying an agent is "who it says it is" beyond key ownership is an identity layer problem
- **Semantic capability enforcement** — whether an agent with `mcp/call` does something harmful within that capability is a policy enforcement problem
- **Post-compromise recovery** — once a signing key is stolen and used, those receipts cannot be retroactively invalidated (only future ones can be blocked by revocation)
- **Privacy** — chain bundles are readable by any party that holds them; selective disclosure via BBS+ is Phase 3 research work

---

## 18. Open Research Questions

**Q1: Attenuation completeness**  
The `nb_constraints_maintained()` function uses a conservative rule ("absence of a parent constraint in child = violation"). Is this too strict? Real UCAN implementations treat absence as "no constraint", which is more flexible but potentially less safe for accountability use cases.

**Q2: Multi-parent proofs**  
UCAN allows `prf` to contain multiple CIDs (rights amplification — combining capabilities from multiple parents). DRS v1 assumes a single-parent linear chain for simplicity. Should DRS support multi-parent proofs? This dramatically increases verification complexity.

**Q3: Consent record standardisation**  
The `uiHash` field captures what was shown to the user. But the hash is of the rendered DOM element — which varies by browser. Should the standard require a canonical consent UI specification that produces a deterministic hash? This would enable auditors to precisely verify what the user saw.

**Q4: Short-lived vs long-lived delegations**  
For automated systems running 24/7, a delegation with `exp: now + 3600` means re-issuing every hour. This requires the human to be available. Should DRS define a "standing delegation" pattern with a separate renewal mechanism?

**Q5: Confinement via a transparency log**  
Certificate Transparency (RFC 6962) solved a similar problem for TLS certificates: anyone can audit what certificates have been issued. A DRS Transparency Log — a public, append-only log of delegation CIDs — would enable confinement-like visibility without requiring online checking. Is this worth the infrastructure cost?

---

*Research sources used in this document:*  
*— Brendel, Cremers, Jackson, Zhao: "The Provable Security of Ed25519: Theory and Practice" — IACR 2020/823*  
*— Grierson, Chalkias, Buchanan: "Double Public Key Signing Function Oracle Attack on EdDSA" — arXiv:2308.15009 (2023)*  
*— W3C Data Integrity EdDSA Cryptosuites v1.0 — W3C Recommendation May 2025*  
*— W3C UCAN Delegation Spec — ucan-wg/spec (2024/2025)*  
*— W3C ZCAP-LD — w3c-ccg/zcap-spec*  
*— IPLD CID Spec — github.com/multiformats/cid*  
*— RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)*  
*— RFC 8785: JSON Canonicalization Scheme (JCS)*  
*— W3C Bitstring Status List v1.0*

*— Okey, March 2026*
