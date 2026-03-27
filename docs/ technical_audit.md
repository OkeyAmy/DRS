# Deep technical audit of a DRS architecture against UCAN v1.0.0-rc.1

**The UCAN v1.0.0-rc.1 specification represents a fundamental architectural break from v0.x** — replacing JWT with DAG-CBOR/IPLD, moving the `prf` field from delegation to invocation, splitting `att` into `sub`/`cmd`/`pol`, and introducing a formal policy language with jq-style selectors. Any architecture document referencing UCAN v1.0 must account for these changes precisely. Several Rust crates commonly cited in UCAN-related designs (notably `libipld`) are now deprecated, and the invocation spec itself contains an internal tag discrepancy between normative text and code examples. Below is a field-by-field audit.

---

## Section A: The v1.0.0-rc.1 spec diverges sharply from v0.x

### A1. Envelope format and type tags

The UCAN v1.0.0-rc.1 envelope is a **two-element IPLD array**, not a JWT:

| Position | Type | Content |
|----------|------|---------|
| `.0` | `Bytes` | Signature over `.1` by the payload's `iss` |
| `.1` | `SigPayload` (map) | Contains Varsig header `h` + tagged payload |
| `.1.h` | `VarsigHeader` | Varsig v1 header describing algorithm and encoding |
| `.1.ucan/<tag>@<version>` | `TokenPayload` | The actual UCAN fields |

**The delegation tag `ucan/dlg@1.0.0-rc.1` is correct.** The delegation spec states verbatim: "The UCAN envelope tag for UCAN Delegation MUST be set to `ucan/dlg@1.0.0-rc.1`."(https://github.com/ucan-wg/spec/blob/main/README.md)(https://github.com/ucan-wg/delegation)

**The invocation tag has a confirmed spec discrepancy.** The normative text says `ucan/inv@1.0.0-rc.1`, but all three code examples in the invocation spec use `ucan/i/1.0.0-rc.1` — differing in both the abbreviation (`inv` vs `i`) and the separator (`@` vs `/`). The main UCAN spec's generic pattern `ucan/<subspec-tag>@<version>` and its example `ucan/example@1.0.0-rc.1` align with the normative text. **The normative text should be treated as authoritative**, but any implementation must be aware of this inconsistency.(https://github.com/ucan-wg/invocation)(https://github.com/ucan-wg/invocation)

### A2. Encoding: DAG-CBOR, not JWT

**UCAN v1.0 uses DAG-CBOR/IPLD encoding. JWT is entirely gone.** The spec states: "All UCANs MUST be canonically encoded with DAG-CBOR for signing. A UCAN MAY be presented or stored in other IPLD formats (such as DAG-JSON), but converted to DAG-CBOR for signature validation." This is a complete break from v0.x, which used RFC 7519 JWTs.(https://github.com/ucan-wg/spec)(https://github.com/erights/ucan-wg-spec)

The canonical CID configuration is formally specified as **CIDv1 + base58btc + SHA-256 + DAG-CBOR multicodec (0x71)**. All conformant CIDs start with the characters `zdpu`.

### A3. Delegation payload fields: att is dead, long live sub/cmd/pol

The **complete** delegation payload in v1.0.0-rc.1 is:

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `iss` | `DID` | Yes | Issuer |
| `aud` | `DID` | Yes | Audience (recipient of delegation) |
| **`sub`** | `DID \| null` | Yes | Subject — the principal the chain is about. `null` enables "Powerline" delegation |
| **`cmd`** | `String` | Yes | `/`-delimited command path (e.g., `/blog/post/create`). `"/"` means all commands |
| **`pol`** | `Policy` | Yes | Array of predicate statements (the policy language) |
| `nonce` | `Bytes` | Yes | Unique random nonce |
| `exp` | `Integer \| null` | Yes | Expiration (UTC Unix timestamp in seconds); `null` = no expiry |
| `nbf` | `Integer` | No | Not-before timestamp |
| `meta` | `{String: Any}` | No | Metadata (signed but not delegated) |

**`sub` is a required field.** It replaces the v0.x concept of embedding the resource URI in `att[].with`. **`cmd` is a required field.** It replaces `att[].can`. **`pol` is the correct field name** for policy, replacing the entire `att` array's role of constraining capabilities. The v0.x `att` field with its `{with, can}` objects **does not exist in v1.0**.

### A4. The prf field moved to invocation — this is critical

**In v1.0, `prf` is NOT in the delegation payload. It lives exclusively in the invocation payload.** This is a fundamental architectural change from v0.x where each delegation JWT contained its own `prf` array of parent token CIDs.

In v1.0, the proof chain is assembled at invocation time. The invocation spec states: "The `prf` field lists the path of authority from the Subject to the Invoker. This MUST be an array of CIDs pointing Delegations starting from the root Delegation (issued by the Subject), in strict sequence where the `aud` of the previous Delegation matches the `iss` of the next Delegation."

**If a DRS architecture document places `prf` in the delegation structure for v1.0, that is incorrect.**

### A5. Policy language: formally specified with jq-style selectors

The UCAN v1.0 Policy Language is well-defined. **Yes, expressions use the form `["==", ".field", value]`** — a three-element array of `[operator, selector, argument]`. The top-level `pol` is an array of statements implicitly joined by AND.

**Complete operator set:**

- **Comparison**: `==`, `!=`, `<`, `<=`, `>`, `>=` — e.g., `["==", ".status", "draft"]`
- **Glob matching**: `like` — e.g., `["like", ".email", "*@example.com"]`
- **Connectives**: `and`, `or` (take `[operator, [statements]]`), `not` (takes `[operator, statement]`)
- **Quantifiers**: `all`, `any` — e.g., `["all", ".reviewers", [">", ".score", 3]]`

**Selector syntax** is jq-inspired: `.` (identity), `.foo` (field access), `[0]` (index), `[-1]` (from end), `[2:5]` (slice), `[]` (all children), `.foo?` (optional — returns null on failure), `["arbitrary-key"]` (bracket notation for ambiguous keys).

All policies constrain the `args` field of an eventual invocation. If a selector cannot resolve, the statement returns **false** (not an exception).

### A6. Delegation and invocation are fully separate types

Yes, v1.0 defines **four** lifecycle components: Delegation (required), Invocation (required), Promise (recommended), and Revocation (recommended). Each uses a distinct envelope tag.(https://github.com/ucan-wg/spec/blob/main/README.md)

**Invocation payload structure:**

| Field | Type | Required |
|-------|------|----------|
| `iss` | `DID` | Yes |
| `sub` | `DID` | Yes (no null allowed, unlike delegation) |
| `aud` | `DID` | No (defaults to subject) |
| `cmd` | `String` | Yes |
| `args` | `{String: Any}` | Yes |
| `prf` | `[&Delegation]` | Yes |
| `nonce` | `Bytes` | Yes |
| `exp` | `Integer \| null` | Yes |
| `meta` | `{String: Any}` | No |
| `iat` | `Integer` | No |
| `cause` | `&Receipt` | No |

The key structural difference: delegations have `pol` (policy constraints); invocations have `args` (actual arguments) and `prf` (proof chain).

### A7. Implementation status: RC1, not stable

The spec is at **Release Candidate 1** — not finalized. Working implementations with open source code:

- **Rust** (`ucan-wg/rs-ucan`): Claims v1.0.0-rc.1 conformance, published as `ucan = "0.8"` on crates.io. Explicitly marked "⚠️ Work in progress" and "not formally audited."
- **Go** (`ucan-wg/go-ucan`): Claims support for required spec parts (delegation, invocation). Also has `go-varsig` for envelope signatures.
- **TypeScript** (`ucan-wg/ts-ucan`): Published as `@ucans/ucans` v0.11.4 on npm, but **appears to still implement v0.x** (JWT, `att`-style capabilities). Low recent activity.
- **ucanto** (`storacha/ucanto`): Production UCAN RPC framework (powers web3.storage/Storacha). Uses `@ipld/dag-cbor`, `@ipld/dag-ucan`, `multiformats`. Not the official WG implementation but the most battle-tested.

---

## Section B: Rust crate ecosystem has shifted significantly

### B1–B2. libipld is deprecated; use serde_ipld_dagcbor

**`libipld` exists on crates.io at version 0.15.0 but was officially deprecated in March 2024.** The IPLD team migrated functionality into focused, Serde-compatible crates. The `libipld` README explicitly states: "it's strongly recommended to use new implementations that use Serde as a basis instead."

**The correct Rust crate for DAG-CBOR today is `serde_ipld_dagcbor`** at version **0.6.4**. It depends on `ipld-core` (≥0.4.2) and `cbor4ii` for underlying CBOR operations. The companion crate `ipld-core` replaces the old `libipld-core`. `libipld-cbor` was a separate crate but is equally deprecated.

| Crate | Version | Status |
|-------|---------|--------|
| `libipld` | 0.15.0 | **Deprecated** (March 2024) |
| `libipld-cbor` | (sub-crate) | **Deprecated** |
| `serde_ipld_dagcbor` | **0.6.4** | ✅ Active, recommended |
| `ipld-core` | 0.4.x | ✅ Active, replaces libipld-core |

Any architecture document recommending `libipld` should be updated to `serde_ipld_dagcbor` + `ipld-core`.

### B3. ed25519-dalek 2.x: exists, enforces S < L, advisory resolved

**`ed25519-dalek` version 2.2.0 is the current stable release.** Version 2.x exists and represents a complete API overhaul (renaming `Keypair` → `SigningKey`, `PublicKey` → `VerifyingKey`).

**S < L is enforced by default in all `verify_*()` functions.** The docs state: "The authors of the RFC explicitly stated that verification of an ed25519 signature must fail if the scalar s is not properly reduced mod ℓ... All verify_*() functions within ed25519-dalek perform this check."

**`verify_strict()` exists and goes beyond S < L.** It additionally: (1) checks the public key is not a weak/low-order point via `is_weak()`, and (2) uses the cofactored equation `[8][S]B = [8]R + [8][k]A` for malleability resistance on R.

**RUSTSEC-2022-0093 was fully addressed in v2.0.0.** The advisory ("Double Public Key Signing Function Oracle Attack") affected versions <2.0. The dangerous 64-byte keypair serialization API was removed from the public surface; equivalent functionality is only available through explicitly labeled `hazmat` APIs. The fix is listed as "Upgrade to ≥ 2".

### B4–B5. CID and multihash crates

**`cid` crate**: version **0.11.1** on crates.io, from `github.com/multiformats/rust-cid`. This is the primary and correct CID crate for Rust (~13.8M downloads).

**`multihash` crate**: version **0.19.3** on crates.io, from `github.com/multiformats/rust-multihash`. Uses const-generics (`Multihash<64>`). Importantly, this crate provides the **data structure only** — actual hash implementations come from `multihash-codetable` and `multihash-derive`.

---

## Section C: Algorithm details and what the spec actually mandates

### C1. Hash chain verification: CID matching is content-addressed by definition

In UCAN v1.0, a delegation's CID **must** match the CID stored in the invocation's `prf[]` array. This is inherent to content-addressing: a CID is computed from the content, so resolving a CID reference and recomputing produces the same CID if and only if the content is authentic.

**CID computation for a delegation**: Serialize the entire UCAN envelope (the two-element array `[signature_bytes, sig_payload_map]`) as canonical **DAG-CBOR**, then compute **SHA-256** over those bytes, then wrap in a **CIDv1** with DAG-CBOR multicodec (0x71). DAG-CBOR canonicalization ensures determinism — sorted map keys (by byte-length then lexicographic), deterministic integer encoding, no indefinite-length items, no CBOR tags except tag 42 for CIDs.

The spec warns explicitly: "If CIDs aren't validated, at least two attacks are possible: privilege escalation and cache poisoning."

Three mandatory validation checks for a delegation chain: **(1) time bounds** — current time within `[nbf, exp]` for ALL delegations; **(2) principal alignment** — `aud` of each proof matches `iss` of the next; **(3) signature validation** — each signature validates against its `iss` DID.

### C2. The signed message is the DAG-CBOR bytes of element [1]

When signing with Ed25519, **the message is the raw DAG-CBOR serialization of the SigPayload map** (element `.1` of the envelope array — the map containing both the Varsig header `h` and the tagged token payload). The process:

1. Construct the SigPayload map: `{ "h": <varsig_header>, "ucan/dlg@1.0.0-rc.1": { <payload fields> } }`
2. Serialize to canonical DAG-CBOR bytes
3. Sign those bytes with Ed25519 (which internally applies SHA-512 per the Ed25519 algorithm)
4. Place the 64-byte signature as element `.0`

The canonical Varsig header for Ed25519 + DAG-CBOR is the bytes `NAHtAe0BE3E` (base64), encoding: algorithm=0xed (Ed25519), hash=0x13 (SHA-512, internal to Ed25519), payload-encoding=DAG-CBOR.

### C3. S < L prevents signature malleability

**L** (sometimes written **ℓ** or informally **q**) is the **order of the Ed25519 base point B**:

> **L = 2²⁵² + 27742317777372353535851937790883648493**

An Ed25519 signature is `(R, S)` where R is a curve point and S is a 32-byte scalar. The verification equation `[S]B = R + [H(R‖A‖M)]A` operates modulo L, meaning `[S]B = [S + L]B`. Without checking **0 ≤ S < L**, an attacker can produce a second valid signature `(R, S+L)` for any existing signature `(R, S)` — since S+L < 2²⁵³, it still fits in 32 bytes.

**RFC 8032 §5.1.7 explicitly requires** "the second half as an integer S, in the range 0 ≤ S < L." RFC 8032 §8.4 states: "Without this check, one can add a multiple of l into a scalar part and still pass signature verification, resulting in malleable signatures."

**Why this matters for UCAN/DRS**: Systems using CID-based references that include signature bytes will produce different CIDs for `(R, S)` vs `(R, S+L)`, enabling cache poisoning and deduplication confusion. Signature malleability also breaks systems that assume signature uniqueness for transaction identification (the classic Mt. Gox-style attack). Enforcing S < L achieves **SUF-CMA** (Strong Unforgeability under Chosen Message Attack).

### C4. Policy language evaluation has formal semantics

**Yes, the UCAN delegation spec provides a formal definition.** Policies are typed via IPLD Schema as a union of statement types (equality, inequality, like, connectives, negation, quantifiers). Evaluation semantics are specified:

- **Selector resolution**: Substitute values from `args` into each selector position
- **Quantifier expansion**: `["all", selector, stmt]` expands to `["and", [stmt applied to each element]]`
- **Predicate evaluation**: Leaf nodes evaluate to boolean
- **Key rules**: unresolvable selectors return **false**; numeric comparisons are type-agnostic (`1 == 1.0`); empty `["and", []]` and `["or", []]` both return **true**

### C5. Policy attenuation is NOT a formal subsumption check

**The concept of attenuation exists in the spec, but there is no formal policy-to-policy subsumption algorithm.** The spec states: "Attenuation is the process of constraining the capabilities in a delegation chain." However, this works differently than one might expect:

**Command attenuation** is formally defined via path-prefix matching — `cmd: "/crud"` subsumes `cmd: "/crud/read"`. **Subject consistency** is enforced — the `sub` DID must match throughout the chain. **Time bounds narrow** — effective window is the intersection of all `[nbf, exp]` ranges.

**But for policies, there is no structural comparison between parent and child.** Instead, the spec mandates that **all policies in the proof chain are independently evaluated against the invocation's `args` at runtime**. A child delegation can technically have `pol: []` (no constraints) even when its parent has strict policies — the parent's policy still blocks non-conforming invocations because every proof's policy is checked. This design intentionally sidesteps the hard problem of proving logical entailment between arbitrary predicate trees.

If a DRS document claims a formal "child policy must be at least as strict as parent" subsumption check exists in the UCAN v1.0 spec, **that is incorrect**. The security guarantee comes from conjunctive runtime evaluation, not delegation-time structural analysis.

---

## Section D: Go and JS/TS packages are active and version-current

### D1. go-ipld-prime: exists at v0.22.0

`github.com/ipld/go-ipld-prime` is active with **v0.22.0** (February 2025). It provides core IPLD Data Model interfaces, built-in DAG-CBOR and DAG-JSON codecs (`codec/dagcbor`, `codec/dagjson`), IPLD Schemas, traversal/selectors, `bindnode` for Go struct mapping, and CID linking via `linking/cid`. Uses "WarpVer" versioning (all versions are v0.x; even minor versions = safe upgrades).

### D2–D3. npm packages are well-maintained

**`@ipld/dag-cbor`** exists at version **9.2.5** (major version 9). Depends on `cborg` (≥4.0.0) for CBOR and `multiformats` (≥13.1.0) for CID/multicodec. The older `ipld-dag-cbor` (v1.0.1) is deprecated.

**`multiformats`** exists at version **13.4.2**. Handles CID creation/parsing (`multiformats/cid`), SHA-256/SHA-512 hashing (`multiformats/hashes/sha2`), multibase encoding/decoding, and block operations. The older `cids` package is deprecated in its favor.

### D4. UCAN WG JavaScript ecosystem is fragmented

The **official WG TypeScript implementation** is `@ucans/ucans` (v0.11.4) from `ucan-wg/ts-ucan`, but it appears to still target the v0.x JWT-based spec with low recent activity. The **production-grade implementation** is Storacha's `@ucanto/*` family — `@ucanto/core` (v9.0.2), `@ucanto/server` (v11.0.3), `@ucanto/client` (v9.0.2), `@ucanto/principal` (v9.0.3). ucanto depends on `@ipld/dag-cbor`, `@ipld/dag-ucan`, and `multiformats`, and is the most battle-tested JS UCAN implementation (powering web3.storage).

---

## Conclusion: five critical findings for the DRS architecture

This audit surfaces five issues that any DRS architecture document must address to be spec-accurate:

**First**, the `prf` field placement is the most consequential error to check. In v1.0, proofs live in the invocation, not the delegation. Any DRS data structure placing `prf` in delegation payloads is modeling v0.x semantics incorrectly attributed to v1.0.

**Second**, policy attenuation as a formal delegation-time subsumption check does not exist in the spec. The security model relies on conjunctive runtime evaluation of all proof-chain policies against invocation arguments. Architectures assuming a structural "child ⊇ parent" check need redesigning around this runtime model.

**Third**, `libipld` is deprecated — any Rust implementation should use `serde_ipld_dagcbor` (0.6.4) + `ipld-core` (0.4.x). The `ed25519-dalek` 2.2.0 crate enforces S < L by default in all verify methods and has resolved RUSTSEC-2022-0093.

**Fourth**, the invocation spec has an internal tag discrepancy (`ucan/inv@1.0.0-rc.1` vs `ucan/i/1.0.0-rc.1` in examples). Implementations should follow the normative text, but this signals the RC1 spec has not reached full editorial consistency.

**Fifth**, the entire v1.0.0-rc.1 spec remains a release candidate with no finalized implementations. The Rust `rs-ucan` is explicitly "work in progress," the Go implementation is early-stage, and the official TypeScript library may not yet implement v1.0 at all. Only Storacha's ucanto represents a production UCAN system, and it predates the v1.0 spec finalization.