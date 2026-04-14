# Verification Algorithm

`verify_chain` runs six sequential blocks (A–F). The function is **fail-closed**: any error in any block immediately returns an error without evaluating subsequent blocks.

## The six blocks

### Block A — Completeness

**What:** Bundle has at least one delegation receipt and exactly one invocation receipt.

**Fail condition:** `receipts` array is empty, or `invocation` field is missing or null.

---

### Block B — Structural Integrity

**What:** The delegation receipts form a valid tamper-evident chain.

For each receipt at index `i`:
- `receipts[i].aud` must equal `receipts[i+1].iss` (audience of each DR is the issuer of the next)
- `receipts[i+1].prev_dr_hash` must equal `sha256:{SHA-256 of receipts[i] JWT bytes}`
- The invocation's `dr_chain[i]` must equal `sha256:{SHA-256 of receipts[i] JWT bytes}`

**Fail condition:** Any hash mismatch, any issuer/audience gap, any missing `dr_chain` entry.

This block defeats chain splicing: substituting any DR changes its bytes, which changes its hash, which breaks `prev_dr_hash` in the next DR.

---

### Block C — Cryptographic Validity

**What:** Every JWT signature is valid.

For each JWT in the bundle:
1. Parse JWT header — must be `{"alg":"EdDSA","typ":"JWT"}`
2. Resolve the issuer DID to its Ed25519 public key (LRU-cached)
3. Verify the Ed25519 signature over `base64url(header).base64url(payload)`

**Fail condition:** any signature invalid or any DID unresolvable.

> **Security:** The multicodec prefix check when resolving `did:key` DIDs uses `crypto/subtle.ConstantTimeCompare` in Go and `subtle::ConstantTimeEq` in Rust. Using `bytes.Equal` or `==` leaks timing information.

---

### Block D — Semantic / Policy Compliance

**What:** The invocation arguments comply with every policy in the chain, and no sub-DR escalates beyond its parent.

Policies are evaluated **conjunctively** — all policies must pass:
- `args.tool` must be in `policy.allowed_tools` (if set) at every level
- `args.estimated_cost_usd` must be ≤ `policy.max_cost_usd` (if set) at every level
- `args.pii_access` must be `false` if `policy.pii_access` is `false` at any level

Sub-DR attenuation and temporal nesting checks:
- Each sub-DR's `policy` must be a subset of its parent's `policy`
- Child `nbf` must not be earlier than parent `nbf`
- Child `exp` must not outlive parent `exp` when both are set
- Any escalation (wider tool list, higher cost limit, `pii_access: true` when parent has `false`) fails this block

**Fail condition:** Any argument exceeds any policy constraint, or any sub-DR escalates permissions.

---

### Block E — Temporal Validity

**What:** All receipts are valid at the current time, and temporal bounds are properly nested.

- `now ≥ receipt.nbf` for every receipt
- `now ≤ receipt.exp` for every receipt where `exp` is not null

**Fail condition:** any receipt is expired or not yet valid.

---

### Block F — Revocation

**What:** No receipt has been revoked via either the remote Bitstring Status List or the local revocation store.

For each delegation receipt with a `drs_status_list_index`:

1. **Remote check** — only if `STATUS_LIST_BASE_URL` is configured.
2. **Local check** — query the in-memory local revocation store.

If the remote status cache is not configured, that part is skipped. Local
revocation still runs.

**Fail condition:** any receipt is marked revoked, or a configured remote
revocation check errors.

> The `sync.Once` guard prevents double-fetch race conditions: when the remote cache expires and multiple goroutines arrive simultaneously, only one HTTP request is made — all others wait and reuse the result.

---

## Algorithm pseudocode

```
verify_chain(bundle) → Result<VerifiedChain, VerifyError>:

  # Block A
  if bundle.receipts is empty: return Err(BUNDLE_INCOMPLETE)
  if bundle.invocation is null: return Err(BUNDLE_INCOMPLETE)

  drs = [decode_jwt(r) for r in bundle.receipts]
  inv = decode_jwt(bundle.invocation)

  # Block B
  for i in 0..len(drs)-1:
    if drs[i].aud != drs[i+1].iss: return Err(ISSUER_AUDIENCE_GAP)
    if drs[i+1].prev_dr_hash != sha256(bundle.receipts[i]): return Err(CHAIN_HASH_MISMATCH)
  for i, dr in enumerate(drs):
    if inv.dr_chain[i] != sha256(bundle.receipts[i]): return Err(CHAIN_HASH_MISMATCH)

  # Block C
  for (jwt, payload) in receipts + invocation:
    pub_key = resolve_did(payload.iss)  # LRU cached, constant-time prefix check
    if not ed25519_verify(jwt, pub_key): return Err(SIGNATURE_INVALID)

  # Block D
  for dr in drs:
    if not args_satisfy_policy(inv.args, dr.policy): return Err(POLICY_VIOLATION)
  for i in 1..len(drs):
    if not is_attenuated_subset(drs[i].policy, drs[i-1].policy): return Err(POLICY_ESCALATION)

  # Block E
  now = unix_timestamp()
  for dr in drs:
    if now < dr.nbf: return Err(RECEIPT_NOT_YET_VALID)
    if dr.exp != null and now > dr.exp: return Err(RECEIPT_EXPIRED)
  # Block F
  for dr in drs:
    if dr.drs_status_list_index != null:
      if remote_status_list_configured and remote_status_list.is_revoked(dr.drs_status_list_index):
        return Err(RECEIPT_REVOKED)
      if local_revocation_store.is_revoked(dr.drs_status_list_index):
        return Err(RECEIPT_REVOKED)

  return Ok(VerifiedChain{root_principal, subject, chain_depth, policy_result})
```

## Performance targets

At 10,000 requests/second on the Go verification server:

| Operation | Cost | Notes |
|---|---|---|
| Policy check per level | O(1) avg | Hash-set intersection in capability index |
| DID resolution | O(1) amortised | LRU cache, 10,000 entry cap, 1-hour TTL |
| Status list check | O(1) amortised | 5-min TTL, `sync.Once` guard |
| Ed25519 verify | implementation-dependent | Go uses `crypto/ed25519` |
| Total per request (2-hop chain) | ~0.8ms p99 | |
