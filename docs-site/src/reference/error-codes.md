# Error Codes

## SDK errors (TypeScript)

These errors are thrown by the SDK during issuance. They fire before any signing occurs — invalid chains cannot be created.

| Code | Thrown by | Description | Fix |
|---|---|---|---|
| `MISSING_CONSENT` | `issueRootDelegation` | Human-rooted delegation issued without a `consent` field | Add `consent` to `issueRootDelegation` params |
| `POLICY_ESCALATION` | `issueSubDelegation` | Child policy field exceeds parent constraint | Reduce the escalating field to be within parent bounds |
| `TEMPORAL_BOUNDS_VIOLATION` | `issueSubDelegation` | `nbf < parentNbf` or `exp > parentExp` | Adjust temporal bounds to be nested within parent bounds |
| `INVALID_OPERATOR_CONFIG` | `validateOperatorConfig`, `parseOperatorConfig` | Missing required field or invalid value | Check the field named in the error message |

## Verification errors (Go — returned as HTTP 403 JSON)

These errors are returned by `verify_chain` when a bundle fails verification.

| Code | Block | Description |
|---|---|---|
| `BUNDLE_INCOMPLETE` | A | Bundle has no receipts or is missing the invocation receipt |
| `ISSUER_AUDIENCE_GAP` | B | `receipts[i].aud` ≠ `receipts[i+1].iss` |
| `CHAIN_HASH_MISMATCH` | B | `prev_dr_hash` does not match SHA-256 of previous DR JWT bytes |
| `DR_CHAIN_MISMATCH` | B | `invocation.dr_chain[i]` does not match SHA-256 of `receipts[i]` JWT bytes |
| `INVALID_JWT_HEADER` | C | JWT header is not `{"alg":"EdDSA","typ":"JWT"}` |
| `DID_UNRESOLVABLE` | C | Issuer DID could not be resolved to an Ed25519 public key |
| `SIGNATURE_INVALID` | C | Ed25519 signature verification failed |
| `SIGNATURE_MALLEABILITY` | C | Signature rejected: `S ≥ L` (strict mode violation) |
| `POLICY_VIOLATION` | D | Invocation `args` exceed a policy constraint |
| `POLICY_ESCALATION` | D | Sub-DR policy escalates beyond parent policy |
| `RECEIPT_NOT_YET_VALID` | E | `now < receipt.nbf` |
| `RECEIPT_EXPIRED` | E | `now > receipt.exp` |
| `TEMPORAL_BOUNDS_VIOLATION` | E | Sub-DR temporal bounds not nested within parent bounds |
| `RECEIPT_REVOKED` | F | Receipt found in Bitstring Status List |

## HTTP 403 response body format

```json
{
  "valid": false,
  "error": "CHAIN_HASH_MISMATCH",
  "block": "B",
  "message": "prev_dr_hash mismatch at chain index 1: expected sha256:abc123..., got sha256:def456..."
}
```

The `message` field always contains a full English sentence with diagnosis. The `block` field (A–F) tells you which verification stage failed.
