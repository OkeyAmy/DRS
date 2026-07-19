# Error Codes

Every code on this page is emitted by the current implementation. The Go
codes are produced by `verify.Chain` (`drs-verify/pkg/verify/chain.go`); the
SDK codes are thrown by the issuance path (`drs-sdk/src/sdk`).

## SDK errors (TypeScript)

Thrown by the SDK during issuance. They fire **before** any signing occurs —
an invalid chain cannot be created.

| Code | Thrown by | Description | Fix |
|---|---|---|---|
| `MISSING_CONSENT` | `issueRootDelegation` | `rootType` is `"human"` but no `consent` was supplied | Pass a `consent` record to `issueRootDelegation` |
| `POLICY_ESCALATION` | `issueSubDelegation` | Child policy field exceeds the parent constraint | Reduce the escalating field to within parent bounds |
| `MALFORMED_JWT` | `issueSubDelegation`, `issueInvocation` | A parent receipt passed in could not be decoded as a 3-part JWT | Pass the exact JWT strings returned by the issuance functions |
| `EMPTY_CHAIN` | `buildBundle`, `createInvocationBundle` | No delegation receipts were supplied | Include at least the root delegation receipt |
| `MISSING_INVOCATION` | `buildBundle` | No invocation receipt was supplied | Include the signed invocation receipt |
| `INVALID_OPERATOR_CONFIG` | `validateOperatorConfig`, `parseOperatorConfig` | Missing required field or invalid value | Check the field named in the error message |

> The SDK does **not** throw `TEMPORAL_BOUNDS_VIOLATION` at issuance. Temporal
> nesting is enforced by the verifier (see the Go table, Block D).

## Verification errors (Go)

Returned by `verify.Chain` inside the `error` object of the `/verify`
response. The response shape and HTTP status are described in
[Response shape](#response-shape) below — note that `POST /verify` always
returns **HTTP 200**, even on failure.

### Block A — Completeness

| Code | Description |
|---|---|
| `EMPTY_CHAIN` | `bundle.receipts` is empty |
| `CHAIN_TOO_DEEP` | More than `MAX_CHAIN_DEPTH` (16) receipts; checked before any cryptographic work |
| `MISSING_INVOCATION` | `bundle.invocation` is empty |
| `MALFORMED_RECEIPT` | A receipt JWT could not be decoded |
| `MALFORMED_INVOCATION` | The invocation JWT could not be decoded |

### Block B — Structural Integrity

| Code | Description |
|---|---|
| `WRONG_TYPE` | A receipt is not a `delegation-receipt`, or the invocation is not an `invocation-receipt` |
| `VERSION_MISMATCH` | `drs_v` is not `4.0` |
| `INVALID_JTI` | A receipt `jti` lacks the `dr:` prefix, or the invocation `jti` lacks the `inv:` prefix |
| `CHAIN_STRUCTURE` | `receipts[0]` (the root) carries a `prev_dr_hash` |
| `MISSING_CONSENT` | Root `drs_root_type` is `human` but `drs_consent` is absent |
| `INVALID_CONSENT` | `drs_consent` is present but a required field (`method`, `timestamp`, `session_id`, `policy_hash`) is empty |
| `CHAIN_BREAK` | A non-root receipt's `prev_dr_hash` is missing or does not match SHA-256 of the previous receipt |
| `ISSUER_MISMATCH` | `receipts[i].iss` ≠ `receipts[i-1].aud` |
| `INVOKER_MISMATCH` | `invocation.iss` ≠ the leaf receipt's `aud` |
| `CHAIN_REFERENCE_MISMATCH` | `invocation.dr_chain` length or a hash entry does not match the receipts |

### Block C — Cryptographic Validity

| Code | Description |
|---|---|
| `UNRESOLVABLE_DID` | An issuer DID could not be resolved to an Ed25519 public key |
| `INVALID_SIGNATURE` | A receipt's Ed25519 signature failed verification |
| `INVALID_INVOCATION_SIGNATURE` | The invocation's Ed25519 signature failed verification |
| `SIGNATURE_MALLEABILITY` | Signature rejected for `S ≥ L` (Ed25519 strict-mode violation) |

### Block D — Semantic / Policy Validity

| Code | Description |
|---|---|
| `INVALID_ROOT_CMD` | The root receipt `cmd` is empty or not an absolute path beginning with `/` |
| `COMMAND_MISMATCH` | A receipt `cmd` widens its parent, or `invocation.cmd` is not equal to / a sub-path of the leaf `cmd` |
| `SUBJECT_MISMATCH` | Delegation receipts do not all share the same `sub` |
| `INVOCATION_SUBJECT_MISMATCH` | `invocation.sub` ≠ the chain's root `sub` |
| `TOOL_SERVER_MISMATCH` | `invocation.tool_server` ≠ `SERVER_IDENTITY`. **Also returned fail-closed** when `tool_server` is set but the verifier has no `SERVER_IDENTITY` configured |
| `POLICY_ESCALATION` | A sub-delegation's policy escalates beyond its parent |
| `TEMPORAL_BOUNDS_VIOLATION` | Child `nbf` < parent `nbf`, child `exp` > parent `exp`, or child omits `exp` while the parent sets one |
| `POLICY_VIOLATION` | `invocation.args` exceed a policy constraint in the chain |

### Block E — Temporal Validity

| Code | Description |
|---|---|
| `INVOCATION_NOT_YET_VALID` | `invocation.iat` is in the future beyond the allowed clock skew (5 min) |
| `INVOCATION_STALE` | `invocation.iat` is older than the maximum invocation age (the nonce store TTL). Bounds the replay window after a JTI is evicted |
| `NOT_YET_VALID` | `now` < a receipt's `nbf` |
| `EXPIRED` | `now` > a receipt's `exp` (receipts with no `exp` never expire) |

### Block F — Revocation

| Code | Description |
|---|---|
| `REVOCATION_CHECK_FAILED` | The Bitstring Status List could not be fetched (fail-closed) |
| `REVOKED` | A receipt is revoked, either in the remote status list or the local `/admin/revoke` store |

## Response shape

A bundle that reaches verification always returns **HTTP 200**. Determine the
outcome from the `valid` field, not the status code. (HTTP 403 is returned only
by the MCP/A2A middleware routes, which gate a request — not by `/verify` itself.)

Requests rejected *before* verification return a non-200 status with a JSON
`error` field:

| HTTP | `error` | When |
|---|---|---|
| 400 | (varies) | Malformed JSON, missing fields, or missing invocation `jti` |
| 409 | `REPLAY_DETECTED` | The invocation `jti` has already been consumed |
| 413 | `REQUEST_BODY_TOO_LARGE` | Request body exceeds the 64 KiB cap |
| 429 | `RATE_LIMIT_EXCEEDED` | Per-IP or global rate limit hit |
| 503 | `NONCE_STORE_EXHAUSTED` | Replay-protection store at capacity — retry shortly |

A failed verification:

```json
{
  "valid": false,
  "error": {
    "code": "CHAIN_BREAK",
    "message": "receipt[1] prev_dr_hash mismatch: claimed \"sha256:def456...\", expected \"sha256:abc123...\".",
    "suggestion": "DR at index 0 may have been modified after DR at index 1 was issued, or the receipts are in the wrong order."
  }
}
```

`error` is an **object** with three string fields:

- `code` — the stable machine-readable code from the tables above
- `message` — a full English sentence describing the specific failure
- `suggestion` — concrete remediation guidance

There is no top-level `block` field on the response; the block is a
documentation grouping, not a wire field.
