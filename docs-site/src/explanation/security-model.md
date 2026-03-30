# Security Model

## Threat table

| Threat | Attack vector | DRS mitigation | Residual risk |
|---|---|---|---|
| **Forged root DR** | Attacker creates a fake delegation | Ed25519 EUF-CMA: forgery requires solving the discrete log | Private key theft |
| **Chain splicing** | Compromised agent substitutes unrelated token | `prev_dr_hash`: any substitution changes the hash chain — fails Block B | Implementation bugs in hash computation |
| **Policy escalation** | Sub-DR claims wider permissions than parent | `check_policy_attenuation()` at issuance + Block D at verification | Policy schema gaps |
| **Policy violation** | Agent passes arguments exceeding constraints | Block D evaluates all policies conjunctively | Unlisted policy fields are not checked |
| **DR tampering** | Attacker modifies a signed DR | Ed25519 signature fails — fails Block C | None — structural |
| **Chain injection** | Insert a fake intermediate DR | `prev_dr_hash` changes break subsequent links — fails Block B | None — structural |
| **Replay after revocation** | Agent replays a revoked DR | Block F: Bitstring Status List (5-min cache TTL) | Up to 5-minute stale cache window |
| **JSON malleability** | Different canonical bytes for same logical JSON | RFC 8785 JCS enforced at both issuance and verification ends | Non-conforming JCS at one end |
| **Signature malleability** | `(R, S)` and `(R, S+L)` both verify under naive check | `ed25519-dalek 2.x` enforces `S < L` via `verify_strict()` | None — library enforces |
| **DID spoofing** | Attacker impersonates a legitimate issuer | `did:key` DIDs are derived from the public key — impossible without the private key | `did:web` requires DNS/TLS security |
| **Prompt injection** | Attacker embeds instructions in tool content | DRS records every invocation chain | Out of scope — model/runtime responsibility |
| **Model-level bypass** | Adversarial prompts bypass safety constraints | Model safety ≠ execution safety | Entirely outside DRS scope |

## Fail-closed principle

DRS verification is fail-closed. Any error in any block returns an error and rejects the request. This applies to:
- Unresolvable DIDs
- Malformed JWTs
- Network errors fetching the Bitstring Status List
- Policy fields the verifier does not recognise

A partially valid chain is an invalid chain.

## Constant-time operations

All security-sensitive comparisons use constant-time equality to prevent timing side-channels:

| Language | Safe | Unsafe |
|---|---|---|
| Go | `crypto/subtle.ConstantTimeCompare` | `bytes.Equal`, `==` |
| Rust | `subtle::ConstantTimeEq` | `==` on byte slices |

This applies specifically to multicodec prefix checks when resolving `did:key` DIDs. The two-byte prefix `[0xed, 0x01]` identifies an Ed25519 key. Checking it with a short-circuit comparison leaks timing information about where the mismatch occurs.

## Key management

| Key type | Recommended storage | Rotation |
|---|---|---|
| Human root key | Hardware Security Module or Secure Enclave | Not rotated (DID is derived from key) |
| Operator root key | HSM required for production | Annual with overlap period |
| Agent session key | Ephemeral — generated per session | Per-session, never persisted |

`did:key` is the preferred DID method: the DID encodes the public key directly. No registry, no DNS, no trust anchor beyond the key itself. `did:web` is supported but requires DNS and TLS security.

## What DRS does not protect against

- **Prompt injection:** An attacker embedding instructions in tool output or environment data. This is a model-layer problem. DRS records that the invocation happened and under what authorisation — it does not prevent the model from following injected instructions.
- **Key compromise:** If a private key is stolen, the attacker can forge receipts signed by that key. Mitigation: rotate keys, revoke outstanding delegations.
- **Post-compromise recovery:** DRS does not define how to recover a system after key material is compromised. That is an operational problem.
