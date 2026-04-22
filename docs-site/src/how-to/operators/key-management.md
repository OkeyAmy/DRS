# Key Management

## Key types and requirements

| Key type | Recommended storage | Rotation |
|---|---|---|
| Human root key | Hardware Security Module or device Secure Enclave | Not rotated — DID is derived from key |
| Operator root key | HSM/KMS or equivalent external signer for production | Annual with overlap period |
| Agent session key | Ephemeral — generated per session, never stored | Per-session |

## Why agent keys must be ephemeral

Long-lived agent private keys are a liability: if the agent is compromised, all delegations signed by that key are at risk. Ephemeral keys limit the blast radius: a compromised key can only affect delegations from the current session, which expire when the session ends.

## Generating keys

**Development only (never in production):**
```bash
pnpm exec drs keygen
# Private key: <base64url 32 bytes>
# DID:         did:key:z6Mk...
```

**Production operator keys:**

Use a KMS/HSM-backed signer or another reviewed external signing service for
operator keys with regulatory significance. The current repository parses
`operator_key_management` values such as `"aws-kms"` and `"gcp-kms"` in
configuration, but it does not include built-in KMS signing code. Do not assume
that setting those values alone moves signing out of local process memory.

## DID method choices

**`did:key` (recommended):** The DID is derived directly from the public key. No registry, no DNS, no trust anchor beyond the key itself. The verification key is self-contained in the DID string.

**`did:web`:** The DID is resolved by fetching a DID document from an HTTPS URL. Useful when you need to rotate keys without changing the DID (the DID document can be updated). Requires your domain's DNS and TLS to be secure — a compromised domain means a compromised DID.

## Key rotation

For `did:key` DIDs, rotating the key means generating a new key and a new DID. The process:

1. Generate new key and DID
2. Update `operator_did` in your `OperatorConfig`
3. New root delegations are issued under the new DID
4. Old delegations (signed with the previous key) remain valid until they expire
5. After old delegations expire, the old key can be decommissioned

## Protecting signing keys

- Never log private key material, even in debug builds
- Never store private keys in environment variables in production
- Do not treat `aws-kms` or `gcp-kms` config values as built-in signing support until your deployment supplies and tests that signer integration
- Never include private keys in Docker images
- Never commit keys to version control
