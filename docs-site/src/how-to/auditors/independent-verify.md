# Independent Verification

DRS chains can be verified by anyone, without contacting the operator, without a DRS account, and without any central authority.

## What you need

- The DRS bundle (the JWT strings)
- The `drs verify` CLI (from `@drs/sdk`) or a running drs-verify instance

## What you do NOT need

- Access to the operator's systems or databases
- A DRS account or subscription
- Network access to the original issuer
- Any trusted third party to authenticate the evidence

## Why this works

Each Delegation Receipt is signed with the issuer's Ed25519 private key. The issuer's public key is encoded directly in their `did:key` DID:

```
did:key:z6Mk{base58btc(multicodec_prefix + public_key_bytes)}
```

Anyone with the DID can derive the public key and verify the signature. No registry lookup, no HTTP request, no trust anchor beyond the public key.

## Offline verification

All blocks except F (revocation) can be run offline:

```bash
pnpm exec drs verify bundle.json --offline
```

The `--offline` flag skips Block F (Bitstring Status List lookup). All cryptographic, structural, policy, and temporal checks run locally with no network calls.

Use `--offline` when:
- You have no network access
- You are verifying historical evidence (revocation status is not relevant for a past action)
- You distrust the network path to the status list server

## Full online verification

```bash
DRS_VERIFY_URL=http://your-drs-verify-instance:8080 pnpm exec drs verify bundle.json
```

Or spin up your own drs-verify instance and point at it:

```bash
cd drs-verify && go run ./cmd/server &
pnpm exec drs verify bundle.json
```

## Checking signatures manually

If you want to verify a signature without the CLI tools, every DRS JWT is a standard EdDSA JWT. Any JWT library that supports `alg: EdDSA` can verify it:

```bash
# Decode and verify using jwt.io or any EdDSA-capable tool
# The DID in the "iss" field encodes the public key:
# did:key:z6Mk{base58(0xed01 + pub_key_bytes)}

# Extract pub key from DID:
echo "did:key:z6Mk..." | pnpm exec drs resolve-did
# {"public_key_hex": "0102030405..."}
```
