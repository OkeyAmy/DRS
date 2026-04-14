# Independent Verification

DRS chains can be verified by anyone, without contacting the operator, without a DRS account, and without any central authority.

## What you need

- the DRS bundle (the JWT strings)
- the `drs verify` CLI from `@okeyamy/drs-sdk`
- access to a `drs-verify` instance you trust, including one you run yourself

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

## Verification

```bash
DRS_VERIFY_URL=http://your-drs-verify-instance:8080 pnpm exec drs verify bundle.json
```

Or run your own verifier and point the CLI at it:

```bash
cd drs-verify && go run ./cmd/server &
pnpm exec drs verify bundle.json
```

## Signature model

Each DRS JWT is an EdDSA JWT. The issuer DID encodes the Ed25519 public key:

```text
did:key:z6Mk{base58btc(0xed01 + public_key_bytes)}
```

That lets any verifier derive the public key from the DID without contacting the
original operator.
