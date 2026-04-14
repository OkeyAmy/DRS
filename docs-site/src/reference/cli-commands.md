# CLI Commands

The `drs` CLI is included in `@okeyamy/drs-sdk`.

```bash
pnpm add -g @okeyamy/drs-sdk
drs --help
```

Or run it without a global install:

```bash
pnpm exec drs <command>
```

---

## drs verify

Verify a bundle against a running `drs-verify` service.

```bash
drs verify [--include-timestamps] <bundle.json>
```

The CLI reads the verifier base URL from `DRS_VERIFY_URL`. If unset, it uses
`http://localhost:8080`.

**Examples:**

```bash
# Verify against local drs-verify
DRS_VERIFY_URL=http://localhost:8080 drs verify bundle.json

# Ask the server to retrieve and verify RFC 3161 timestamp tokens
drs verify --include-timestamps bundle.json
```

**Exit codes:** `0` = valid, `1` = invalid or command error.

---

## drs audit

Print a human-readable audit trail for a bundle file.

```bash
drs audit <bundle.json>
```

Current output includes:

- bundle version
- receipt count
- `iss`, `aud`, `cmd`, `exp` for each receipt
- `iss`, `cmd`, `tool_server` for the invocation

It does not currently export regulatory evidence packages or retrieve bundles by
invocation ID.

---

## drs policy

Translate a policy JSON file or a JSON document with a top-level `policy` field.

```bash
drs policy <receipt.json>
```

The command does not support `--receipt`. If you want the policy from a bundle,
extract one receipt payload first or save the policy to its own JSON file.

---

## drs translate

Translate a policy JSON object to plain English.

```bash
drs translate <policy.json>
```

---

## drs keygen

Generate a new Ed25519 keypair for development or testing.

```bash
drs keygen
```

Current output:

```text
Ed25519 keypair generated.

DID          : did:key:z6Mk...
Public key   : <hex>
Private key  : <hex>
```

> **Security:** the private key is printed in plaintext hex. Do not commit it.
> Use a proper KMS or HSM for production keys.
