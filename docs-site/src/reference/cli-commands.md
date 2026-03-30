# CLI Commands

The `drs` CLI is included in `@drs/sdk`. Install globally:

```bash
pnpm add -g @drs/sdk
drs --help
```

Or use without global install via:
```bash
pnpm exec drs <command>
```

---

## drs verify

Verify a DRS bundle against drs-verify.

```bash
drs verify <bundle-file> [options]
```

| Option | Description |
|---|---|
| `--url <url>` | drs-verify base URL (default: `$DRS_VERIFY_URL`) |
| `--offline` | Skip Block F (revocation check) — runs all other blocks locally |

**Examples:**

```bash
# Verify against local drs-verify
DRS_VERIFY_URL=http://localhost:8080 drs verify bundle.json

# Offline verification (no revocation check)
drs verify bundle.json --offline

# Verify and show all block results
drs verify bundle.json --verbose
```

**Exit codes:** `0` = valid, `1` = invalid, `2` = error (malformed input, server unreachable)

---

## drs audit

Print the full human-readable audit trail for a bundle.

```bash
drs audit <bundle-file>
```

Shows: issuer/audience for each receipt, policy at each level, consent record, temporal bounds, chain hashes, and invocation arguments.

---

## drs policy

Display the policy from a delegation receipt.

```bash
drs policy <bundle-file> [--receipt <index>]
```

`--receipt 0` shows the root DR's policy. `--receipt 1` shows the first sub-DR's policy. Default: shows all.

---

## drs translate

Translate a policy JSON object to plain English.

```bash
drs translate <policy-file> [--locale <locale>]
```

```bash
echo '{"allowed_tools":["web_search"],"max_cost_usd":50,"pii_access":false}' \
  | drs translate --locale en-GB
```

Output:
```
Research Agent wants permission to:
✓  Search the web
✗  Cannot access personal data
✗  Cannot spend more than £50.00
```

Supported locales: `en-GB`, `en-US`, `fr-FR`, `de-DE` (others fall back to `en-US`).

---

## drs keygen

Generate a new Ed25519 keypair.

```bash
drs keygen [--output <file>]
```

Without `--output`: prints private key (base64url) and DID to stdout.

With `--output keypair.json`: writes:
```json
{
  "private_key": "<base64url 32 bytes>",
  "did": "did:key:z6Mk...",
  "created_at": "2026-03-30T10:00:00Z"
}
```

> **Security:** The private key is printed to stdout or written to the output file in plaintext. Use HSM or KMS for production keys — the `keygen` command is for development only.
