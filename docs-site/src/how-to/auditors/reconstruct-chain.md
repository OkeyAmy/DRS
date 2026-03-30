# Reconstruct a Delegation Chain

You can reconstruct and verify any delegation chain from stored receipts without operator cooperation. All you need are the JWT strings and the DIDs.

## Step 1: Retrieve the bundle

If the operator has provided the bundle file:

```bash
pnpm exec drs audit retrieve --inv-jti "inv:7h5c4d3e-..." --output evidence.json
```

Or assemble manually from JWT strings provided by the operator:

```json
{
  "bundle_version": "4.0",
  "invocation": "<invocation-receipt-jwt>",
  "receipts": [
    "<root-dr-jwt>",
    "<sub-dr-jwt-1>"
  ]
}
```

## Step 2: Verify the chain

```bash
pnpm exec drs verify evidence.json
```

This runs all six verification blocks locally. The public keys are resolved from the DID strings embedded in each JWT's `iss` field. No network calls to any operator system.

```
✓ Bundle verified
  Chain depth:    2
  Root principal: did:key:z6MkHuman...
  Subject:        did:key:z6MkHuman...
  Command:        /mcp/tools/call
  Policy result:  pass
  Blocks:         A✓ B✓ C✓ D✓ E✓ F✓
```

## Step 3: Read the full audit trail

```bash
pnpm exec drs audit evidence.json
```

Output:
```
DRS Chain Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Receipt 0 (root — human)
  Issued by:   did:key:z6MkHuman...
  Granted to:  did:key:z6MkAgent1...
  Command:     /mcp/tools/call
  Policy:      max_cost_usd=50, allowed_tools=[web_search,write_file]
  Valid:        2026-03-28 10:30:00 → 2026-05-28 10:30:00
  Consent:      explicit-ui-click at 2026-03-28T10:30:00Z (locale: en-GB)
  Policy hash:  sha256:a1b2c3...  (hash of text user saw)

Receipt 1 (sub-delegation)
  Issued by:   did:key:z6MkAgent1...
  Granted to:  did:key:z6MkAgent2...
  Policy:      max_cost_usd=5, allowed_tools=[web_search]
  Chain hash:  sha256:def456... ✓

Invocation
  Called by:   did:key:z6MkAgent2...
  Tool:        web_search
  Args:        {"estimated_cost_usd": 0.02, "query": "Monad TPS"}
  Budget used: $0.02 of $5.00 (sub) / $50.00 (root)
  Chain:       sha256:abc123... → sha256:def456... ✓

All 3 signatures valid. Chain intact. No revocations found.
```

## Step 4: Verify the consent record

To confirm the user saw human-readable policy (not raw JSON):

```bash
pnpm exec drs policy evidence.json --receipt 0
```

This shows the policy of the root DR. Cross-reference the `policy_hash` in the consent record with:

```bash
pnpm exec drs translate --input-json '{"allowed_tools":["web_search"],"max_cost_usd":50}' \
  | sha256sum
```

If the SHA-256 of the translated text matches `drs_consent.policy_hash`, the user saw legible information.

## What you can prove

From the DRS chain alone, you can prove:
- **Who authorised** the action (the `iss` of the root DR, with their Ed25519 signature)
- **What they authorised** (the `policy` field at every level)
- **When they authorised it** (the `nbf`, `exp`, `iat` fields)
- **What actually happened** (the invocation receipt's `args` field)
- **That consent was meaningful** (the `drs_consent.policy_hash` links to human-readable text)
- **That the chain is intact** (all `prev_dr_hash` values verify, all signatures valid)

You cannot prove these things from server logs alone.
