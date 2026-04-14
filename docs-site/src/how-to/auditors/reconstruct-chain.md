# Reconstruct a Delegation Chain

You can reconstruct and verify any delegation chain from stored receipts without operator cooperation. All you need are the JWT strings and the DIDs.

## Step 1: Obtain the bundle

If the operator has already provided `bundle.json`, use that directly.

Or assemble a bundle manually from JWT strings:

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

This verifies the chain through `drs-verify`. The verifier reads the issuer DIDs
from the JWTs and resolves `did:key` locally from the DID bytes.

## Step 3: Read the audit trail

```bash
pnpm exec drs audit evidence.json
```

Current `drs audit` output is intentionally compact. It prints bundle version,
receipt count, the main fields from each receipt, and the invocation's issuer,
command, and tool server.

## Step 4: Verify the consent record

To confirm the user saw human-readable policy (not raw JSON):

The CLI does not read policies out of a bundle by receipt index. Instead,
extract the root receipt payload or save its `policy` object to a separate JSON
file, then run:

```bash
pnpm exec drs policy root-policy.json
```

Use your application-side consent records to relate the translated policy text
back to the stored `policy_hash`.

## What you can prove

From the DRS chain alone, you can prove:
- **Who authorised** the action (the `iss` of the root DR, with their Ed25519 signature)
- **What they authorised** (the `policy` field at every level)
- **When they authorised it** (the `nbf`, `exp`, `iat` fields)
- **What actually happened** (the invocation receipt's `args` field)
- **That consent was meaningful** (the `drs_consent.policy_hash` links to human-readable text)
- **That the chain is intact** (all `prev_dr_hash` values verify, all signatures valid)

You cannot prove these things from server logs alone.
