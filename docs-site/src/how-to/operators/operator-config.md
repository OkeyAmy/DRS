# Operator Configuration

Machine-to-machine deployments (no live human in the delegation loop) use an `OperatorConfig` loaded at startup. This governs how the operator issues root delegations, manages key material, and handles out-of-policy requests.

## Configuration file format

```json
{
  "drs_root_type": "automated-system",
  "operator_did": "did:key:z6MkOperator...",
  "operator_key_management": "env",
  "standing_policy": {
    "allowed_tools": ["web_search", "write_file", "read_file"],
    "max_cost_usd": 100.00,
    "pii_access": false,
    "write_access": true
  },
  "renewal_rules": {
    "auto_renew": true,
    "session_ttl_hours": 8,
    "max_renewal_count": 0
  },
  "escalation": {
    "target_type": "organisation",
    "supervisor_did": "did:key:z6MkSupervisor...",
    "fallback": "deny"
  },
  "storage_tier": 1
}
```

Load in TypeScript:

```typescript
import { parseOperatorConfig } from '@okeyamy/drs-sdk';
import { readFileSync } from 'fs';

const cfg = parseOperatorConfig(
  JSON.parse(readFileSync('operator-config.json', 'utf-8'))
);
// Throws DrsError: INVALID_OPERATOR_CONFIG if any field is invalid
```

## Key management options

| `operator_key_management` | Where the key lives |
|---|---|
| `"env"` | `DRS_OPERATOR_KEY` environment variable (base64url-encoded 32 bytes) |
| `"file"` | Path in `operator_key_path` — raw 32-byte Ed25519 key file |
| `"aws-kms"` | Configuration value reserved for an external AWS KMS signer integration |
| `"gcp-kms"` | Configuration value reserved for an external GCP Cloud KMS signer integration |

> **Security:** Never use `"file"` or `"env"` in production with keys that have regulatory significance unless your deployment wraps signing in a separately reviewed secrets boundary.

> **Implementation note:** these values are accepted by the configuration model only.
> This repository does not currently implement KMS-backed signing. Treat KMS/HSM
> signing as an external integration or production-hardening task, not as built-in
> runtime support.

## Root type

| `drs_root_type` | When to use |
|---|---|
| `"automated-system"` | Fully automated operator — no human consent loop |
| `"organisation"` | Represents an organisation that has a defined approval process |

Human-rooted delegations (`"human"`) are not used in `OperatorConfig` — they require a live human consent interaction per session.

## Renewal rules

| Field | Description |
|---|---|
| `auto_renew` | If `true`, the agent runtime renews the session delegation before it expires |
| `session_ttl_hours` | How long each session delegation is valid |
| `max_renewal_count` | Maximum renewals per original session. `0` = unlimited |

## Escalation behaviour

When an agent requests an action exceeding the `standing_policy`:
1. Request is held (not rejected immediately)
2. Notification sent to `supervisor_did`
3. If supervisor approves: a new sub-DR is issued with expanded policy
4. If supervisor does not respond within timeout: `fallback` applies

| `fallback` | Behaviour |
|---|---|
| `"deny"` | Request is rejected — safe default |
| `"allow-degraded"` | Request is allowed with a degraded policy — only use when availability is more critical than strict policy enforcement |

> **Security:** `"allow-degraded"` should never be the default in regulated deployments. Discuss with your security team before enabling it.

## Storage tier field

`storage_tier` records the operator's intended receipt-retention posture. The
configuration schema accepts `0` through `5` so operator files can use the full
DRS vocabulary, but not every tier is implemented by the current verifier.

| Value | Current verifier behavior |
|---|---|
| `0` | In-memory store when `STORE_DIR` is unset |
| `1` | Local filesystem store when `STORE_DIR` is set |
| `2` | Roadmap only — no S3-compatible object-store backend in this release |
| `3` | Filesystem store plus RFC 3161 timestamp attempt when `STORE_DIR` and `TSA_URL` are set; WORM must be supplied by deployment infrastructure |
| `4` | Same backend as Tier 3, with timestamp verification/reporting requested by callers |
| `5` | Roadmap only — no Ethereum anchoring backend in this release |

See [Storage Tiers](./storage-tiers.md) for the canonical status table.
