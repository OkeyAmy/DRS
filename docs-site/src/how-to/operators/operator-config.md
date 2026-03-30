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
  "storage_tier": 2
}
```

Load in TypeScript:

```typescript
import { parseOperatorConfig } from '@drs/sdk';
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
| `"aws-kms"` | AWS KMS — requires `DRS_KMS_KEY_ID` env var |
| `"gcp-kms"` | GCP Cloud KMS — requires `DRS_GCP_KEY_NAME` env var |

> **Security:** Never use `"file"` or `"env"` in production with keys that have regulatory significance. Use `"aws-kms"` or `"gcp-kms"` for production operator keys. See [Key Management](./key-management.md).

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
