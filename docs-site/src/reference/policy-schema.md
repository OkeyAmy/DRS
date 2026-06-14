# Policy Schema

The `policy` object defines capability constraints on a delegation. All fields are optional — an absent field means no constraint for that dimension.

## Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `allowed_tools` | string[] | Unrestricted | Allowlist of MCP tool names. If absent, all tools are permitted. |
| `max_cost_usd` | number | Unlimited | Maximum USD cost per invocation. Checked against the agent-declared `args.estimated_cost_usd` (see caveat below). |
| `pii_access` | boolean | `false` | Whether access to personally identifiable information is permitted. |
| `write_access` | boolean | `false` | Whether write operations are permitted. |
| `max_calls` | integer | Unlimited | Maximum total invocations. Tracked by the agent runtime, not enforced by `verify_chain`. |
| `allowed_resources` | string[] | Unrestricted | Allowlist of resource URIs. |

## Policy evaluation (Block D)

Policies are evaluated **conjunctively**: every policy in the chain must pass. The invocation `args` are checked against every DR's policy from root to the immediate sub-DR.

For each DR's policy:

```
PASS if:
  (policy.allowed_tools is absent or ["*"]) OR (args.tool exists AND args.tool ∈ policy.allowed_tools)
  AND
  (policy.max_cost_usd is absent) OR (args.estimated_cost_usd exists AND args.estimated_cost_usd ≤ policy.max_cost_usd)
  AND
  (policy does not constrain pii_access or permits it) OR (args.pii_access exists AND args.pii_access is false)
  AND
  (policy does not constrain write_access or permits it) OR (args.write_access exists AND args.write_access is false)
```

Missing invocation fields fail closed when a policy constrains that dimension.

### Caveat: `max_cost_usd` is a self-declared bound, not a metered one

`verify_chain` compares `policy.max_cost_usd` against `args.estimated_cost_usd`
— a value the **agent itself writes** into the invocation it signs. The
verifier confirms the signed declaration does not exceed the policy; it does
**not** measure actual cost.

This makes `max_cost_usd` meaningful only when the cost is **known before the
call** and the caller is the party being constrained — for example a financial
transaction amount, or a fixed-fee API where the price is fixed in advance. In
that setting a downstream tool server can cross-check `estimated_cost_usd`
against the real transaction it is about to execute and reject a mismatch.

It is **not** a reliable control for variable, after-the-fact costs such as LLM
inference (token usage is unknown until the model responds). An agent can
declare `estimated_cost_usd: 0.01` and still incur far more; the receipt only
proves what was *claimed*, not what was *spent*. For LLM spend control, meter at
the model gateway and treat `max_cost_usd` as an attestation of intent, not an
enforced ceiling.

Like `max_calls`, true spend enforcement lives in the runtime/gateway, not in
receipt verification.

## Attenuation rules

Sub-delegation policies must be strict subsets (attenuation) of the parent:

| Parent field | Child constraint |
|---|---|
| `allowed_tools: [A, B, C]` | Child `allowed_tools` ⊆ `{A, B, C}` — cannot add new tools |
| `max_cost_usd: N` | Child `max_cost_usd` ≤ `N` — cannot increase limit |
| `pii_access: false` | Child must have `pii_access: false` — cannot re-enable |
| `write_access: false` | Child must have `write_access: false` — cannot re-enable |
| `max_calls: N` | Child `max_calls` ≤ `N` — cannot increase limit |

## Example policies

**Minimal (research agent, read-only):**
```json
{
  "allowed_tools": ["web_search", "read_file"],
  "max_cost_usd": 10.00,
  "pii_access": false,
  "write_access": false
}
```

**Operator standing policy (automated system):**
```json
{
  "allowed_tools": ["web_search", "write_file", "read_file", "execute_code"],
  "max_cost_usd": 500.00,
  "pii_access": false,
  "write_access": true,
  "max_calls": 10000
}
```

**Single-tool sub-delegation (tight):**
```json
{
  "allowed_tools": ["web_search"],
  "max_cost_usd": 1.00,
  "pii_access": false,
  "write_access": false,
  "max_calls": 10
}
```
