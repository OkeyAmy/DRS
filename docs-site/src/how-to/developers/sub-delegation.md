# Sub-Delegation

Sub-delegations allow an agent to pass a subset of its authority to another agent. The child policy must not escalate beyond the parent — this is the Principle of Least Authority (POLA).

## Attenuation rules

| Parent policy field | Child constraint |
|---|---|
| `allowed_tools: [A, B, C]` | Child `allowed_tools` must be ⊆ `{A, B, C}` |
| `max_cost_usd: 50` | Child `max_cost_usd` must be ≤ `50` |
| `pii_access: false` | Child must have `pii_access: false` |
| `write_access: false` | Child must have `write_access: false` |
| `max_calls: 100` | Child `max_calls` must be ≤ `100` |
| `exp: T` | Child `exp` must be ≤ `T` |
| `nbf: T` | Child `nbf` must be ≥ `T` |

Violation at issuance throws `DrsError: POLICY_ESCALATION`. Violation in a received bundle fails Block D of `verify_chain`.

## Example: narrowing authority

```typescript
import { issueSubDelegation } from '@drs/sdk';

const parentPolicy = {
  allowed_tools: ['web_search', 'write_file', 'read_file'],
  max_cost_usd: 50.00,
  pii_access: false,
  write_access: true,
};

// Agent narrows authority before delegating
const subDR = await issueSubDelegation({
  signingKey:   agentPrivateKey,
  issuerDid:    'did:key:z6MkAgent1...',
  subjectDid:   'did:key:z6MkHuman...',   // always the original human
  audienceDid:  'did:key:z6MkAgent2...',
  cmd: '/mcp/tools/call',
  policy: {
    allowed_tools: ['web_search'],         // ⊆ parent's [web_search, write_file, read_file]
    max_cost_usd:  5.00,                   // ≤ parent's 50
    pii_access:    false,                  // same (can't relax)
    write_access:  false,                  // tightened: parent allowed true
  },
  nbf:          parentNbf,                 // ≥ parent's nbf
  exp:          parentNbf + 3600,          // ≤ parent's exp
  parentJwt:    parentDR,
  parentPolicy: parentPolicy,
  parentNbf:    parentNbf,
  parentExp:    parentExp,
});
```

## What happens if you escalate?

```typescript
// This throws POLICY_ESCALATION:
await issueSubDelegation({
  policy: {
    allowed_tools: ['web_search', 'write_file', 'execute_code'],  // added execute_code
    max_cost_usd: 100,                                             // exceeded parent's 50
  },
  // ...
});
// DrsError: POLICY_ESCALATION — allowed_tools contains execute_code not in parent policy
```

The error fires before any signing. Invalid chains cannot be created.

## The `sub` field never changes

The `sub` (subject) field represents the original resource owner — always the human at the root of the chain. It must remain identical through every sub-delegation:

```
rootDR.sub  = "did:key:z6MkHuman..."
subDR.sub   = "did:key:z6MkHuman..."   ← same
inv.sub     = "did:key:z6MkHuman..."   ← same
```

Changing `sub` in a sub-delegation is a structural error caught by Block B.
