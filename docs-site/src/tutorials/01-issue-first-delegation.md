# Tutorial: Issue Your First Delegation

This tutorial walks through issuing a root delegation receipt and a sub-delegation from scratch using the TypeScript SDK. You will end up with two signed JWTs linked by `prev_dr_hash`.

## Prerequisites

- Node.js 20+ and pnpm
- `@okeyamy/drs-sdk` installed: `pnpm add @okeyamy/drs-sdk`

## Step 1: Generate two keypairs

```bash
# Human keypair
pnpm exec drs keygen
# Private key: <HUMAN_PRIVATE_KEY>
# DID:         did:key:z6MkHUMAN...

# Agent keypair
pnpm exec drs keygen
# Private key: <AGENT_PRIVATE_KEY>
# DID:         did:key:z6MkAGENT...
```

## Step 2: Issue the root delegation

Create `issue-demo.ts`:

```typescript
import { issueRootDelegation, computeChainHash } from '@okeyamy/drs-sdk';

const humanKey = Uint8Array.from(Buffer.from('HUMAN_PRIVATE_KEY_HEX', 'hex'));
const now = Math.floor(Date.now() / 1000);

const rootDR = await issueRootDelegation({
  signingKey:  humanKey,
  issuerDid:   'did:key:z6MkHUMAN...',
  subjectDid:  'did:key:z6MkHUMAN...',   // human is both issuer and subject at root
  audienceDid: 'did:key:z6MkAGENT...',
  cmd: '/mcp/tools/call',
  policy: {
    allowed_tools: ['web_search', 'write_file'],
    max_cost_usd: 50.00,
    pii_access: false,
    write_access: false,
  },
  nbf: now,
  exp: now + 86400,   // 24 hours
  rootType: 'human',
  consent: {
    method: 'explicit-ui-click',
    timestamp: new Date().toISOString(),
    session_id: 'sess:' + crypto.randomUUID(),
    policy_hash: 'sha256:placeholder', // In production: sha256 of human-readable text
    locale: 'en-GB',
  },
});

console.log('Root DR JWT:', rootDR);
console.log('Root DR hash:', computeChainHash(rootDR));
```

Run it:
```bash
pnpm exec tsx issue-demo.ts
```

## Step 3: Issue a sub-delegation

The agent narrows the policy before delegating further:

```typescript
import { issueSubDelegation } from '@okeyamy/drs-sdk';

const agentKey = Uint8Array.from(Buffer.from('AGENT_PRIVATE_KEY_HEX', 'hex'));

const parentPolicy = {
  allowed_tools: ['web_search', 'write_file'],
  max_cost_usd: 50.00,
  pii_access: false,
  write_access: false,
};

const subDR = await issueSubDelegation({
  signingKey:   agentKey,
  issuerDid:    'did:key:z6MkAGENT...',
  subjectDid:   'did:key:z6MkHUMAN...',    // subject never changes
  audienceDid:  'did:key:z6MkSUBAGENT...',
  cmd: '/mcp/tools/call',
  policy: {
    allowed_tools: ['web_search'],           // tightened: removed write_file
    max_cost_usd: 5.00,                      // tightened: £50 → £5
    pii_access: false,
    write_access: false,
  },
  nbf: now,
  exp: now + 3600,     // 1 hour (shorter than parent's 24 hours)
  parentJwt:    rootDR,
  parentPolicy: parentPolicy,
  parentNbf:    now,
  parentExp:    now + 86400,
});

console.log('Sub-DR JWT:', subDR);
```

## What you built

You now have two JWTs where:
- `subDR` payload contains `"prev_dr_hash": "sha256:{hash of rootDR}"`
- The policy in `subDR` is strictly contained within `rootDR`'s policy
- Any tampering with `rootDR` breaks the hash chain — fails Block B of verification

## What happens if you try to escalate?

Try setting `max_cost_usd: 100` in the sub-delegation (exceeds the parent's 50):

```
DrsError: POLICY_ESCALATION — max_cost_usd 100 exceeds parent limit 50
```

The error fires at issuance — before any signing occurs. You cannot accidentally create an invalid chain.

## Next steps

- [Tutorial: Verify a Bundle](./02-verify-a-bundle.md) — verify the chain you just built
- [Sub-Delegation how-to](../how-to/developers/sub-delegation.md) — detailed attenuation rules
