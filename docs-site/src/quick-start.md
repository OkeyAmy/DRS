# Quick Start

Get from zero to a verified delegation bundle in under 10 minutes.

## Prerequisites

- Node.js 20+ and pnpm
- Go 1.22+ (to run drs-verify locally)

## 1. Install the SDK

```bash
pnpm add @drs/sdk
```

## 2. Generate a keypair

```bash
pnpm exec drs keygen
```

Output:
```
Private key (keep secret): <base64url-encoded 32 bytes>
DID:                        did:key:z6Mk...
```

Save both values. The private key signs delegation receipts. The DID is your identity on the chain.

## 3. Issue a root delegation

```typescript
import { issueRootDelegation } from '@drs/sdk';

const privateKey = Uint8Array.from(Buffer.from('YOUR_PRIVATE_KEY', 'base64url'));
const now = Math.floor(Date.now() / 1000);

const rootDR = await issueRootDelegation({
  signingKey:  privateKey,
  issuerDid:   'did:key:z6MkYOUR_DID',
  subjectDid:  'did:key:z6MkYOUR_DID',   // human is both issuer and subject at root
  audienceDid: 'did:key:z6MkAGENT_DID',
  cmd: '/mcp/tools/call',
  policy: {
    allowed_tools: ['web_search'],
    max_cost_usd: 10.00,
    pii_access: false,
  },
  nbf: now,
  exp: now + 3600,          // 1 hour
  rootType: 'automated-system',
});

console.log('Root DR JWT:', rootDR);
```

## 4. Start drs-verify locally

```bash
cd drs-verify
go run ./cmd/server
# drs-verify listening on :8080
```

## 5. Build and verify a bundle

```typescript
import { buildBundle, serialiseBundle, issueInvocation, computeChainHash } from '@drs/sdk';

const invocation = await issueInvocation({
  signingKey:  agentPrivateKey,
  issuerDid:   'did:key:z6MkAGENT_DID',
  subjectDid:  'did:key:z6MkYOUR_DID',
  cmd: '/mcp/tools/call',
  args: { tool: 'web_search', query: 'hello', estimated_cost_usd: 0.01 },
  drChain: [computeChainHash(rootDR)],
  toolServer: 'did:key:z6MkTOOL_DID',
});

const bundle = buildBundle({ invocation, receipts: [rootDR] });
import { writeFileSync } from 'fs';
writeFileSync('bundle.json', serialiseBundle(bundle));
```

```bash
DRS_VERIFY_URL=http://localhost:8080 pnpm exec drs verify bundle.json
```

Expected output:
```
✓ Bundle verified
  Chain depth:    1
  Root principal: did:key:z6Mk...
  Subject:        did:key:z6Mk...
  Command:        /mcp/tools/call
  Policy result:  pass
  Blocks:         A✓ B✓ C✓ D✓ E✓ F✓
```

## Next steps

- **Developers:** [MCP Middleware Integration](./how-to/developers/mcp-middleware.md) — integrate DRS into your tool server in one day
- **Operators:** [Deploy drs-verify](./how-to/operators/deploy-drs-verify.md) — run a production verification server
- **Auditors:** [Reconstruct a Chain](./how-to/auditors/reconstruct-chain.md) — verify audit evidence independently
- **Contributors:** [Dev Setup](./how-to/contributors/dev-setup.md) — get the full codebase running
