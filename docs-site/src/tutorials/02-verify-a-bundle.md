# Tutorial: Verify a Bundle

This tutorial builds on [Issue Your First Delegation](./01-issue-first-delegation.md). You will wrap the delegation chain in a bundle, send it to drs-verify, and confirm it passes all six verification blocks.

## Prerequisites

- Go 1.22+ with `drs-verify` source
- The `rootDR` and `subDR` JWTs from Tutorial 1
- `@drs/sdk` installed

## Step 1: Start drs-verify

```bash
cd drs-verify
go run ./cmd/server
# drs-verify listening on :8080
```

## Step 2: Issue an invocation receipt

```typescript
import { issueInvocation, computeChainHash, buildBundle, serialiseBundle } from '@drs/sdk';
import { writeFileSync } from 'fs';

const agentKey = Uint8Array.from(Buffer.from('SUBAGENT_PRIVATE_KEY', 'base64url'));

const invocation = await issueInvocation({
  signingKey:  agentKey,
  issuerDid:   'did:key:z6MkSUBAGENT...',
  subjectDid:  'did:key:z6MkHUMAN...',
  cmd: '/mcp/tools/call',
  args: {
    tool: 'web_search',
    query: 'Monad TPS benchmarks',
    estimated_cost_usd: 0.02,
  },
  drChain: [
    computeChainHash(rootDR),
    computeChainHash(subDR),
  ],
  toolServer: 'did:key:z6MkTOOLSERVER...',
});

// Build and serialise the bundle
const bundle = buildBundle({
  invocation,
  receipts: [rootDR, subDR],
});

writeFileSync('bundle.json', serialiseBundle(bundle));
console.log('Bundle written to bundle.json');
```

## Step 3: Verify via CLI

```bash
DRS_VERIFY_URL=http://localhost:8080 pnpm exec drs verify bundle.json
```

Expected output:
```
✓ Bundle verified
  Chain depth:    2
  Root principal: did:key:z6MkHUMAN...
  Subject:        did:key:z6MkHUMAN...
  Command:        /mcp/tools/call
  Policy result:  pass
  Blocks:         A✓ B✓ C✓ D✓ E✓ F✓
```

## Step 4: Verify via HTTP API directly

```bash
curl -s -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d @bundle.json | jq .
```

```json
{
  "valid": true,
  "chain_depth": 2,
  "root_principal": "did:key:z6MkHUMAN...",
  "subject": "did:key:z6MkHUMAN...",
  "command": "/mcp/tools/call",
  "policy_result": "pass"
}
```

## Step 5: Test a rejection

Tamper with the bundle — modify one character in `rootDR`:

```bash
# Create a tampered bundle
cat bundle.json | sed 's/"receipts":\["eyJ/\"receipts\":[\"fakeXXX/' > tampered.json
DRS_VERIFY_URL=http://localhost:8080 pnpm exec drs verify tampered.json
```

Expected:
```
✗ Verification failed
  Block:  B (structural integrity)
  Error:  CHAIN_HASH_MISMATCH — prev_dr_hash mismatch at chain index 1
```

## Step 6: Print the full audit trail

```bash
pnpm exec drs audit bundle.json
```

This prints a human-readable breakdown of every receipt in the chain: issuers, audiences, policies, temporal bounds, and consent records.

## Next steps

- [End-to-End Trace](./03-end-to-end-trace.md) — watch the full lifecycle including tool server execution
- [MCP Middleware Integration](../how-to/developers/mcp-middleware.md) — integrate this verification flow into a real MCP server
