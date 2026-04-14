# Quick Start

Get from zero to a verified bundle quickly using the current SDK and verifier.

## Prerequisites

- Node.js 20+ and pnpm
- Go 1.22+ (to run `drs-verify` locally)

## 1. Install the SDK

```bash
pnpm add @okeyamy/drs-sdk
```

## 2. Generate a keypair

```bash
pnpm exec drs keygen
```

Current output is plaintext hex:

```text
Ed25519 keypair generated.

DID          : did:key:z6Mk...
Public key   : <hex>
Private key  : <hex>
```

Save the DID and private key securely.

## 3. Issue a root delegation

```typescript
import { issueRootDelegation } from "@okeyamy/drs-sdk";

const privateKey = Uint8Array.from(Buffer.from("YOUR_PRIVATE_KEY_HEX", "hex"));
const now = Math.floor(Date.now() / 1000);

const rootDR = await issueRootDelegation({
  signingKey: privateKey,
  issuerDid: "did:key:z6MkYOUR_DID",
  subjectDid: "did:key:z6MkYOUR_DID",
  audienceDid: "did:key:z6MkAGENT_DID",
  cmd: "/mcp/tools/call",
  policy: {
    allowed_tools: ["web_search"],
    max_cost_usd: 10,
    pii_access: false,
  },
  nbf: now,
  exp: now + 3600,
  rootType: "automated-system",
});
```

## 4. Start `drs-verify`

```bash
cd drs-verify
go run ./cmd/server
```

## 5. Build and verify a bundle

```typescript
import { buildBundle, serialiseBundle, issueInvocation, computeChainHash } from "@okeyamy/drs-sdk";
import { writeFileSync } from "node:fs";

const invocation = await issueInvocation({
  signingKey: agentPrivateKey,
  issuerDid: "did:key:z6MkAGENT_DID",
  subjectDid: "did:key:z6MkYOUR_DID",
  cmd: "/mcp/tools/call",
  args: { tool: "web_search", query: "hello", estimated_cost_usd: 0.01 },
  drChain: [computeChainHash(rootDR)],
  toolServer: "did:key:z6MkTOOL_DID",
});

const bundle = buildBundle({ invocation, receipts: [rootDR] });
writeFileSync("bundle.json", serialiseBundle(bundle));
```

```bash
DRS_VERIFY_URL=http://localhost:8080 pnpm exec drs verify bundle.json
```

Expected successful output starts with:

```text
✓ Chain verified
  Root principal : did:key:z6Mk...
  Chain depth    : 1
```

## Next steps

- [MCP Middleware Integration](./how-to/developers/mcp-middleware.md)
- [Deploy drs-verify](./how-to/operators/deploy-drs-verify.md)
- [Reconstruct a Chain](./how-to/auditors/reconstruct-chain.md)
- [Dev Setup](./how-to/contributors/dev-setup.md)
