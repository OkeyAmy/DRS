# Quick Start

Get from zero to a verified bundle using the **published** SDK and
verifier container. You do not need to clone this repository.

> New to DRS? First read
> [You do not need to fork](./how-to/builders/no-fork-required.md) and
> [Which part of DRS do I install?](./how-to/builders/choosing-your-path.md)
> to map your role to the right artifact.

## Prerequisites

- Node.js 20+ and pnpm
- Docker (for the verifier). No Go toolchain required.

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

## 4. Start `drs-verify` (from the published image)

```bash
docker run --rm -d -p 8080:8080 --name drs-verify \
  ghcr.io/okeyamy/drs-verify:latest

# Confirm it's up
curl http://localhost:8080/readyz
# {"status":"ready"}
```

No clone, no Go build — the image is published to GHCR from this
repo's release pipeline.

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

Pick your path:

- Building a mobile agent →
  [React Native / Expo integration](./how-to/builders/react-native.md)
- Building an MCP tool server in Node →
  [MCP server integration (Node)](./how-to/builders/mcp-node.md)
- Building an A2A agent in Node →
  [A2A agent integration (Node)](./how-to/builders/a2a-node.md)
- Building any other Node backend →
  [Non-MCP Node backend integration](./how-to/builders/node-backend.md)
- Building in Go →
  [MCP Middleware Integration (Go)](./how-to/developers/mcp-middleware.md)
- Operating the verifier →
  [Deploy drs-verify](./how-to/operators/deploy-drs-verify.md)
- Reviewing evidence →
  [Reconstruct a Chain](./how-to/auditors/reconstruct-chain.md)
- Contributing a change →
  [Dev Setup](./how-to/contributors/dev-setup.md)
