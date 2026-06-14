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

Current output keeps private key material out of stdout:

```text
Ed25519 keypair generated.

DID          : did:key:z6Mk...
Public key   : <hex>
Private key  : written to /home/you/.drs/signing.key
```

Save the DID and protect the private key file. Use `drs keygen --out <path>`
when you need a different development key location.

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

> `max_cost_usd` is a self-declared bound, not a metered one — it is reliable
> only for costs known before the call (e.g. a transaction amount), not for LLM
> token spend. See the
> [`max_cost_usd` caveat](./reference/policy-schema.md#caveat-max_cost_usd-is-a-self-declared-bound-not-a-metered-one).

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

The agent is a **separate identity** from the operator — it has its own
keypair (the `audienceDid` the root delegation was issued to). In a real
deployment the agent generates and holds this key itself; here we just need
its private key to sign the invocation.

```typescript
import { createInvocationBundle, serialiseBundle } from "@okeyamy/drs-sdk";
import { writeFileSync } from "node:fs";

// The agent's own key — the holder of the audienceDid from step 3.
const agentPrivateKey = Uint8Array.from(Buffer.from("AGENT_PRIVATE_KEY_HEX", "hex"));
const agentDid = "did:key:z6MkAGENT_DID";

const bundle = await createInvocationBundle({
  rootReceipt: rootDR,
  signingKey: agentPrivateKey,
  issuerDid: agentDid,
  subjectDid: "did:key:z6MkYOUR_DID",
  toolServer: "did:key:z6MkTOOL_DID",
  tool: "web_search",
  args: { query: "hello", estimated_cost_usd: 0.01 },
});

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
