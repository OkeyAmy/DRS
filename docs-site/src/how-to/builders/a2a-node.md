# Integrate DRS with an A2A agent (Node / TypeScript)

Agent-to-Agent (A2A) differs from MCP in shape — both agents sit at
equal standing and exchange tasks — but the DRS integration story is
the same: the caller attaches a receipt bundle, the receiver verifies it
before acting.

This guide covers the receiver side in Node. The caller side is the
same as [React Native issuance](./react-native.md) and
[MCP Node integration](./mcp-node.md) — you issue an invocation with
`issueInvocation`.

## Architecture

```
Agent A (initiator)                  Agent B (receiver)
     │
     │ POST /a2a/task
     │ X-DRS-Bundle: eyJ...
     ▼
┌──────────────────┐         ┌─────────────────────┐
│ Agent B (Node)   │────────▶│ drs-verify sidecar  │
│ 1. extract hdr   │  POST   │ ghcr.io/okeyamy/... │
│ 2. /verify       │ /verify │                     │
│ 3. if valid →    │◀────────│                     │
│    run task      │         └─────────────────────┘
└──────────────────┘
```

Agent B is structurally the same as an MCP tool server — both verify an
inbound bundle before executing. If you've already set up the
[MCP integration](./mcp-node.md) the code here is almost identical.

## Install

```bash
pnpm add -D @okeyamy/drs-sdk
```

Type-only. The actual verification happens in the `drs-verify`
container.

## Compose with Redis for shared replay protection

If Agent B is horizontally scaled across multiple instances, you need
shared replay protection or an attacker can submit the same bundle to
each replica in turn.

```yaml
services:
  agent-b:
    build: .
    deploy:
      replicas: 3
    environment:
      DRS_VERIFY_URL: http://drs-verify:8080

  drs-verify:
    image: ghcr.io/okeyamy/drs-verify:latest
    environment:
      NONCE_STORE_BACKEND: redis
      REDIS_URL: redis://redis:6379/0
    deploy:
      replicas: 2      # drs-verify itself can also scale — state is in Redis

  redis:
    image: redis:7-alpine
```

## A2A middleware

```ts
// a2a-middleware.ts
import type { ChainBundle, VerificationResult } from "@okeyamy/drs-sdk";

const VERIFY_URL = process.env.DRS_VERIFY_URL ?? "http://localhost:8080";

export async function drsA2A(req, res, next) {
  const bundleHeader = req.headers["x-drs-bundle"];
  if (!bundleHeader || typeof bundleHeader !== "string") {
    return res.status(401).json({ error: "Missing X-DRS-Bundle" });
  }

  const bundle: ChainBundle = JSON.parse(
    Buffer.from(bundleHeader, "base64url").toString("utf8"),
  );

  const r = await fetch(`${VERIFY_URL}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(bundle),
  });
  const result = (await r.json()) as VerificationResult;

  if (!result.valid) return res.status(403).json(result);

  (req as any).drs = result.context;
  next();
}
```

## Task handler

```ts
import express from "express";
import { drsA2A } from "./a2a-middleware.js";

const app = express();
app.use(express.json({ limit: "1mb" }));

app.post("/a2a/task", drsA2A, async (req, res) => {
  // req.drs.root_principal is the original human/organisation
  // req.drs.leaf_policy is the effective policy AFTER attenuation
  const { task_type, payload } = req.body;

  // A2A-specific: enforce that the task matches what's allowed by policy.
  const allowedTools = req.drs.leaf_policy?.allowed_tools ?? [];
  if (allowedTools.length > 0 && !allowedTools.includes(task_type)) {
    return res.status(403).json({
      error: "task_type not in allowed_tools",
      allowed: allowedTools,
    });
  }

  const result = await runA2ATask(task_type, payload, {
    onBehalfOf: req.drs.root_principal,
  });
  res.json(result);
});

app.listen(3000);
```

## JSON-RPC variant

Some A2A deployments use JSON-RPC instead of plain HTTP. The DRS
spec allows the bundle to live in `_meta["X-DRS-Bundle"]` instead of
a header.

```ts
app.post("/a2a/rpc", express.json(), async (req, res) => {
  const bundleStr = req.body?._meta?.["X-DRS-Bundle"];
  if (!bundleStr) return res.status(401).json({ error: "missing bundle" });

  const bundle = JSON.parse(
    Buffer.from(bundleStr, "base64url").toString("utf8"),
  );
  const r = await fetch(`${VERIFY_URL}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(bundle),
  });
  const result = await r.json();

  if (!result.valid) {
    return res.json({
      jsonrpc: "2.0",
      id: req.body.id,
      error: { code: -32001, message: "DRS verification failed", data: result.error },
    });
  }

  // dispatch on req.body.method ...
});
```

## Related

- [Choosing your path](./choosing-your-path.md)
- [MCP in Node](./mcp-node.md)
- [Human consent records](../developers/human-consent.md)
- [A2A middleware reference (Go)](../developers/a2a-middleware.md)
