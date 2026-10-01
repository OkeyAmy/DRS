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
     │ POST /a2a  (JSON-RPC SendMessage)
     │ X-DRS-Bundle: eyJ...
     ▼
┌──────────────────┐         ┌─────────────────────┐
│ Agent B (Node)   │────────▶│ drs-verify sidecar  │
│ 1. forward req   │  POST   │ ghcr.io/okeyamy/... │
│ 2. /v1/gate      │/v1/gate │                     │
│ 3. if valid →    │◀────────│                     │
│    run task      │         └─────────────────────┘
└──────────────────┘
```

Agent B is structurally the same as an MCP tool server — both verify an
inbound bundle before executing. If you've already set up the
[MCP integration](./mcp-node.md) the code here is almost identical.

## Install

```bash
pnpm add @drs/mcp-server @a2a-js/sdk express
# Until @drs/mcp-server is published, use it as a workspace dependency from this repo.
```

The actual cryptographic verification happens in the `drs-verify` container.
The workspace Node package gives your receiver a secure enforcement point that
rejects invalid chains and body-binding mismatches before task execution.

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

## Gate the official A2A agent

```ts
import express from "express";
import { DefaultRequestHandler, InMemoryTaskStore } from "@a2a-js/sdk/server";
import { jsonRpcHandler, agentCardHandler, UserBuilder } from "@a2a-js/sdk/server/express";
import { createDrsGate, withDrsGate } from "@drs/mcp-server";

const gate = createDrsGate({
  verifyUrl: process.env.DRS_VERIFY_URL ?? "http://localhost:8080",
  protocol: "a2a",
});
const requestHandler = new DefaultRequestHandler(agentCard, new InMemoryTaskStore(), executor);

const app = express();
// The agent card stays public so callers can discover the agent.
app.use("/.well-known/agent-card.json", agentCardHandler({ agentCardProvider: requestHandler }));
// Every JSON-RPC call to /a2a is decided by drs-verify before the SDK sees it.
app.use("/a2a", express.json({ limit: "64kb" }), (req, res, next) =>
  withDrsGate(gate, () => next())(req, res, req.body));
app.use("/a2a", jsonRpcHandler({ requestHandler, userBuilder: UserBuilder.noAuthentication }));
app.listen(3000);
```

The caller signs each request with `cmd: "/a2a/<method>"` and
`args: { ...params, tool: "<method>" }`, so a delegation policy of
`allowed_tools: ["SendMessage"]` restricts which A2A methods an agent may call.
`@drs/mcp-client`'s `createDrsFetch({ signer, protocol: "a2a" })` does this for
the official A2A client (`JsonRpcTransportFactory({ fetchImpl })`).

A changed message, a replayed bundle or an unsigned call is refused with a
JSON-RPC error (`-32010`) before your executor runs.

### Plain HTTP endpoints

For a custom REST endpoint (not the A2A JSON-RPC binding), use
`protocol: "http"`: the whole JSON body must equal the signed args.

## Related

- [Choosing your path](./choosing-your-path.md)
- [MCP in Node](./mcp-node.md)
- [Human consent records](../developers/human-consent.md)
- [A2A middleware reference (Go)](../developers/a2a-middleware.md)
