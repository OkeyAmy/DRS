# Integrate DRS with an MCP server (Node / TypeScript)

Your MCP server runs on Node with the official MCP TypeScript SDK. Agents sign
each `tools/call` with DRS. You want every tool call verified before it runs.
This is the sidecar pattern: protocol rules live in `drs-verify`, your server
holds none.

No Go code, no forking DRS, no rebuilding containers.

## Architecture

```
Agent (React Native, web, Node, etc.)
   │
   │  POST /mcp   (JSON-RPC tools/call)
   │  X-DRS-Bundle: eyJ...   or params._meta["xyz.okeyamy.drs/bundle"]
   │
   ▼
┌────────────────────────────┐       ┌───────────────────────┐
│  Your MCP server (Node)    │──────▶│  drs-verify (Docker)  │
│  1. forward the request    │ POST  │  ghcr.io/okeyamy/     │
│  2. POST /v1/gate          │/v1/gate│  drs-verify:latest    │
│  3. allow → MCP SDK        │       │                       │
│  4. deny → JSON-RPC error  │◀──────│                       │
└────────────────────────────┘       └───────────────────────┘
```

## Install

```bash
pnpm add @drs/mcp-server @modelcontextprotocol/server @modelcontextprotocol/node
# Until @drs/mcp-server is published, use it as a workspace dependency from this repo.
```

## Gate the official MCP server

```ts
import { createServer } from "node:http";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createDrsGate, withDrsGate } from "@drs/mcp-server";

const gate = createDrsGate({
  verifyUrl: process.env.DRS_VERIFY_URL ?? "http://localhost:8080",
  protocol: "mcp",
});

function makeServer() {
  const server = new McpServer({ name: "tools", version: "1.0.0" });
  // server.registerTool(...) — your tools, unchanged.
  return server;
}

// createMcpHandler serves MCP 2025-11-25 and 2026-07-28 clients.
const mcp = toNodeHandler(createMcpHandler(makeServer));
createServer(withDrsGate(gate, (req, res, body) => mcp(req, res, body))).listen(3000);
```

What passes without a bundle: `initialize`, `server/discover`, `tools/list`,
notifications and stream `GET`s. What needs one: every `tools/call`, signed for
`{ ...arguments, tool: name }` under `cmd: "/mcp/tools/call"`.

A refused call is answered with the JSON-RPC error drs-verify produced
(`error.code` `-32010`, `error.data.code` e.g. `BINDING_MISMATCH`), HTTP 403 —
never 401, which MCP clients would treat as an OAuth challenge. If drs-verify is
unreachable the gate fails closed with 503.

Inside a tool, the verified context (root principal, leaf policy) is on
`req.drs` in the Node handler.

## stdio servers

```ts
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createDrsGate, DrsGatedServerTransport } from "@drs/mcp-server";

const gate = createDrsGate({ verifyUrl: process.env.DRS_VERIFY_URL!, protocol: "mcp" });
await makeServer().connect(new DrsGatedServerTransport(new StdioServerTransport(), gate));
```

## The agent side

```ts
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createChainSigner, createDrsFetch } from "@drs/mcp-client";

const signer = createChainSigner({ receipts, signingKey, issuerDid, subjectDid, toolServer });
const client = new Client({ name: "agent", version: "1.0.0" });
await client.connect(
  new StreamableHTTPClientTransport(new URL("http://tools.example/mcp"), {
    fetch: createDrsFetch({ signer, protocol: "mcp" }),
  }),
);
await client.callTool({ name: "web_search", arguments: { query: "weather" } });
```

Each call is signed with the arguments it actually sends and a fresh `jti`. For
stdio, wrap the client transport: `new DrsClientTransport(new StdioClientTransport(...), signer)`.

## Performance notes

- One localhost round-trip to `drs-verify` per gated call; handshakes and
  discovery are decided without cryptography. Measured `/verify` p95 is
  5.4 ms at 300 rps (see the drs-bench repo).
- Every request, including handshakes, reaches the sidecar from your server's
  single IP. Raise `RATE_LIMIT_PER_IP` on the sidecar to cover your total
  traffic, or the verifier's per-IP limit becomes your server's limit.
- If that hop matters, use the [embedded Go middleware](../developers/mcp-middleware.md).

## Docker Compose for local dev

```yaml
# docker-compose.yml at the root of YOUR project
services:
  mcp-server:
    build: .
    ports:
      - "3000:3000"
    environment:
      DRS_VERIFY_URL: http://drs-verify:8080
    depends_on:
      - drs-verify

  drs-verify:
    image: ghcr.io/okeyamy/drs-verify:latest
    environment:
      LISTEN_ADDR: ":8080"
      LOG_FORMAT: json
      # Required: invocations addressed to another tool server are refused.
      SERVER_IDENTITY: did:web:tools.example
      # Optional: replay protection that survives restart and scales horizontally
      NONCE_STORE_BACKEND: redis
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
```

## Related

- [Choosing your path](./choosing-your-path.md)
- [Human consent records](../developers/human-consent.md)
- [Error codes](../../reference/error-codes.md)
- [API endpoints](../../reference/api-endpoints.md)
