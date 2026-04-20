# Integrate DRS with an MCP server (Node / TypeScript)

Your MCP server runs on Node. Agents send tool-call requests with a
`X-DRS-Bundle` header. You want the bundle verified before your business
logic runs. This is the sidecar pattern.

No Go code, no forking DRS, no rebuilding containers.

## Architecture

```
Agent (React Native, web, Node, etc.)
   │
   │  POST /tools/call
   │  X-DRS-Bundle: eyJ...
   │
   ▼
┌────────────────────────────┐       ┌───────────────────────┐
│  Your MCP server (Node)    │──────▶│  drs-verify (Docker)  │
│  1. read bundle from header│ POST  │  ghcr.io/okeyamy/     │
│  2. POST /verify           │ /verify│  drs-verify:latest    │
│  3. if valid → run tool    │       │                       │
│  4. else → 403             │◀──────│                       │
└────────────────────────────┘       └───────────────────────┘
```

## Install nothing extra on your server

DRS verification in this pattern needs only the SDK's **types** — the
actual verification happens inside the `drs-verify` container. So:

```bash
# On your MCP server
pnpm add -D @okeyamy/drs-sdk    # dev-only, for TypeScript types
```

The `-D` is intentional — you import types at compile time, but you do
not call any SDK function on the server.

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
      # Optional: replay protection that survives restart and scales horizontally
      NONCE_STORE_BACKEND: redis
      REDIS_URL: redis://redis:6379/0
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
```

## Middleware for your MCP server

Express / Fastify / raw `http.Server` — the pattern is the same.

```ts
// drs-middleware.ts
import type { ChainBundle, VerificationResult } from "@okeyamy/drs-sdk";

const VERIFY_URL = process.env.DRS_VERIFY_URL ?? "http://localhost:8080";

export async function drsVerify(req, res, next) {
  const bundleHeader = req.headers["x-drs-bundle"];
  if (!bundleHeader || typeof bundleHeader !== "string") {
    return res.status(401).json({
      error: "Missing X-DRS-Bundle header — DRS verification is required.",
    });
  }

  let bundle: ChainBundle;
  try {
    const json = Buffer.from(bundleHeader, "base64url").toString("utf8");
    bundle = JSON.parse(json);
  } catch {
    return res.status(400).json({
      error: "X-DRS-Bundle is not valid base64url JSON.",
    });
  }

  const verifyRes = await fetch(`${VERIFY_URL}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(bundle),
  });
  const result = (await verifyRes.json()) as VerificationResult;

  if (!result.valid) {
    return res.status(403).json(result);
  }

  // Attach the verified context for downstream handlers.
  (req as any).drs = result.context;
  next();
}
```

## Wiring it in Express

```ts
import express from "express";
import { drsVerify } from "./drs-middleware.js";

const app = express();
app.use(express.json());

app.post("/tools/call", drsVerify, async (req, res) => {
  // req.drs is set — it contains RootPrincipal, LeafPolicy, etc.
  const { tool, ...args } = req.body;

  // Enforce policy at the tool layer. `drs-verify` has already checked
  // attenuation; here you enforce execution-time limits.
  const maxCost = req.drs.leaf_policy?.max_cost_usd;
  if (maxCost != null && args.estimated_cost_usd > maxCost) {
    return res.status(403).json({ error: "Exceeds policy.max_cost_usd" });
  }

  const result = await runTool(tool, args);
  res.json(result);
});

app.listen(3000);
```

## Wiring it in Fastify

```ts
import Fastify from "fastify";
import { drsVerify } from "./drs-middleware.js";

const app = Fastify();

app.post(
  "/tools/call",
  {
    preHandler: async (req, reply) => {
      // Adapt the Express-shaped middleware to Fastify.
      const next = () => {};
      const expressRes = {
        status: (n: number) => ({ json: (x: unknown) => reply.code(n).send(x) }),
      };
      await drsVerify(req as any, expressRes as any, next);
    },
  },
  async (req) => {
    return { ok: true, drs: (req as any).drs };
  },
);

app.listen({ port: 3000 });
```

## Performance notes

- `drs-verify` handles DID resolution caching, nonce replay checking,
  and revocation lookups in one round-trip. Typical /verify latency
  against a local container is **5–15 ms** (single-digit when caches
  are warm).
- If the 5–15 ms hop matters, switch to the
  [embedded Go middleware pattern](../developers/mcp-middleware.md) —
  but that forces your tool server to be in Go.

## Request-binding caveat

The middleware above verifies the delegation chain. It does **not**
yet compare the signed `invocation.args` against the actual request
body. If an attacker replaces the body while keeping the header, DRS
will still say "valid" — because the header's invocation and the body
are decoupled.

Either:

1. **Execute from the signed args** (preferred): trust
   `req.drs.invocation.args` instead of `req.body` when invoking the
   tool. This is the strongest guarantee.
2. **Hash-compare**: in your handler, canonicalise the parts of
   `req.body` that correspond to `invocation.args` and reject if they
   differ.

The first option is the DRS-native answer. The invocation receipt *is*
the authenticated payload.

## Related

- [Choosing your path](./choosing-your-path.md)
- [Human consent records](../developers/human-consent.md)
- [Error codes](../../reference/error-codes.md)
- [API endpoints](../../reference/api-endpoints.md)
