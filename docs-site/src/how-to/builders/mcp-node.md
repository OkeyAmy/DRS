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

## Write the enforcement gate

Enforcement is **not a package** — it is a small fail-closed gate you own and
copy into your project. It reads `X-DRS-Bundle`, sends the decoded bundle plus
the actual request body to `drs-verify`, and lets your handler run only when the
chain verifies **and** the body matches the signed `invocation.args`.

`drs-verify` is the only verifier. The gate never makes a trust decision itself
— it forwards to `/verify` and enforces the reject-code contract below. Keeping
it as a handful of lines you own means there is no second implementation to drift
from the verifier, and no extra dependency to secure.

### Reject-code contract

| Condition | HTTP status the gate returns |
|---|---|
| No `X-DRS-Bundle` header | `401` |
| Header is not base64url JSON | `400` |
| `/verify` pre-check rejected (replay `409`, rate limit `429`, store full `503`) | pass the verifier's status through |
| `valid: false` **or** `binding !== "match"` | `403` |
| `/verify` unreachable | `503` |

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

## The gate

Zero dependencies — Node 20+ has `fetch`, `Buffer`, and base64url built in.
Copy this into your project. Express / Fastify / raw `http.Server` all use the
same core.

```ts
// drs-gate.ts
const VERIFY_URL = process.env.DRS_VERIFY_URL ?? "http://localhost:8080";

// Framework-agnostic Express-style middleware. Fails closed at every step.
export async function drsGate(req, res, next) {
  const header = req.headers["x-drs-bundle"];
  if (!header) {
    return res.status(401).json({ error: "missing X-DRS-Bundle header" });
  }

  let bundle;
  try {
    bundle = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
  } catch {
    return res.status(400).json({ error: "malformed X-DRS-Bundle header" });
  }

  let verdict;
  try {
    const r = await fetch(`${VERIFY_URL}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      // Send the exact parsed body so drs-verify can bind it to invocation.args.
      body: JSON.stringify({ ...bundle, body: req.body }),
    });
    // Pass through pre-verification rejections (409 replay, 429, 503).
    if (r.status !== 200) {
      return res.status(r.status).json(await r.json());
    }
    verdict = await r.json();
  } catch (err) {
    return res
      .status(503)
      .json({ error: "verifier unavailable", detail: String(err) });
  }

  // Fail closed: execute only on a valid chain AND a body bound to signed args.
  if (verdict.valid !== true || verdict.binding !== "match") {
    return res.status(403).json({
      error: "DRS_VERIFICATION_FAILED",
      detail: verdict.error ?? { binding: verdict.binding },
    });
  }

  req.drs = verdict.context; // root_principal, leaf_policy, chain_depth, …
  next();
}
```

## Wiring it in Express

```ts
import express from "express";
import { drsGate } from "./drs-gate.js";

const app = express();
app.use(express.json());

app.post("/tools/call", drsGate, async (req, res) => {
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
import { drsGate } from "./drs-gate.js";

const app = Fastify();

app.post(
  "/tools/call",
  {
    preHandler: async (req, reply) => {
      // Adapt the Express-shaped gate to Fastify.
      const next = () => {};
      const expressRes = {
        status: (n: number) => ({ json: (x: unknown) => reply.code(n).send(x) }),
      };
      await drsGate(req as any, expressRes as any, next);
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

## Request-binding behavior

The gate passes the actual parsed request body to `/verify`. The verifier
compares that body with the signed `invocation.args` using JCS. If they differ,
the gate rejects the request with `403` before your handler runs — this is what
stops an agent from signing "refund $10" and sending a body for "$10,000".

### Transport shapes

DRS carries the bundle over HTTP as an `X-DRS-Bundle` header (**Shape 1**), which
is what the gate above enforces and what the normative Go middleware enforces.
There is also a transport convention for pure JSON-RPC MCP where the same
base64url bundle rides in `_meta["X-DRS-Bundle"]` on `tools/call` (**Shape 2**);
the encoding is identical, so one serialised bundle string works on either. If
your server speaks raw JSON-RPC rather than HTTP, read the bundle from
`params._meta["X-DRS-Bundle"]` and use `params.arguments` as the binding body —
the same fail-closed `valid && binding === "match"` check applies. DRS ships no
bundled Node middleware for either shape; enforcement is the small gate you own.

## Related

- [Choosing your path](./choosing-your-path.md)
- [Human consent records](../developers/human-consent.md)
- [Error codes](../../reference/error-codes.md)
- [API endpoints](../../reference/api-endpoints.md)
