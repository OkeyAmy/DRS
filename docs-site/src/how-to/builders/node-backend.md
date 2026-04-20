# Integrate DRS with a non-MCP / non-A2A Node backend

Plenty of real-world services aren't MCP tool servers or A2A agents —
they're ordinary APIs that want to enforce "this request came from an
authorised delegation chain" before doing work. DRS still fits.

This guide covers three patterns for adding DRS to an existing Node
backend:

1. **Express/Fastify middleware** — add one `app.use` call.
2. **Reverse proxy in front of an unchanged backend** — zero application
   changes.
3. **Per-route opt-in** — some routes enforce DRS, others don't.

## Pattern 1: one-line middleware

Same shape as the [MCP Node integration](./mcp-node.md). Summary:

```ts
import { drsVerify } from "./drs-middleware.js";

app.use(drsVerify);                     // enforce on every route
app.use("/admin", drsVerify);           // enforce on a subtree only
```

The middleware reads `X-DRS-Bundle`, POSTs to the sidecar verifier, and
either 401s/403s or attaches `req.drs` and calls `next()`. See the MCP
guide for the full implementation.

## Pattern 2: reverse proxy (zero app changes)

Put `drs-verify` and a small proxy container in front of your existing
backend. Your app gets requests as if DRS were transparent, and a
header named `X-DRS-Principal` is added by the proxy so the app can
learn who authorised the call.

Cloudflare Workers, envoy, nginx with lua, or a tiny Node proxy all
work. Here's the Node version:

```ts
// proxy.ts
import http from "node:http";
import { createProxyServer } from "http-proxy";

const VERIFY_URL = "http://drs-verify:8080";
const UPSTREAM = "http://my-existing-backend:5000";

const proxy = createProxyServer({ target: UPSTREAM, changeOrigin: true });

http.createServer(async (req, res) => {
  const bundleHeader = req.headers["x-drs-bundle"];
  if (!bundleHeader) {
    res.writeHead(401, { "content-type": "application/json" });
    return res.end(JSON.stringify({ error: "missing X-DRS-Bundle" }));
  }
  const bundle = JSON.parse(
    Buffer.from(bundleHeader as string, "base64url").toString("utf8"),
  );
  const vr = await fetch(`${VERIFY_URL}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(bundle),
  });
  const result = await vr.json();
  if (!result.valid) {
    res.writeHead(403, { "content-type": "application/json" });
    return res.end(JSON.stringify(result));
  }
  // Strip the bundle (contains sensitive signatures) and add a principal header.
  delete req.headers["x-drs-bundle"];
  req.headers["x-drs-principal"] = result.context.root_principal;
  req.headers["x-drs-correlation-id"] = result.context.correlation_id ?? "";
  proxy.web(req, res);
}).listen(8443);
```

Deploy this alongside `drs-verify` and your backend:

```yaml
services:
  edge:
    build: ./proxy
    ports: ["8443:8443"]
    depends_on: [drs-verify, backend]

  drs-verify:
    image: ghcr.io/okeyamy/drs-verify:latest

  backend:
    image: your-app:latest     # unchanged
```

The backend never learns DRS exists. It just sees `X-DRS-Principal`.

## Pattern 3: per-route opt-in

For a mixed workload — some endpoints public, some require DRS, some
require DRS + additional RBAC — make DRS enforcement explicit per
route:

```ts
import { drsOptional, drsRequired } from "./drs-middleware.js";

app.get("/status", (req, res) => res.json({ ok: true })); // public

app.get("/report", drsOptional, (req, res) => {
  // If bundle present, tailor the response to that principal.
  // Otherwise return a generic report.
  res.json(generateReport(req.drs?.root_principal));
});

app.post("/admin/delete", drsRequired, (req, res) => {
  // DRS enforced. Additionally check operator role.
  const principal = req.drs.root_principal;
  if (!isOperator(principal)) return res.status(403).json({ error: "not operator" });
  deleteThing(req.body.id);
  res.status(204).end();
});
```

## Policy enforcement at the app layer

`drs-verify` enforces attenuation (child policies can't escalate) but it
does not enforce runtime cost or per-call counting. Do that in your app:

```ts
app.post("/llm/complete", drsRequired, async (req, res) => {
  const policy = req.drs.leaf_policy ?? {};
  const estCost = estimateCost(req.body);

  if (policy.max_cost_usd != null && estCost > policy.max_cost_usd) {
    return res.status(403).json({
      error: "exceeds policy.max_cost_usd",
      max: policy.max_cost_usd,
      estimated: estCost,
    });
  }

  const result = await callLLM(req.body);
  res.json(result);
});
```

## Related

- [Choosing your path](./choosing-your-path.md)
- [Error codes](../../reference/error-codes.md)
- [API endpoints](../../reference/api-endpoints.md)
