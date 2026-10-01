# Integrate DRS with a non-MCP / non-A2A Node backend

Plenty of real-world services aren't MCP tool servers or A2A agents —
they're ordinary APIs that want to enforce "this request came from an
authorised delegation chain" before doing work. DRS still fits.

Every pattern below uses the same building block: a gate from
`@drs/mcp-server` with `protocol: "http"`. The gate forwards the method,
the `X-DRS-Bundle` header and the parsed body to `drs-verify`
`POST /v1/gate`. `drs-verify` verifies the chain, checks that the body
equals the signed `invocation.args`, and consumes the invocation `jti`.
Your app holds no protocol logic. See the
[Protocol Gate reference](../../reference/protocol-gate.md) for the exact
contract.

```bash
pnpm add @drs/mcp-server express
# Until @drs/mcp-server is published, use it as a workspace dependency from this repo.
```

## Pattern 1: enforce on every route

```ts
import express from "express";
import { createDrsGate, withDrsGate } from "@drs/mcp-server";

const gate = createDrsGate({
  verifyUrl: process.env.DRS_VERIFY_URL ?? "http://localhost:8080",
  protocol: "http",
});

// Express calls (req, res, next); the gate wants (req, res, parsedBody).
const drsRequired = (req, res, next) =>
  withDrsGate(gate, () => next())(req, res, req.body);

const app = express();
app.use(express.json({ limit: "64kb" }));
app.use(drsRequired);          // enforce on every route
```

A denied request is answered with the status and body `drs-verify` chose
(`401 MISSING_BUNDLE`, `403 BINDING_MISMATCH`, `409 REPLAY_DETECTED`, …).
An allowed request reaches your handler with `req.drs` set to the
verification context (`root_principal`, `root_type`, `leaf_policy`,
`chain_depth`).

## Pattern 2: gate in front of an unchanged backend

Put `drs-verify` and a small Node gate in front of your existing backend.
The gate decides, then forwards allowed requests with an
`X-DRS-Principal` header so the app can learn who authorised the call.
The gate is your process — `drs-verify` itself never proxies traffic.

```ts
// edge.ts
import http from "node:http";
import { createDrsGate, withDrsGate } from "@drs/mcp-server";

const gate = createDrsGate({ verifyUrl: "http://drs-verify:8080", protocol: "http" });
const UPSTREAM = "http://my-existing-backend:5000";

http
  .createServer(
    withDrsGate(gate, async (req, res, body) => {
      const upstream = await fetch(new URL(req.url ?? "/", UPSTREAM), {
        method: req.method,
        headers: {
          "content-type": "application/json",
          "x-drs-principal": req.drs?.root_principal ?? "",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      res.writeHead(upstream.status, {
        "content-type": upstream.headers.get("content-type") ?? "application/json",
      });
      res.end(Buffer.from(await upstream.arrayBuffer()));
    }),
  )
  .listen(8443);
```

The bundle header is not forwarded upstream. Deploy this alongside
`drs-verify` and your backend:

```yaml
services:
  edge:
    build: ./edge
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
require DRS plus additional RBAC — mount the gate per route:

```ts
app.get("/status", (req, res) => res.json({ ok: true })); // public, no gate

app.post("/admin/delete", drsRequired, (req, res) => {
  // DRS enforced. Additionally check operator role.
  const principal = req.drs.root_principal;
  if (!isOperator(principal)) return res.status(403).json({ error: "not operator" });
  deleteThing(req.body.id);
  res.status(204).end();
});
```

There is no "optional" mode: a route either goes through the gate or it
does not.

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
