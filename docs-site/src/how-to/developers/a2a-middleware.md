# A2A Middleware Integration

Gate an Agent2Agent (A2A) agent's JSON-RPC endpoint so every call carries a DRS
bundle signed for exactly that request. Tested against `@a2a-js/sdk` 1.3.0
(A2A protocol v1.0).

## What the gate does

Every JSON-RPC method on the endpoint (`SendMessage`, `GetTask`, …) is gated.
The agent signs:

- `cmd: "/a2a/<method>"` — e.g. `/a2a/SendMessage`; a root delegation scoped
  to `/a2a` covers every method
- `args: { ...params, tool: "<method>" }` — so `allowed_tools: ["SendMessage"]`
  policies work

The bundle travels in the `X-DRS-Bundle` header. Serve the agent card
(`/.well-known/agent-card.json`) outside the gate. Batches are refused; REST and
gRPC bindings are not supported — use the JSON-RPC binding.

Refusals are JSON-RPC errors with code `-32010` and `error.data.code`
(`MISSING_BUNDLE` → 403, `BINDING_MISMATCH` → 403, `REPLAY_DETECTED` → 409, …).

## Go

```go
cfg, err := gate.NewConfig(deps, nonce.New(100_000, 15*time.Minute), binding.ModeEnforced)
if err != nil {
	log.Fatal(err)
}
http.Handle("/a2a", gate.Middleware(cfg, gate.A2A{}, yourA2AHandler))
```

Build `deps` with `verify.NewDefaultDeps(serverIdentity)` as in the
[MCP guide](mcp-middleware.md).

## Node

```js
import { createDrsGate, withDrsGate } from "@drs/mcp-server";

const gate = createDrsGate({ verifyUrl: "http://127.0.0.1:8080", protocol: "a2a" });
app.use("/a2a", express.json(), (req, res, next) =>
  withDrsGate(gate, () => next())(req, res, req.body));
app.use("/a2a", jsonRpcHandler({ requestHandler, userBuilder }));
```

The calling agent signs with `@drs/mcp-client`:

```js
import { createChainSigner, createDrsFetch } from "@drs/mcp-client";

const fetchImpl = createDrsFetch({ signer: createChainSigner({ ... }), protocol: "a2a" });
const client = await new ClientFactory({
  transports: [new JsonRpcTransportFactory({ fetchImpl })],
}).createFromUrl(agentUrl);
```
