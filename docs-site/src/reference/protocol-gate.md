# DRS Protocol Gate — MCP, A2A and plain HTTP enforcement

This page is the normative contract for `drs-verify/pkg/gate` and the `POST /v1/gate` endpoint.
Tests across the repository cite it by section.

Supersedes: `pkg/middleware/mcp.go`, `pkg/middleware/a2a.go`, the TS `drsMcpMiddleware` /
`createDrsHttpMiddleware` protocol logic.

## Why

A real-wire audit on 2026-10-01 (official MCP SDK 1.31 / 2.2 in both protocol eras, Go MCP
SDK 1.8.0, `@a2a-js/sdk` 1.3.0) found that the verifier core worked unchanged in every era, but
every protocol edge except one was broken:

- Go `MCPMiddleware` compared the whole JSON-RPC envelope to the signed args: signed calls were
  rejected, unsigned calls passed in optional mode, enforced mode blocked the handshake.
- The Node header gate and the documented gate locked official MCP clients out at `initialize`.
- The shipped `DrsTransportWrapper` was not an MCP `Transport` (no `start`).
- A2A could only pass with an empty policy.
- A 401 from DRS is read by 2026-07-28 clients as an OAuth challenge.
- Binding-mode typos failed open; integers above 2^53 collided after canonicalisation.

## Design

All protocol knowledge lives in one Go package, `drs-verify/pkg/gate`:

```
request ─► Adapter.Extract ─► Call{Bundle, Cmd, Args, ID} ─► Decide:
                                                               verify.Chain
                                                               → Cmd check
                                                               → binding (JCS, I-JSON range)
                                                               → nonce commit (only if all above pass)
                                                             ─► Decision{Allow, Status, Body, Context}
```

The same `Decide` backs the Go `gate.Middleware` and the `POST /v1/gate` endpoint used by
out-of-process gates (Node, stdio). TS packages hold no protocol rules.

### Adapters (normative mapping)

| Adapter | Gated requests | Signed `args` must equal | Required `invocation.cmd` |
|---|---|---|---|
| `http` | every request | the request body | any |
| `mcp` | JSON-RPC `tools/call` only | `params.arguments` ∪ `{"tool": params.name}` | `/mcp/tools/call` |
| `a2a` | every JSON-RPC method | `params` ∪ `{"tool": method}` | `/a2a/<method>` |

MCP traffic that is not `tools/call` (initialize, server/discover, list calls, notifications)
passes through untouched. For `mcp` and `a2a`, GET, DELETE, HEAD and OPTIONS pass (they carry no
tool action); POST is gated; any other method is refused with 405 `METHOD_NOT_ALLOWED`.

### Bundle carriers

- HTTP header `X-DRS-Bundle` (base64url JSON bundle) — all adapters.
- `params._meta["xyz.okeyamy.drs/bundle"]` — MCP (works on stdio, which has no headers).
- Both carriers with different values → `MULTIPLE_BUNDLES`.

### Error contract

JSON-RPC adapters answer with a JSON-RPC error echoing the request `id`, code `-32010`,
`error.data.code` = one of the codes below. A missing bundle is **403, never 401** on MCP/A2A
(MCP clients treat 401 as an OAuth challenge). Plain HTTP keeps 401 for a missing bundle.

| Code | HTTP | Meaning |
|---|---|---|
| `MISSING_BUNDLE` | 403 (http: 401) | gated request without a bundle |
| `MALFORMED_BUNDLE` | 400 | not base64url JSON / wrong carrier type |
| `MULTIPLE_BUNDLES` | 400 | repeated header or conflicting carriers |
| chain codes (`POLICY_VIOLATION`, …) | 403 | `verify.Chain` refused the chain |
| `CMD_MISMATCH` | 403 | invocation scoped to another protocol/method |
| `BINDING_MISMATCH` | 403 | executed args ≠ signed args (incl. integers outside I-JSON range) |
| `REPLAY_DETECTED` | 409 | jti already consumed |
| `NONCE_STORE_UNAVAILABLE` | 503 | replay store failure |
| `HEADER_MISMATCH` | 400 | `Mcp-Method` / `Mcp-Name` disagree with the body |
| `RESERVED_ARGUMENT` | 400 | caller argument named `tool` |
| `BATCH_NOT_SUPPORTED` | 400 | JSON-RPC batch array |
| `INVALID_JSONRPC` / `INVALID_TOOL_CALL` / `INVALID_PARAMS` | 400 | malformed message |
| `BODY_TOO_LARGE` | 413 | body > 64 KiB |
| `METHOD_NOT_ALLOWED` | 405 | MCP/A2A request with a method other than POST, GET, DELETE, HEAD, OPTIONS |
| `MISSING_JTI` | 400 | Invocation carries no `jti`, so replay protection cannot apply |
| `VERIFICATION_FAILED` | 403 | Chain refused without a more specific code (normally the chain error code is returned instead) |
| `BODY_READ_ERROR` | 400 | Request body could not be read |
| `BAD_REQUEST` | 400 | Adapter rejected the request for a reason not covered above |
| `INVALID_GATE_REQUEST` | 400 | `POST /v1/gate` envelope is not valid JSON or is missing fields |
| `UNKNOWN_PROTOCOL` | 400 | `POST /v1/gate` `protocol` is not `http`, `mcp` or `a2a` |

### Numbers

Any JSON number (integer, decimal or exponent notation) with magnitude above 2^53−1 is refused
(`BINDING_MISMATCH`, I-JSON range, RFC 7493 §2.2): beyond it distinct numbers round to the same
double and would compare equal after JCS. Fractional differences below double precision
(e.g. `0.1` vs `0.10000000000000001`) still compare equal and are out of scope.

### Rate limiting

Node/stdio gates call `/v1/gate` for every request, including handshakes, from one host. All of
that traffic shares the sidecar's per-IP bucket — raise `RATE_LIMIT_PER_IP` for sidecar
deployments accordingly.

### Ordering

The nonce is committed last. A binding mismatch therefore never burns a jti, and an honest retry
of the same signed call still succeeds.

### `/verify` changes

- `DRS_REQUIRE_BINDING` (default `true`): a request without `body` returns `valid:false`,
  `BINDING_REQUIRED`. A body mismatch returns `valid:false`, `BINDING_MISMATCH`, `binding:"mismatch"`.
- The nonce is committed only after binding passes.
- Set `DRS_REQUIRE_BINDING=false` to restore chain-only verification (nonce still committed).

### Configuration safety

`binding.ParseMode` rejects unknown strings; `gate.NewConfig` rejects a nil nonce checker.
`verify.NewDefaultDeps(serverIdentity)` builds embedded-verifier dependencies.

## Not covered

A2A REST/gRPC bindings (use the JSON-RPC binding), MCP methods other than `tools/call`
(resources/read, prompts/get pass through ungated).
