# MCP and A2A Integration Shape Review

This review explains which MCP/A2A integration shapes can make execution
integrity claims today.

## Shape 1: HTTP-Terminated Tool Requests

Shape 1 is the safer integration pattern when the HTTP request body is available
to middleware before the protected handler runs.

| Property | Status | Evidence |
|---|---|---|
| Bundle verification before handler execution | Proven for Node HTTP middleware path. | `results.md`, `S-middleware-handler-block.json` |
| Body binding between signed invocation args and actual request body | Proven for local verifier detection. | `results.md`, `S-body-binding-mismatch.json` |
| Handler blocked on mismatch | Proven. | `handlerCalls: 0` in `S-middleware-handler-block.json` |

Shape 1 can support execution-integrity wording when the integrator uses the
fail-closed middleware behavior and forwards the exact parsed body to `/verify`.

## Shape 2: Pure JSON-RPC Middleware

Shape 2 is provenance-only until the middleware binds JSON-RPC `params` to the
signed invocation arguments before handler execution.

| Property | Status | Evidence |
|---|---|---|
| DRS bundle can be decoded and verified | Covered by package tests and SDK/verifier flows. | `evidence.md`, TypeScript tests |
| JSON-RPC `params` body binding | Not proven by this audit. | No live Shape 2 params-binding walkthrough exists. |
| Execution-integrity claim | Not supported by this audit. | `docs/drs-source-of-truth.md` documents Shape 2 limitation. |

Safe wording for Shape 2:

> The middleware can attach DRS provenance to a JSON-RPC request, but this audit
> does not prove that JSON-RPC `params` are bound to signed invocation arguments
> before execution.

Unsafe wording for Shape 2:

> DRS prevents JSON-RPC parameter tampering in Shape 2.

## A2A Middleware

The same body-binding rule applies to A2A: execution integrity requires verifying
the signed intent against the exact payload the downstream handler will execute.
Package-level A2A middleware tests exist, but this audit does not include a live
A2A server walkthrough.

## Required Follow-Up Work

1. Add a live Shape 2 JSON-RPC scenario with signed args and tampered `params`.
2. Prove the middleware rejects before the JSON-RPC handler runs.
3. Add an A2A live server walkthrough with the same pass/fail pattern.
4. Promote the claim only after `results.md` records real request/response evidence.
