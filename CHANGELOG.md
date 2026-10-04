# Changelog

All notable changes to the DRS workspace are documented here, grouped by
component. Versions follow semver; the repository is pre-1.0, so minor
bumps may contain breaking changes (always listed under **Breaking**).

## Unreleased

### Toolchain

- Go 1.25.12 → 1.25.13 (drs-verify, integration-tests, Dockerfile): fixes reachable
  stdlib advisories GO-2026-6218, GO-2026-6090, GO-2026-6089, GO-2026-5972, GO-2026-5026.
- CI pins `govulncheck@v1.7.0`; v1.8.0 requires Go 1.26.
- `pnpm-workspace.yaml` sets `allowBuilds.esbuild: false` (pnpm 11 rejects the
  placeholder that was committed).

### Protocol gate (MCP, A2A, HTTP) — drs-verify, @drs/mcp-server, @drs/mcp-client

A real-wire audit (2026-10-01) against the official MCP SDKs (1.31, 2.2 in both
the `2025-11-25` and `2026-07-28` protocol versions, Go SDK 1.8.0) and
`@a2a-js/sdk` 1.3.0 found the protocol edge broken while the verifier core was
sound. See the [Protocol Gate reference](https://okeyamy.github.io/DRS/reference/protocol-gate.html).

**Breaking — read before upgrading:**

- Go module path is now `github.com/OkeyAmy/DRS/drs-verify` (the previous
  `github.com/drs-protocol/drs-verify` could not be fetched with `go get`).
  Release tags for this submodule must be prefixed `drs-verify/v`.
- `pkg/middleware.MCPMiddleware`, `A2AMiddleware`, their `Optional*` variants and
  `GetVerificationContext` are removed. Use `pkg/gate`:
  `gate.Middleware(cfg, gate.MCP{} | gate.A2A{} | gate.HTTP{}, next)` and
  `gate.VerificationContext(ctx)`. The old MCP middleware compared the whole
  JSON-RPC envelope with the signed args, so it refused every real signed call.
- `POST /verify` requires `body` by default (`DRS_REQUIRE_BINDING=true`): an
  omitted body is `valid:false` / `BINDING_REQUIRED`, and a mismatch is now
  `valid:false` / `BINDING_MISMATCH` (previously `valid:true` with
  `binding:"mismatch"`). Set `DRS_REQUIRE_BINDING=false` for the old behaviour.
- `@drs/mcp-server`: `drsMcpMiddleware` and `createDrsHttpMiddleware` are
  replaced by `createDrsGate` + `withDrsGate` (HTTP) and
  `DrsGatedServerTransport` (stdio), thin clients of `POST /v1/gate`.
- `@drs/mcp-client`: `DrsTransportWrapper` (not a valid MCP Transport) is
  replaced by `createDrsFetch` and `DrsClientTransport`, signing each call with
  the arguments it actually sends (`createChainSigner`).
- The MCP `_meta` bundle key is now `xyz.okeyamy.drs/bundle`.

**Added:**

- `POST /v1/gate` — protocol-aware allow/deny decisions for non-Go gates.
- MCP adapter: gates `tools/call` only; signed args are
  `params.arguments + {tool: params.name}` under `cmd /mcp/tools/call`;
  bundle in `X-DRS-Bundle` or `params._meta`; `Mcp-Method`/`Mcp-Name`
  cross-checked against the body.
- A2A adapter: gates every JSON-RPC method under `cmd /a2a/<method>` with
  `{...params, tool: method}`, so `allowed_tools` policies apply to A2A. The
  bundle travels only in the `X-DRS-Bundle` header.
- `verify.NewDefaultDeps(serverIdentity)` and the `testkit` package (real
  signed chains for tests).
- Live test suites: `integration-tests/tests/protocols.live.test.mjs` (official
  MCP v1/v2 HTTP + stdio and A2A SDKs, attack matrix) and
  `integration-tests/go` (official Go MCP SDK through `gate.Middleware`).

**Fixed (security):**

- Binding-mode strings other than exactly `"enforced"` silently passed
  mismatches; modes are now typed and unknown values are configuration errors.
- Numbers beyond 2^53 collapsed during canonicalisation, so a signed `amount`
  of 9007199254740992 bound to an executed 9007199254740993 (in integer, decimal
  or exponent notation). Such values are now refused.
- MCP/A2A gates now refuse methods other than POST/GET/DELETE/HEAD/OPTIONS
  (405) instead of passing them ungated.
- A binding mismatch consumed the invocation's jti; the nonce is now committed
  only after binding passes.
- MCP gates answered a missing bundle with 401, which MCP clients treat as an
  OAuth challenge; JSON-RPC gates now answer 403 with a JSON-RPC error.
- An argument named `tool` could overwrite the signed tool name; it is now
  refused (`RESERVED_ARGUMENT`). Bundles scoped to another protocol are refused
  (`CMD_MISMATCH`). JSON-RPC batches fail closed.
- The Node `_meta` middleware crashed on body-less GET requests.

### drs-verify

**Breaking — read before upgrading a deployment:**

- The default nonce TTL (`NONCE_STORE_TTL_SECS`) dropped from **3600 to 900**
  seconds. Invocations older than 15 minutes are now rejected as stale unless
  you explicitly set a longer TTL. Rationale: a one-hour replay window was far
  wider than any legitimate invocation latency and enlarged the nonce store
  for no security benefit.
- The server now **refuses to boot** with `TRUST_PROXY=true` and
  `NONCE_STORE_BACKEND=memory`. A proxied deployment is presumed
  multi-instance, and a per-process memory nonce store cannot provide replay
  protection across instances — a replayed invocation would succeed on any
  instance that had not seen the JTI. Set `NONCE_STORE_BACKEND=redis` (with
  `REDIS_URL`) or, for a genuinely single-instance deployment, unset
  `TRUST_PROXY`.

**Fixed:**

- Oversized request bodies now return **413 Request Entity Too Large** with a
  JSON `REQUEST_BODY_TOO_LARGE` error instead of a generic 400. The 64 KiB
  body cap itself is unchanged.
- Toolchain bumped to Go 1.25.12 (GO-2026-5856, crypto/tls ECH privacy leak).

### drs-sdk 0.2.0

**Breaking:**

- Removed the WASM loader exports (`initWasm`, `getWasmModule`, `isWasmReady`)
  from the package entry point. The loader was advertised but no standalone
  WASM artifact was ever published, so `initWasm()` could never succeed. The
  module remains in the source tree (deprecated) as an integration path for a
  future WASM release.
- `verifyWithService` no longer sends the redundant `X-DRS-Bundle` header;
  the bundle travels only in the request body. drs-verify never read the
  header, so no server-side change is needed.

**Added:**

- HTTP 409 from drs-verify now surfaces as a typed `REPLAY_DETECTED` error
  instead of a generic service error, so callers can distinguish replayed
  invocations from outages.

### drs-core 0.1.2

**Fixed:**

- `verify_chain` no longer panics on `wasm32-unknown-unknown`:
  `SystemTime::now()` traps on that target, so Block E's clock read now uses
  `js_sys::Date::now()` behind a `cfg` gate (JS host required — browser or
  Node via wasm-bindgen). Non-finite or negative clock values fail closed
  with `ClockError`.

**Changed:**

- The crate is now explicitly documented as a **non-normative,
  feature-frozen reference implementation**. The normative DRS verifier is
  drs-verify; all production verification goes through its HTTP `/verify`
  endpoint.

## v0.1.1 — 2026-06-26

- Supply-chain hardening: npm publish hygiene, cosign image signing,
  npm OIDC trusted publishing, Trivy scan ordering.
- Security patches from the full vulnerability audit (PR #83).

## v0.1.0 — initial public release
