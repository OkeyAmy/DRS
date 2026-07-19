# Changelog

All notable changes to the DRS workspace are documented here, grouped by
component. Versions follow semver; the repository is pre-1.0, so minor
bumps may contain breaking changes (always listed under **Breaking**).

## Unreleased

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
