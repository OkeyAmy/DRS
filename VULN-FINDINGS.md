# DRS Vulnerability Findings

**Target:** `/home/okey/Desktop/Projects/DRS`
**Scanned:** 2026-06-06
**Commit:** 92a4c69
**Method:** Static analysis — 7 parallel agents, 7 focus areas

---

## Summary

| Severity | Count |
|---|---|
| HIGH | 5 |
| MEDIUM | 26 |
| LOW | 24 |
| **Total** | **55** |

Low-confidence findings (< 0.40): **0**

**Source files covered:** ~200 across drs-core (Rust), drs-verify (Go), drs-sdk (TypeScript), packages/drs-mcp-server, packages/drs-mcp-client

---

## Summary Table

| ID | Severity | Confidence | Category | File:Line | Title |
|---|---|---|---|---|---|
| F-001 | HIGH | 1.00 | sensitive-data-exposure | keygen.ts:23 | Raw Ed25519 private key printed to stdout in hex |
| F-002 | LOW | 1.00 | documentation | README.md:176 | README documents nonce check order incorrectly |
| F-003 | LOW | 1.00 | missing-runtime-enforcement | types.ts:17 | max_calls policy field never enforced at runtime |
| F-004 | MEDIUM | 0.98 | policy-enforcement-gap | types/types.go:14 | max_calls in signed receipts not enforced at verification time |
| F-005 | HIGH | 0.95 | auth-bypass | evaluate.go:58 | Policy field enforcement opt-in — absent args bypass all restrictions |
| F-006 | HIGH | 0.95 | auth-bypass | middleware.ts:184 | Shape 2 MCP middleware skips body-to-invocation binding check |
| F-007 | HIGH | 0.95 | resource-exhaustion | binding.go:34 | Unbounded io.ReadAll in middleware binding path — no body size cap |
| F-008 | MEDIUM | 0.95 | auth-bypass | chain.go:287 | tool_server binding default-off — confused-deputy replay possible |
| F-009 | MEDIUM | 0.95 | auth-bypass | decode.go:77 | nil nonce.Checker silently disables replay protection |
| F-010 | MEDIUM | 0.95 | insufficient-validation | bundle.ts:103 | Bundle field type validation checks presence only |
| F-011 | MEDIUM | 0.95 | algorithm-complexity | policy.rs:173 | O(n·m) policy attenuation not fixed — v2 defect persists |
| F-012 | MEDIUM | 0.92 | auth-bypass | evaluate.go:105 | CheckAttenuation has no exp field handling — temporal escalation |
| F-013 | HIGH | 0.90 | auth-bypass | chain.go:327 | Invocation receipt has no temporal validity check |
| F-014 | MEDIUM | 0.90 | auth-bypass | chain.go:308 | Temporal attenuation gap: child-exp-nil + parent-exp-set uncaught |
| F-015 | MEDIUM | 0.90 | resource-exhaustion | mcp.go:55 | X-DRS-Bundle header decoded without per-header size cap |
| F-016 | MEDIUM | 0.90 | auth-bypass | status.go:228 | getBit fail-open for out-of-range status list index |
| F-017 | MEDIUM | 0.90 | insecure-default | client.ts:29 | No HTTPS enforcement for verifier URL |
| F-018 | MEDIUM | 0.90 | dos | chain/verify.rs | Rust verify_chain has no depth cap — unbounded chain length |
| F-019 | MEDIUM | 0.90 | auth-bypass | chain/verify.rs | No temporal validity check on InvocationReceipt in Rust |
| F-020 | LOW | 0.90 | auth-bypass | binding.go:28 | Unrecognized bindingMode silently degrades to lenient |
| F-021 | MEDIUM | 0.88 | auth-bypass | policy.rs | Rust policy eval skips enforcement when required fields absent |
| F-022 | MEDIUM | 0.85 | dos | jcs/mod.rs | No recursion-depth guard for JCS canonicalization |
| F-023 | MEDIUM | 0.85 | dos | chain.go:39 | 16-hop did:web chains: up to 17 HTTPS fetches per request |
| F-024 | MEDIUM | 0.85 | auth-bypass | did.go:586 | did:web DID document extraction has no verification method id binding |
| F-025 | MEDIUM | 0.85 | availability | store.go:87 | Nonce store exhaustion returns 503 — attacker can lock out all agents |
| F-026 | MEDIUM | 0.85 | availability | did.go:356 | Singleflight panic: inflight entry not cleaned in defer |
| F-027 | MEDIUM | 0.85 | ssrf | rfc3161.go:149 | TSA URL accepted without scheme/host validation — SSRF |
| F-028 | MEDIUM | 0.85 | supply-chain | loader.ts:41 | WASM binary loaded without integrity verification |
| F-029 | MEDIUM | 0.85 | insecure-design | operator.ts:39 | File-backed key management has no permissions check |
| F-030 | MEDIUM | 0.85 | auth-bypass | capability_index.rs | Prefix wildcard priority logic gap in CapabilityIndex |
| F-031 | MEDIUM | 0.80 | missing-rate-limit | main.go:216 | No dedicated rate limit on POST /admin/revoke |
| F-032 | MEDIUM | 0.80 | cryptographic-correctness | rfc3161.go:358 | Cert validity checked at time.Now() instead of tst.GenTime |
| F-033 | MEDIUM | 0.80 | auth-bypass | rfc3161.go:431 | extractSignerCert matches by serial only — not issuer |
| F-034 | LOW | 0.80 | documentation | chain.go:508 | strictVerifyEd25519 comment misrepresents Go 1.13+ behaviour |
| F-035 | LOW | 0.80 | sensitive-data-exposure | issue.ts:148 | Unverified JWT fields echoed into error messages |
| F-036 | LOW | 0.80 | information-disclosure | drs-core/src/ | serde_json error messages expose internal Rust type names in WASM |
| F-037 | MEDIUM | 0.75 | cryptographic-correctness | jcs.ts:30 | JCS sort diverges from RFC 8785 for supplementary-plane Unicode keys |
| F-038 | LOW | 0.75 | code-quality | chain.go:49 | JWT split three times independently in same request path |
| F-039 | LOW | 0.75 | rate-limit-bypass | ratelimit.go:107 | trustProxy=true XFF multi-hop limitation undocumented |
| F-040 | LOW | 0.75 | documentation | rfc3161.go | Timestamp non-fatality: Valid: true does not imply TimestampTrusted: true |
| F-041 | LOW | 0.75 | insecure-design | client.ts:68 | BundleProvider.getBundle() contract ambiguous — double-encoding risk |
| F-042 | LOW | 0.75 | integer-overflow | drs-core/src/ | Truncating cast u64→i64 in unix_now() — incorrect after year 2262 |
| F-043 | LOW | 0.70 | path-traversal | did.go | did:web path component not fully sanitized |
| F-044 | LOW | 0.70 | dos | did.go | Duplicate DNS resolution for same did:web domain during cache misses |
| F-045 | LOW | 0.70 | security-control-bypass | did.go | Private IP blocklist may be missing RFC 6890 ranges |
| F-046 | LOW | 0.70 | sensitive-data-exposure | status.go | Filesystem error details leaked in revocation store messages |
| F-047 | LOW | 0.70 | missing-validation | main.go | No minimum token entropy enforcement on admin revocation token |
| F-048 | LOW | 0.70 | resource-management | status.go | http.Client Timeout shadows fetchTimeout context |
| F-049 | LOW | 0.70 | resource-exhaustion | revocation/ | FileBackedRevocationStore grows unboundedly |
| F-050 | LOW | 0.70 | resource-exhaustion | rfc3161.go | Off-by-one: TSA response reader allocates 64 KiB + 1 bytes |
| F-051 | LOW | 0.70 | dependency-pinning | Cargo.toml | serde_json_canonicalizer pinned to '0.2' — may lag RFC 8785 updates |
| F-052 | LOW | 0.65 | security-control-bypass | did.go | Circuit breaker state lost on LRU eviction |
| F-053 | LOW | 0.65 | race-condition | did.go | Half-open circuit breaker allows thundering herd on recovery |
| F-054 | LOW | 0.65 | audit-gap | main.go | No failed-authentication audit log for /admin/revoke |
| F-055 | LOW | 0.65 | code-quality | drs-core/src/ | splitn(4, '.') — semantically should be splitn(3, '.') |

---

## Findings

### F-001 — HIGH — Raw Ed25519 private key printed to stdout in hex
**File:** `drs-sdk/src/cli/commands/keygen.ts:23`
**Confidence:** 1.0

**Description:** `keygen()` generates a 32-byte Ed25519 private key, converts it to hex at lines 12–14, and calls `console.log(`Private key  : ${privHex}`)` at line 23. Any shell history, CI log capture, terminal scroll-back, or pipe to a logging sink records the key in plaintext. No zeroization of `privKey` or `privHex` occurs after printing.

**Exploit scenario:** Operator runs `drs keygen | tee /var/log/setup.log`. Log file now contains the private key hex. Any user or process with read access to the log can extract the key and forge delegation receipts signed by that operator identity. On CI systems that capture stdout, the key is exposed to anyone with build log access.

**Recommendation:** Write the private key to a file path given as a CLI argument (default `~/.drs/signing.key` with 0600 permissions), not to stdout. Print only the DID and public key to stdout. Zeroize `privKey` (`fill(0)`) after key derivation.

---

### F-002 — LOW — README documents nonce check order as 'before chain verification'
**File:** `README.md:176`
**Confidence:** 1.0

**Description:** README.md line 176 states JTIs are checked "before chain verification". Actual execution order in `mcpMiddleware` and `a2aMiddleware`: (1) `verify.Chain`, then (2) `CheckNonceReplay` only on a valid result. The code order is correct and secure; the documentation describes the insecure order, misleading security auditors.

**Exploit scenario:** A security auditor reads the README and concludes nonce checking is the first gate. If the code were "fixed" to match the documentation (nonces first), JTI pre-exhaustion attacks would become possible via invalid-signature requests.

**Recommendation:** Correct README.md line 176: "chain signature verification runs first; JTIs are committed to the nonce store only after the signature is confirmed valid. This prevents JTI pre-exhaustion attacks."

---

### F-003 — LOW — max_calls policy field never enforced at runtime in SDK or middleware
**File:** `drs-sdk/src/sdk/types.ts:17`
**Confidence:** 1.0

**Description:** `Policy.max_calls` is documented as "INFORMATIONAL ONLY". `checkPolicyAttenuation()` enforces attenuation at issuance, but no component — SDK, CLI, MCP client, MCP server middleware — checks actual call counts at runtime. `drsMcpMiddleware` receives `VerificationResult` carrying `context.leaf_policy.max_calls` but never reads it.

**Exploit scenario:** Human grants consent for `max_calls: 5` on a high-cost API. Nothing in drs-verify, drs-mcp-server, or the SDK counts or rejects calls beyond 5. Agent executes 500 calls before `exp` fires.

**Recommendation:** (1) Add `policy_warnings?: string[]` to `VerificationResult` when `leaf_policy.max_calls` is set. (2) Add `enforceMaxCalls` middleware option backed by LRU `Map<jti, number>`. (3) Document in MCP server README with reference implementation. See also F-004.

---

### F-004 — MEDIUM — max_calls present in signed receipts but not enforced at verification time (Go layer)
**File:** `drs-verify/pkg/types/types.go:14`
**Confidence:** 0.98

**Description:** `types.Policy.MaxCalls` is carried in signed receipts and attenuated correctly, but `policy.Evaluate` explicitly excludes `max_calls` enforcement. `VerificationContext.LeafPolicy` includes `max_calls` so integrators can enforce it, but there is no forcing function — `Valid: true` carries no indication whether `max_calls` was consulted. See also F-003 (TypeScript layer) and F-019 (Rust layer).

**Recommendation:** Include a `MaxCallsHint` or `PolicyWarnings` field in `VerificationContext` when `LeafPolicy.MaxCalls != nil`. Emit a warning log in `Evaluate`. Document prominently in the API reference.

---

### F-005 — HIGH — Policy field enforcement is opt-in — absent args keys bypass all capability restrictions
**File:** `drs-verify/pkg/policy/evaluate.go:58`
**Confidence:** 0.95

**Description:** `policy.Evaluate` guards every enforcement block with a key-presence test (`if toolRaw, ok := args["tool"]; ok { ... }`). If the attacker-controlled invocation omits the key entirely, every enforcement block is skipped and the capability is granted unconditionally. This applies to `allowed_tools` (line 58), `allowed_resources` (line 71), `allowed_data_classes` (line 85), `pii_access` (line 40), and `write_access` (line 49).

**Exploit scenario:** A chain restricts `allowed_tools: ["read_db"]` and `write_access: false`. Attacker signs an invocation JWT with `args: {}`. `policy.Evaluate` skips all guards. Invocation passes Block D with no `POLICY_VIOLATION`. Tool server receives `Valid: true` and executes an arbitrary tool write.

**Recommendation:** Flip from opt-in to opt-out: when a policy field restricts access, the corresponding args key MUST be present. Return error when `allowed_tools` is non-empty but args contains no `"tool"` key. See also F-021 (same defect in Rust).

---

### F-006 — HIGH — Shape 2 MCP middleware skips body-to-invocation binding check
**File:** `packages/drs-mcp-server/src/middleware.ts:184`
**Confidence:** 0.95

**Description:** `drsMcpMiddleware()` sends only the decoded bundle JSON to drs-verify (line 152) without including the MCP tool-call parameters. Because no `body` field is sent, the verifier cannot perform the RFC 8785 binding comparison between `invocation.args` and the actual tool arguments in `message.params`. `result.binding` is never checked. Contrast with Shape 1 (`http.ts` lines 64–91) which enforces this comparison.

**Exploit scenario:** Malicious MCP client constructs a bundle where `invocation.args = {tool: "read_file", path: "/etc/passwd"}` and attaches it to a request with params `{tool: "write_file", path: "/etc/cron.d/backdoor", content: "..."}`. Chain verifies as cryptographically valid. Shape 2 middleware returns `verified: true`. Tool server executes the write — a capability the bundle never authorized.

**Recommendation:** Extract `message.params?.arguments` and include as `body` field alongside `bundle` in the POST to drs-verify, mirroring Shape 1. Then check `result.binding === "match"` and call `failClosed("BINDING_MISMATCH")` when not.

---

### F-007 — HIGH — Unbounded io.ReadAll in MCPMiddleware/A2AMiddleware binding path
**File:** `drs-verify/pkg/middleware/binding.go:34`
**Confidence:** 0.95

**Description:** `checkRequestBinding` (line 34) calls `io.ReadAll(r.Body)` with no size limit. When integrators mount `MCPMiddleware` or `A2AMiddleware` on their own server, the middleware does not apply `http.MaxBytesReader` before reading the body. Contrast: the built-in `/verify` endpoint in main.go line 312 applies `http.MaxBytesReader(w, r.Body, maxBodyBytes)`. The 10s `ReadTimeout` bounds time but not RAM.

**Exploit scenario:** Attacker holds a valid signed bundle and sends POST requests with 500 MB bodies to a tool server using `MCPMiddleware`. Each request passes rate limiter and chain verification, then `io.ReadAll` buffers 500 MB. Four concurrent connections consume 2 GB of server RAM and OOM the server.

**Recommendation:** Add `http.MaxBytesReader` inside `checkRequestBinding` before `io.ReadAll`, defaulting to 1 MiB. Expose `MaxBodyBytes` parameter on `MCPMiddleware`/`A2AMiddleware`.

---

### F-008 — MEDIUM — tool_server binding default-off with no startup warning
**File:** `drs-verify/pkg/verify/chain.go:287`
**Confidence:** 0.95

**Description:** Line 287: `if deps.ServerIdentity != "" && invocation.ToolServer != deps.ServerIdentity`. When `SERVER_IDENTITY` env var is not set (the default), this check is skipped entirely. A bundle signed for tool server A can be presented to tool server B and verify as valid. No startup warning is emitted when `ServerIdentity` is empty.

**Recommendation:** Log a startup `slog.Warn` when `ServerIdentity` is empty. Optionally, treat an empty `invocation.tool_server` in the payload as `MISSING_TOOL_SERVER` when the verifier has a configured identity. Document that `SERVER_IDENTITY` is required in multi-server deployments.

---

### F-009 — MEDIUM — nil nonce.Checker silently disables replay protection
**File:** `drs-verify/pkg/middleware/decode.go:77`
**Confidence:** 0.95

**Description:** `CheckNonceReplay` returns `false` (proceed) when the `ns nonce.Checker` argument is `nil`. An integrator calling `middleware.MCPMiddleware(deps, nil, mode, handler)` compiles without error and silently disables all replay protection. No `slog.Warn`, no metric, no panic is emitted.

**Exploit scenario:** Integrator passes `nil` intending to add a nonce store later. Attacker intercepts one valid bundle and replays it indefinitely — chain verification passes every time, nonce check is skipped.

**Recommendation:** Panic at construction time when `nonceStore == nil`: `panic("MCPMiddleware: nonceStore must not be nil")`. If `nil` must remain valid for testing, emit `slog.Warn` and a metric in `CheckNonceReplay` when `ns == nil`.

---

### F-010 — MEDIUM — Bundle field type validation checks presence only
**File:** `drs-sdk/src/sdk/bundle.ts:103`
**Confidence:** 0.95

**Description:** `validateBundleObject()` uses the `in` operator to check that `receipts`, `invocation`, and `bundle_version` exist. It does not verify their types. A malformed bundle `{"bundle_version": null, "receipts": {}, "invocation": 42}` passes validation and is cast as a valid `ChainBundle`. Downstream `.split(".")` calls on non-string elements throw runtime TypeErrors that may expose internal stack traces.

**Recommendation:** Add explicit type guards: `Array.isArray(parsed.receipts)`, every element of `receipts` is a `string`, `typeof parsed.invocation === "string"`, `parsed.bundle_version === "4.0"`. Reject with `DrsError("MALFORMED_BUNDLE")` on any type failure.

---

### F-011 — MEDIUM — O(n·m) policy attenuation not fixed in Rust — v2 defect persists
**File:** `drs-core/src/policy.rs:173`
**Confidence:** 0.95

**Description:** `is_attenuated_subset()` for list-valued fields uses nested iteration: for each element in the child list, scan the parent list. This is O(n·m) per call, executed once per hop. CLAUDE.md explicitly lists this as a v2 defect (25 million comparisons/sec at moderate load). The Rust implementation still uses this algorithm.

**Recommendation:** Replace nested iteration with a `HashSet`-based check: load parent list into `HashSet<&str>` (O(m)), check each child element in O(1). Total: O(n+m). Apply to all three list fields. Add a performance test confirming sub-millisecond attenuation for 1000-element lists.

---

### F-012 — MEDIUM — CheckAttenuation has no exp field handling — temporal escalation possible
**File:** `drs-verify/pkg/policy/evaluate.go:105`
**Confidence:** 0.92

**Description:** `policy.CheckAttenuation` (lines 105–187) covers all policy fields except `exp`. The temporal attenuation in `chain.go` lines 308–315 also misses the case: parent has `exp`, child omits `exp`. A child that omits `exp` while the parent has `exp` set gains an unbounded delegation lifetime — a temporal escalation not caught anywhere.

**Recommendation:** In `chain.go`, add: if `receipts[i].Exp == nil && receipts[i-1].Exp != nil`, return `TEMPORAL_BOUNDS_VIOLATION`. Add the same logic to `CheckAttenuation` for defence-in-depth.

---

### F-013 — HIGH — Invocation receipt has no temporal validity check — stale invocations accepted indefinitely
**File:** `drs-verify/pkg/verify/chain.go:327`
**Confidence:** 0.90

**Description:** Block E (lines 327–342) enforces `nbf` and `exp` on delegation receipts. `InvocationReceipt.Iat` is never compared against current time. An invocation JWT signed with an arbitrarily old `iat` passes without any staleness check. Combined with the 1-hour nonce store TTL, a captured invocation can be replayed once the JTI TTL expires, as long as the delegation chain is still valid.

**Exploit scenario:** Delegation chain has 30-day `exp`. Day 1: invocation captured. Day 25: chain still valid; nonce TTL expired. The captured invocation JWT is replayed — `Iat` is 24 days old, but neither Go nor Rust checks it. Replay passes all six blocks.

**Recommendation:** Reject invocations where `now - Iat > maxInvocationAge` (suggested: 5 minutes, configurable). Also reject where `Iat > now + clockSkewTolerance`. See also F-019 (same defect in Rust).

---

### F-014 — MEDIUM — Temporal attenuation gap: child-exp-nil + parent-exp-set not caught
**File:** `drs-verify/pkg/verify/chain.go:308`
**Confidence:** 0.90

**Description:** Lines 308–315: `if receipts[i].Exp != nil && receipts[i-1].Exp != nil`. When the parent has `exp` set but the child omits `exp`, the guard is false and the check is skipped. The child gains an unbounded lifetime not explicitly granted. The Rust core has the same gap.

**Recommendation:** Add: `if receipts[i].Exp == nil && receipts[i-1].Exp != nil`, return `TEMPORAL_BOUNDS_VIOLATION`. Apply the same fix to `drs-core/src/chain/verify.rs`.

---

### F-015 — MEDIUM — X-DRS-Bundle header decoded without per-header size cap
**File:** `drs-verify/pkg/middleware/mcp.go:55`
**Confidence:** 0.90

**Description:** `decodeBundle` is called before authentication on the raw header string. Go's default `MaxHeaderBytes` is 1 MiB for all headers combined, not per-header. An attacker can send a near-1 MiB `X-DRS-Bundle` header triggering ~750 KB of base64 decode + JSON unmarshal before any signature check. At 100 RPS per-IP limit, this is 75 MB/s of pre-auth allocation from a single IP.

**Recommendation:** Check `len(bundleHeader) > maxBundleHeaderBytes` (e.g., 65536) before calling `decodeBundle`; return 413 immediately. Set explicit `MaxHeaderBytes` on the `http.Server` in main.go.

---

### F-016 — MEDIUM — getBit fail-open for out-of-range status list index
**File:** `drs-verify/pkg/revocation/status.go:228`
**Confidence:** 0.90

**Description:** `getBit` returns `false` (not-revoked) without error when the requested index is out of range for the loaded status list bitstring. A receipt with a status list index beyond the end of the bitstring is treated as not-revoked rather than triggering an error. This is fail-open for revocation.

**Recommendation:** When index >= len(bitstring) * 8, return an error. Propagate up to fail-closed: if revocation status cannot be determined, treat as revoked. Log the out-of-range access.

---

### F-017 — MEDIUM — No HTTPS enforcement for verifier URL in SDK
**File:** `drs-sdk/src/verify/client.ts:29`
**Confidence:** 0.90

**Description:** `verify.ts` defaults to `"http://localhost:8080"`. `VerifyClient` constructor accepts any URL without scheme validation. In non-loopback deployments, the full serialised bundle — all delegation receipt JWTs and the invocation receipt — is transmitted in cleartext. A MITM attacker can both read bundles and serve forged `{"valid":true}` responses.

**Recommendation:** Validate that `baseUrl` uses `https:` in non-localhost contexts. Log a warning for `http://localhost`. Add `rejectUnauthorized` flag (default `true`) for test environments.

---

### F-018 — MEDIUM — Rust verify_chain has no chain depth cap
**File:** `drs-core/src/chain/verify.rs`
**Confidence:** 0.90

**Description:** The Go layer enforces `maxChainDepth = 16`. The Rust `verify_chain` has no equivalent depth cap. An attacker submitting arbitrarily deep chains to a Rust-path consumer (WASM SDK or future native bindings) can cause unbounded Ed25519 verification work per request.

**Recommendation:** Add `const MAX_CHAIN_DEPTH: usize = 16` and return `Err(DrsError::ChainTooDeep)` when `receipts.len() > MAX_CHAIN_DEPTH` before beginning verification. Add a test confirming 17-hop chains are rejected.

---

### F-019 — MEDIUM — No temporal validity check on InvocationReceipt in Rust core
**File:** `drs-core/src/chain/verify.rs`
**Confidence:** 0.90

**Description:** Same defect as F-013 in the Go layer. The Rust `verify_chain` does not check `iat` on `InvocationReceipt` against current time. Stale invocations pass through the Rust verification path without a staleness check.

**Recommendation:** Add: if `now.unix_timestamp() - invocation.iat > MAX_INVOCATION_AGE_SECS` (suggested: 300), return `Err(DrsError::InvocationStale)`.

---

### F-020 — LOW — Unrecognized bindingMode silently degrades to lenient
**File:** `drs-verify/pkg/middleware/binding.go:28`
**Confidence:** 0.90

**Description:** `checkRequestBinding` only checks for `"off"` and `"enforced"`. Any other string — including typos like `"Enforced"` — falls through to the lenient path. No validation occurs at `MCPMiddleware`/`A2AMiddleware` construction time.

**Recommendation:** Validate `mode` string at construction time. Return error (or panic) on unrecognized mode. Export typed constants `BindingModeOff`, `BindingModeLenient`, `BindingModeEnforced`.

---

### F-021 — MEDIUM — Rust policy eval skips enforcement when required fields absent
**File:** `drs-core/src/policy.rs`
**Confidence:** 0.88

**Description:** Same opt-in pattern as F-005 in the Rust policy evaluator. Enforcement blocks guarded by field-presence checks on attacker-controlled args. If invocation omits required fields (`tool`, `resource`, `data_class`), enforcement is skipped and the invocation passes. Affects both native Rust and WASM paths.

**Recommendation:** Same fix as F-005 applied to Rust: when `policy.allowed_tools` is non-empty, args MUST contain a `"tool"` key. Absent key returns `Err(PolicyViolation)`.

---

### F-022 — MEDIUM — No recursion-depth guard for JCS canonicalization in Rust
**File:** `drs-core/src/jcs/mod.rs`
**Confidence:** 0.85

**Description:** The JCS canonicalization implementation recursively traverses JSON values without a depth limit. An attacker who can control JSON content in `invocation.args` can submit deeply nested JSON (e.g., 10000 levels) that exhausts the Rust call stack and causes a stack overflow panic or WASM trap.

**Recommendation:** Add a depth counter to the recursive JCS traversal. Return `Err(DrsError::JsonTooDeep)` when `depth > MAX_JCS_DEPTH` (e.g., 64). Single-line change at the recursive function entry.

---

### F-023 — MEDIUM — 16-hop did:web chains trigger up to 17 outbound HTTPS fetches per request
**File:** `drs-verify/pkg/verify/chain.go:39`
**Confidence:** 0.85

**Description:** Block C calls `verifyJWTSignature` once per receipt + once for the invocation (up to 17 calls total). For `did:web` DIDs, each unique uncached DID requires an outbound HTTPS fetch with a 10s timeout. A 16-hop chain with 16 distinct `did:web` issuers (all uncached) incurs worst-case 16 × 10s = 160s latency. Under concurrent load, this creates hundreds of simultaneous HTTPS fetches to attacker-controlled endpoints.

**Recommendation:** Add a per-request `did:web` resolution budget: if total did:web resolutions within one `Chain()` call exceeds N (e.g., 4), return `CHAIN_TOO_MANY_DID_FETCHES`. Provide a policy flag restricting issuers to `did:key` for strict latency deployments.

---

### F-024 — MEDIUM — did:web DID document extraction has no verification method id binding
**File:** `drs-verify/pkg/resolver/did.go:586`
**Confidence:** 0.85

**Description:** `extractEd25519FromDIDDocument` returns the first successfully parsed verification method without checking that it corresponds to the DID's fragment identifier (`#key-1` etc). An attacker controlling a `did:web` endpoint can position an invalid entry before their chosen key, causing `extractEd25519` to return the attacker's key for signature verification.

**Recommendation:** When the DID has a fragment, only extract the verification method whose `id` matches the fragment. This is the correct W3C DID Core document processing rule.

---

### F-025 — MEDIUM — Nonce store exhaustion returns 503 — attacker with valid credentials can lock out all agents
**File:** `drs-verify/pkg/nonce/store.go:87`
**Confidence:** 0.85

**Description:** `nonce.Store.Check` returns `ErrStoreExhausted` when at capacity and no expired entries exist. `CheckNonceReplay` maps this to HTTP 503. An attacker with valid signed bundles generating fresh JTIs can exhaust the default 100,000-entry store at 100 RPS per IP in ~16 minutes, or with 10 IPs at the 1000 RPS global limit in 100 seconds. All agents then receive 503 for up to 1 hour.

**Recommendation:** On exhaustion, evict oldest entries (LRU) rather than returning 503. Document the scenario as a configuration risk. Recommend Redis backend for production multi-agent deployments.

---

### F-026 — MEDIUM — Singleflight inflight entry and done channel not cleaned up in defer
**File:** `drs-verify/pkg/resolver/did.go:356`
**Confidence:** 0.85

**Description:** The singleflight implementation closes the done channel and deletes the inflight map entry outside a `defer`. If `resolveUncached` panics between acquiring the inflight entry and the cleanup code, the channel is never closed, the map entry is never removed, and goroutines waiting on the same DID block forever.

**Recommendation:** Wrap cleanup in `defer func() { close(e.done); r.mu.Lock(); delete(r.inflight, did); r.mu.Unlock() }()`. Use `recover()` to catch panics in `resolveUncached` and convert to errors.

---

### F-027 — MEDIUM — TSA URL accepted without scheme/host validation — SSRF
**File:** `drs-verify/pkg/timestamp/rfc3161.go:149`
**Confidence:** 0.85

**Description:** The TSA URL is accepted from configuration or JWT payload without validating that it uses `https:` scheme or that the host is not a private/internal address. An attacker-controlled receipt can specify a TSA URL pointing to internal infrastructure (e.g., `http://169.254.169.254/`).

**Recommendation:** (1) Validate TSA URL scheme is `https:`. (2) Validate TSA host is not a private IP (reuse the DID resolver SSRF blocklist). (3) Maintain a TSA allowlist via `TSA_ALLOWLIST` env var.

---

### F-028 — MEDIUM — WASM binary loaded without integrity verification
**File:** `drs-sdk/src/wasm/loader.ts:41`
**Confidence:** 0.85

**Description:** `initWasm(wasmUrl?)` performs a dynamic import and optionally initialises with a caller-supplied `wasmUrl` without hash verification or scheme restriction. A tampered WASM module can return `{valid: true}` for any bundle, bypassing all verification.

**Recommendation:** (1) Pin the expected WASM binary hash as a constant; verify SHA-256 after fetch before instantiation. (2) Restrict `wasmUrl` to `https:` scheme and allowlisted origins. (3) Document as unsuitable for adversarial environments until signed artifact + pinned hash is part of the release process.

---

### F-029 — MEDIUM — File-backed key management has no file permission check
**File:** `drs-sdk/src/sdk/operator.ts:39`
**Confidence:** 0.85

**Description:** `validateOperatorConfig()` checks that `operator_key_path` is present when `operator_key_management === "file"` but does not verify file existence, permissions (0600), or absolute path. A world-readable key file is silently accepted.

**Recommendation:** Check `fs.statSync(operator_key_path).mode & 0o077 === 0` — reject with `INVALID_OPERATOR_CONFIG` if group- or world-readable. Validate absolute path. Zero-fill `Uint8Array` after key derivation.

---

### F-030 — MEDIUM — Prefix wildcard priority logic gap in CapabilityIndex
**File:** `drs-core/src/capability_index.rs`
**Confidence:** 0.85

**Description:** The `CapabilityIndex` prefix wildcard lookup does not correctly prioritize specific rules over wildcard rules in all cases. A request may match a less-restrictive wildcard entry instead of a more-restrictive specific entry, allowing broader access than intended.

**Recommendation:** Ensure the lookup always returns the most-specific matching rule (longest-prefix wins). Add comprehensive test cases for wildcard vs. specific rule priority.

---

### F-031 — MEDIUM — No dedicated rate limit on POST /admin/revoke
**File:** `drs-verify/cmd/server/main.go:216`
**Confidence:** 0.80

**Description:** The global rate limiter applies to all endpoints. No dedicated per-endpoint rate limit, IP allowlist, or lockout policy is applied to `/admin/revoke`. An attacker who can reach this endpoint can attempt token enumeration at the global rate limit speed.

**Recommendation:** Add a dedicated rate limit for `/admin/revoke`: 10 RPS globally, 2 RPS per IP, 60-second lockout after 5 failures. Consider `ADMIN_ALLOWED_IPS` env var or mTLS authentication for the admin endpoint.

---

### F-032 — MEDIUM — TSA certificate validity checked against time.Now() instead of tst.GenTime
**File:** `drs-verify/pkg/timestamp/rfc3161.go:358`
**Confidence:** 0.80

**Description:** Certificate validity at lines 358–360 is checked against `time.Now()` rather than the timestamp token's `GenTime`. For archived receipts where the TSA certificate has since expired, this produces false rejections even though the certificate was valid at signing time. RFC 3161 requires validating the certificate at `GenTime`.

**Recommendation:** Replace `time.Now()` with `tst.GenTime` in certificate validity checks. Add a test with a cert whose validity ended between signing time and verification time.

---

### F-033 — MEDIUM — extractSignerCert matches by serial number only — certificate substitution possible
**File:** `drs-verify/pkg/timestamp/rfc3161.go:431`
**Confidence:** 0.80

**Description:** `extractSignerCert` matches the signer certificate by serial number only. Serial numbers are unique only within a single CA; an attacker who obtains a cert from another trusted CA with the same serial number can substitute it.

**Recommendation:** Match on both serial number AND issuer: `cert.SerialNumber.Cmp(signerInfo.IssuerAndSerial.SerialNumber) == 0 && cert.Issuer.String() == signerInfo.IssuerAndSerial.IssuerName.String()`. This is the correct RFC 3161 matching.

---

### F-034 — LOW — strictVerifyEd25519 comment misrepresents Go 1.13+ behaviour
**File:** `drs-verify/pkg/verify/chain.go:508`
**Confidence:** 0.80

**Description:** The comment at lines 511–513 claims "Go's stdlib accepts non-canonical S values". Since Go 1.13, `crypto/ed25519` already enforces S < L. The `strictVerifyEd25519` call is correct as defence-in-depth, but the misleading comment could cause a future maintainer to remove it.

**Recommendation:** Update comment: "Go 1.13+ already enforces S < L; this check is defence-in-depth for cross-implementation parity with ed25519-dalek verify_strict. Do not remove."

---

### F-035 — LOW — Unverified JWT fields echoed into error messages — log injection
**File:** `drs-sdk/src/sdk/issue.ts:148`
**Confidence:** 0.80

**Description:** `issueSubDelegation()` decodes `parentJwt` without signature verification. The decoded `parentPayload.aud` and `parentPayload.cmd` are embedded verbatim into `DrsError` message strings. An attacker providing a crafted `parentJwt` can inject newlines or other control characters into error messages forwarded to logging systems.

**Recommendation:** Strip control characters (`\n`, `\r`, `\t`) and truncate to 256 characters before embedding JWT field values in error messages. Validate `aud` matches DID format; replace non-matching values with `"<invalid>"`.

---

### F-036 — LOW — serde_json error messages expose internal Rust type names in WASM
**File:** `drs-core/src/` (WASM boundary)
**Confidence:** 0.80

**Description:** When serde_json deserialization fails in the WASM-compiled Rust core, error messages include internal Rust type names and field paths (e.g., "missing field `issuer` at line 1 column 245"). These cross the WASM boundary to JavaScript callers and can help an attacker map the internal JWT schema.

**Recommendation:** Sanitize error messages before crossing the WASM boundary. Map serde_json errors to generic `"MALFORMED_RECEIPT"` errors. Keep detailed errors only in debug builds (`cfg!(debug_assertions)`).

---

### F-037 — MEDIUM — JCS key sort diverges from RFC 8785 for supplementary-plane Unicode characters
**File:** `drs-sdk/src/sdk/jcs.ts:30`
**Confidence:** 0.75

**Description:** RFC 8785 §3.2.3 requires object members sorted in ascending Unicode code point order. JavaScript `Array.sort()` sorts by UTF-16 code unit value. For supplementary-plane characters (U+10000+), UTF-16 surrogate pairs cause sort order to diverge from code-point order. This breaks cross-implementation hash agreement with the Rust `serde-json-canonicalizer` for payloads with supplementary-plane keys.

**Recommendation:** Replace `Object.keys(obj).sort()` with a Unicode code-point comparator using `codePointAt()`. Add a conformance test with a supplementary-plane Unicode key.

---

### F-038 — LOW — JWT split three times independently in same request path
**File:** `drs-verify/pkg/verify/chain.go:49`
**Confidence:** 0.75

**Description:** The same JWT string is split by `decodeJWTHeader`, `decodeJWTPayload`, and `verifyJWTSignature` independently. The re-join at line 501 reconstructs what was already computed. No current exploit, but creates three independent parsing opportunities where a future refactor could introduce inconsistency.

**Recommendation:** Refactor to a single `parseJWT(jwt string) (header, payload, sigBytes []byte, err error)` function used by all three call sites.

---

### F-039 — LOW — trustProxy=true XFF multi-hop limitation undocumented
**File:** `drs-verify/pkg/middleware/ratelimit.go:107`
**Confidence:** 0.75

**Description:** `clientIP` uses rightmost IP in `X-Forwarded-For` when `TRUST_PROXY=true`. This is correct for exactly one trusted proxy layer. With two layers (CDN + load balancer), the rightmost entry is the CDN's egress IP, so all clients behind that CDN node share one per-IP rate bucket.

**Recommendation:** Add `TRUST_PROXY_COUNT` config (default 1) implementing "skip N rightmost" XFF logic. Add startup log warning clarifying the XFF semantic used.

---

### F-040 — LOW — Timestamp non-fatality: Valid: true does not imply TimestampTrusted: true
**File:** `drs-verify/pkg/timestamp/rfc3161.go`
**Confidence:** 0.75

**Description:** Timestamp verification failures do not fail the chain. A receipt where `VerifyTimestampTrusted` fails is treated the same as a receipt with no timestamp — chain returns `Valid: true`. Auditors who only check `Valid: true` may miss that the timestamp was absent or invalid.

**Recommendation:** Add `TimestampError` field to `VerificationContext`. Add a `strict_timestamp` mode that fails the chain if no valid RFC 3161 timestamp is present. Document clearly that `Valid: true` does not imply `TimestampTrusted: true`.

---

### F-041 — LOW — BundleProvider.getBundle() contract ambiguous — double-encoding risk
**File:** `packages/drs-mcp-client/src/client.ts:68`
**Confidence:** 0.75

**Description:** `maybeInjectBundle()` calls `getBundle()` (returns `string | null`) then passes to `stringToBase64Url()`. The interface does not state whether the return value should be a raw JSON string or already-encoded. An integrator who calls `serialiseBundle(bundle)` in their implementation produces a double-encoded bundle that fails to parse on the server side.

**Recommendation:** Update `BundleProvider` JSDoc: "return value must be a raw JSON string (`JSON.stringify(bundle)`)". Alternatively, change interface to return `ChainBundle` (typed object) and move encoding inside `maybeInjectBundle()`.

---

### F-042 — LOW — Truncating cast u64→i64 in unix_now()
**File:** `drs-core/src/` (timestamp utility)
**Confidence:** 0.75

**Description:** `unix_now()` computes Unix timestamp as u64 then casts to i64. For dates after ~year 2262, the u64 value exceeds `i64::MAX` and the cast truncates silently, producing a large negative timestamp. JWT temporal checks using this value will incorrectly evaluate all receipts.

**Recommendation:** Use checked cast: `i64::try_from(unix_timestamp).map_err(|_| DrsError::TimestampOverflow)`. Or use the `time` crate's `i64`-native type directly.

---

### F-043 — LOW — did:web path component not fully sanitized
**File:** `drs-verify/pkg/resolver/did.go`
**Confidence:** 0.70

**Description:** The did:web resolution maps DID components to URL path segments. If path components containing encoded traversal sequences (`%2F`, `%2E%2E`) are decoded before URL construction, an attacker-controlled DID could probe paths on the target host outside the intended `/.well-known/did.json` path.

**Recommendation:** Validate that each path component, after percent-decoding, does not contain `/`, `..`, or traversal sequences. Reject with `INVALID_DID` before making any network request.

---

### F-044 — LOW — Duplicate DNS resolution for same did:web domain during concurrent cache misses
**File:** `drs-verify/pkg/resolver/did.go`
**Confidence:** 0.70

**Description:** The singleflight implementation coalesces inflight requests per DID, but multiple DIDs sharing the same domain each trigger independent DNS lookups. Limited amplification effect.

**Recommendation:** Consider caching DNS resolutions at the resolver level or using a shared HTTP client with connection pooling. Low priority.

---

### F-045 — LOW — Private IP SSRF blocklist may be missing RFC 6890 ranges
**File:** `drs-verify/pkg/resolver/did.go`
**Confidence:** 0.70

**Description:** The SSRF blocklist for did:web resolution may not cover all RFC 6890 Special-Purpose Address Registries, such as 100.64.0.0/10 (Shared Address Space used in some Kubernetes deployments), 198.18.0.0/15 (benchmarking), and 240.0.0.0/4 (reserved).

**Recommendation:** Audit the SSRF blocklist against the full RFC 6890 registry. Add 100.64.0.0/10, 198.18.0.0/15, 240.0.0.0/4, and 0.0.0.0/8. Run a test suite against all RFC 6890 ranges.

---

### F-046 — LOW — Filesystem error details leaked in revocation store messages
**File:** `drs-verify/pkg/revocation/status.go`
**Confidence:** 0.70

**Description:** Error messages from the `FileBackedRevocationStore` may include OS-level error details (file paths, errno values) that expose the server's filesystem layout.

**Recommendation:** Wrap filesystem errors before surfacing them. Return only generic error codes (`"revocation store unavailable"`) to callers. Log the full error internally with `slog.Error`.

---

### F-047 — LOW — No minimum token entropy enforcement on admin revocation token
**File:** `drs-verify/cmd/server/main.go`
**Confidence:** 0.70

**Description:** The admin token is compared via `sha256.Sum256` (constant-time) but no minimum entropy requirement is enforced at startup. An operator could configure `ADMIN_TOKEN=admin`, making brute-force trivially feasible.

**Recommendation:** At startup, validate that `ADMIN_TOKEN` has at least 32 bytes of entropy (length ≥ 32 and basic entropy check). Reject startup with an error if the token is too weak.

---

### F-048 — LOW — http.Client Timeout shadows fetchTimeout context
**File:** `drs-verify/pkg/revocation/status.go`
**Confidence:** 0.70

**Description:** The status list fetcher uses both `http.Client.Timeout` and a context with `fetchTimeout`. The shorter fires first but the error type differs (`context.DeadlineExceeded` vs. `url.Error` with `Timeout: true`). Error handling that only checks one form may not handle the other correctly.

**Recommendation:** Use only the context deadline for timeout control. Set `http.Client.Timeout` to 0 (no client-level timeout) and rely entirely on the context.

---

### F-049 — LOW — FileBackedRevocationStore grows unboundedly
**File:** `drs-verify/pkg/revocation/`
**Confidence:** 0.70

**Description:** The `FileBackedRevocationStore` accumulates revoked receipt hashes without a size limit or rotation policy. In a long-running deployment with many revocations, the store file grows indefinitely and could eventually exhaust disk space.

**Recommendation:** Add `REVOCATION_STORE_MAX_ENTRIES` env var. Implement LRU eviction or compaction when the limit is reached. Log a warning at 80% capacity. Migrate to Redis backend for production.

---

### F-050 — LOW — TSA response reader off-by-one: allocates 64 KiB + 1 bytes
**File:** `drs-verify/pkg/timestamp/rfc3161.go`
**Confidence:** 0.70

**Description:** The TSA response reader may allocate `maxTSAResponseBytes + 1` bytes due to an off-by-one in the size check (`>=` vs `>`). The extra byte is negligible but represents a boundary condition discrepancy from the documented limit.

**Recommendation:** Fix the size limit check to use `> maxTSAResponseBytes` (not `>=`). Add a test case with exactly `maxTSAResponseBytes` and `maxTSAResponseBytes + 1`.

---

### F-051 — LOW — serde_json_canonicalizer pinned to '0.2' — may lag RFC 8785 conformance updates
**File:** `drs-core/Cargo.toml`
**Confidence:** 0.70

**Description:** The dependency is pinned to minor version `0.2` only. If RFC 8785 conformance fixes require a major version bump, the project will not automatically track them. CLAUDE.md lists this crate as a monitored dependency.

**Recommendation:** Pin to a specific patch version (e.g., `"=0.2.1"`). Subscribe to upstream releases. Run official RFC 8785 test vectors on every dependency update.

---

### F-052 — LOW — Circuit breaker state lost on LRU eviction
**File:** `drs-verify/pkg/resolver/did.go`
**Confidence:** 0.65

**Description:** When a DID resolver cache entry is evicted from the LRU, the associated circuit breaker state is also lost. An attacker who triggers sufficient LRU evictions (>10,000 distinct DIDs) can reset the circuit breaker for any DID, bypassing the 5-failure/60s-cooldown protection.

**Recommendation:** Maintain circuit breaker state in a separate bounded store (keyed by DID, TTL = 2× cooldown) independent of the LRU cache. Circuit breaker entries should not be evictable by LRU pressure alone.

---

### F-053 — LOW — Half-open circuit breaker allows thundering herd on recovery
**File:** `drs-verify/pkg/resolver/did.go`
**Confidence:** 0.65

**Description:** When the circuit breaker enters half-open state, concurrent goroutines may all be allowed through before the probe result is recorded, creating a thundering herd on recovery.

**Recommendation:** Use atomic compare-and-swap to ensure only one goroutine transitions to probing at a time. Other goroutines in the half-open window should wait for the probe result.

---

### F-054 — LOW — No failed-authentication audit log for /admin/revoke
**File:** `drs-verify/cmd/server/main.go`
**Confidence:** 0.65

**Description:** Failed authentication attempts against `/admin/revoke` are rejected without a security audit log entry. Detecting token brute-force attempts requires inferring from HTTP 401 metrics alone, with no correlation to source IP or timing.

**Recommendation:** Add `slog.Warn("admin auth failed", "ip", clientIP, "ua", userAgent)` on every 401. Emit `admin_auth_failures_total` metrics counter with IP label.

---

### F-055 — LOW — splitn(4, '.') semantically should be splitn(3, '.')
**File:** `drs-core/src/` (JWT parsing)
**Confidence:** 0.65

**Description:** Rust JWT splitting code uses `splitn(4, '.')` but validates `len == 3`. Using `splitn(3, '.')` would be semantically cleaner and make the intent (exactly 2 dots in a valid JWT) explicit. No current exploit; maintenance clarity concern only.

**Recommendation:** Change `splitn(4, '.')` to `splitn(3, '.')`. Add comment explaining why splitn(3) is used.

---

## Next step

```
/triage /home/okey/Desktop/Projects/DRS/VULN-FINDINGS.json --repo /home/okey/Desktop/Projects/DRS
```

> **Note:** These are static candidates, not verified. For execution-verified crashes and PoC reproduction, run `vuln-pipeline run <target>` (README Step 2) against the drs-core Rust code. The Go and TypeScript layers can be verified with integration tests against the existing test suite.
