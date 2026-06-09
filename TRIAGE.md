# DRS Security Triage

**Source:** `VULN-FINDINGS.json` (55 raw findings, 48 candidates after dedup)
**Generated:** 2026-06-08
**Method:** 3-vote adversarial verification per finding; recall noise tolerance (split votes → `needs_manual_test`)

---

## Summary

| Verdict | Count |
|---|---|
| TRUE_POSITIVE | 9 |
| NEEDS_MANUAL_TEST | 4 |
| FALSE_POSITIVE | 35 |
| Duplicates removed | 7 |
| **Total input** | **55** |

---

## TRUE_POSITIVE findings — ranked by exploitability

### #1 · f001 · HIGH · `drs-sdk/src/cli/commands/keygen.ts:23`
**Ed25519 private key printed to stdout**
Threat: key compromise / CLI key exposure · Confidence: 0.87 · Component: drs-sdk

The `keygen` command writes the raw Ed25519 private key as hex to stdout. Shell history, CI logs, pipe recipients, and process-listing observers all receive the key in plaintext.

**Fix:** Write private key only to a file with mode 0600. Never to stdout. Add `--out <path>` flag. Emit nothing to stdout in the keygen happy path.

---

### #2 · f007 · HIGH · `drs-verify/pkg/middleware/binding.go:34`
**io.ReadAll with no MaxBytesReader on request body**
Threat: DoS verification path · Confidence: 0.80 · Component: drs-verify

`io.ReadAll(r.Body)` on the MCP/A2A binding middleware path has no size cap. A multi-gigabyte body stalls the goroutine until WriteTimeout fires (~30s), driving GC pressure and starving legitimate requests.

**Fix:** `r.Body = http.MaxBytesReader(w, r.Body, 65536)` before the ReadAll call.

---

### #3 · f015 · MEDIUM · `drs-verify/pkg/middleware/mcp.go:55`
**X-DRS-Bundle header: base64.DecodeString before size check**
Threat: DoS verification path · Confidence: 0.90 · Component: drs-verify

`base64.DecodeString` eagerly allocates its output buffer before any size check. No `http.MaxHeaderBytes` on the server. A 1 MB header value causes ~750 KB allocation per request, applied before the rate limiter fires.

**Fix:** Reject `len(bundleHeader) > 87381` before calling DecodeString. Or use `base64.NewDecoder` with `io.LimitReader`.

---

### #4 · f011 · MEDIUM · `drs-core/src/capability/policy.rs:167`
**O(n·m) Vec::contains in capability attenuation check**
Threat: DoS (algorithmic complexity) · Confidence: 0.90 · Component: drs-core

Nested `Vec::contains` over parent capabilities for each child capability produces O(n·m) comparisons. With 16 receipts × 500 capabilities = 8 million comparisons per verification. Attacker controls sub-delegation capability lists.

**Fix:** Build a `HashSet<&str>` from the parent list once per receipt. O(n + m).

---

### #5 · f018 · MEDIUM · `drs-core/src/chain/verify.rs:26`
**verify_chain has no depth cap on the WASM surface**
Threat: DoS (stack overflow in WASM) · Confidence: 0.80 · Component: drs-core

The Go layer caps chain depth at 16 before invoking Rust. The Rust function has no equivalent guard. When called directly from WASM bindings (bypassing Go), a 10,000-link chain overflows the WASM stack. A panic or error on the WASM surface may be treated as fail-open by the caller.

**Fix:** Add an explicit depth counter; return `Err(VerifyError::ChainTooDeep)` when depth > 16.

---

### #6 · f023 · MEDIUM · `drs-verify/pkg/verify/chain.go:236`
**Block C DID resolution is fully serial**
Threat: DoS (serial egress) · Confidence: 0.77 · Component: drs-verify

The Block C loop resolves each receipt's issuer DID sequentially. With 16 distinct `did:web` issuers each responding in 9s, total Block C latency is 144s per chain. The circuit breaker does not protect against slow-but-responding servers.

**Fix:** Collect unique issuer DIDs, resolve concurrently via `errgroup` with a semaphore (max 8), then apply results to the chain.

---

### #7 · f032 · MEDIUM · `drs-verify/pkg/anchor/rfc3161.go:358`
**Redundant time.Now() check falsely rejects archived receipts**
Threat: Timestamp evidence integrity · Confidence: 0.90 · Component: drs-verify

`rfc3161.go:345` correctly sets `CurrentTime: tst.GenTime` per RFC 3161 §2.3. Lines 358-360 add a second check using `time.Now()`. For archived receipts whose TSA certificate has expired since signing, the first check passes but the second fails. Validly-timestamped archived receipts are falsely rejected.

**Fix:** Delete lines 358-360. The `cert.Verify(opts)` at line 342-350 with `CurrentTime: tst.GenTime` is the correct and sufficient check.

---

### #8 · f033 · MEDIUM · `drs-verify/pkg/anchor/rfc3161.go:431`
**extractSignerCert: serial-number-only match (RFC 5652 §10.2.3 violation)**
Threat: Timestamp evidence forgery · Confidence: 0.67 · Component: drs-verify

`extractSignerCert` discards `ias.Issuer` and matches only on `ias.SerialNumber`. RFC 5652 §10.2.3 requires both issuer name AND serial. For the exported `VerifyTimestamp` (no trust pool), an attacker who controls a CA with a serial-number collision can substitute their certificate. `VerifyTimestampTrusted` has a compensating trust-pool control; `VerifyTimestamp` does not.

**Fix:** Match on both `cert.Issuer` and `cert.SerialNumber` in `extractSignerCert`. Consider requiring a non-nil trust pool in `VerifyTimestamp`.

---

### #9 · f037 · LOW · `drs-sdk/src/sdk/jcs.ts:30`
**JCS key sort uses UTF-16 order — RFC 8785 §3.2.3 requires Unicode code point order**
Threat: Latent cross-implementation JCS divergence · Confidence: 0.60 · Component: drs-sdk

`Object.keys(obj).sort()` without a custom comparator sorts by UTF-16 code unit value. For supplementary-plane characters (U+10000+, e.g. emoji), this diverges from Unicode code point order. The Rust and Go implementations both use code-point order. Currently latent: the JWT verifier reads raw signing bytes; the binding check applies symmetric Go JCS. The conformance test vectors contain only ASCII keys; the fixture generator has the same defect. **Risk activates if the WASM `jcs_canonical_bytes` path is wired into the signing flow.**

**Fix:** Replace with a code-point-aware sort comparator. Add supplementary-plane key test vectors.

---

## NEEDS_MANUAL_TEST

These findings produced a split vote (2:1) under recall noise tolerance. They require a hands-on test to resolve.

| ID | Severity | Vote split | File:line | Title |
|---|---|---|---|---|
| f014 | MEDIUM | 2TP:1FP | chain.go:308 | nil-child-exp guard may bypass Block D2 policy check |
| f008 | MEDIUM | 2FP:1TP | chain.go:0 | Cross-instance replay via empty SERVER_IDENTITY |
| f016 | LOW | 2FP:1TP | status.go:228 | getBit fail-open for out-of-range index |
| f025 | LOW | 2FP:1TP | nonce/store.go:87 | ErrStoreExhausted under load |

**f014** (chain.go:308): Craft a chain where the child receipt has a nil `exp` claim and the parent has a non-nil `exp`. Confirm whether Block D2 attenuation check catches or passes it. If it passes: TRUE_POSITIVE fix required.

**f008** (cross-instance replay): Confirm whether `SERVER_IDENTITY` / `TOOL_SERVER_URL` is set in all production deployments. If any deployment runs with an empty ServerIdentity, the D4c `tool_server` binding check is silently skipped and a captured chain can be replayed against a different server.

**f016** (status.go:228): Craft a chain where the revocation status list at verification time is shorter than the index stored in the signed receipt. Confirm whether `getBit` returns `false` (not-revoked) or an error.

**f025** (nonce/store.go:87): Measure the nonce store capacity and TTL in production configuration. If capacity × TTL allows exhaustion within the global rate limit window, this is a TRUE_POSITIVE.

---

## Component routing

| Component | Owner | Findings |
|---|---|---|
| `drs-sdk` (TypeScript) | SDK owner | f001 (HIGH), f037 (LOW) |
| `drs-verify` (Go) | Verify server owner | f007 (HIGH), f015 (MEDIUM), f023 (MEDIUM), f032 (MEDIUM), f033 (MEDIUM), f008¹, f014¹, f016¹, f025¹ |
| `drs-core` (Rust) | Core crypto owner | f011 (MEDIUM), f018 (MEDIUM) |

¹ needs_manual_test — route for human testing, not immediate code fix.

---

## False positive summary

35 findings confirmed false positive. Major exclusion categories:

| Rule | Count | Examples |
|---|---|---|
| Rule 3 — intended design | 12 | binding mode constants, non-fatal timestamps, operator env vars |
| Org Rule B — drs-verify internal only | 8 | HTTP health checks, metrics port, rate-limit bypass via XFF |
| Rule 13 — missing hardening (not exploitable) | 7 | absent audit logs, missing EKU validation path, CGNAT range |
| Rule 12 — nuisance / scanner misquote | 4 | comment text misquoted, non-secret DIDs in errors |
| Rule 1 — volumetric DoS (infra layer) | 2 | singleflight dedup, nonce exhaustion (under Org B conditions) |
| Rule 10 — dependency version management | 1 | Cargo.toml semver pin with Cargo.lock present |
| Other (2, 7, 8, 16) | 1 each | test-only, path traversal, trusted CLI, theoretical race |
