# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by independent agents reading source. They were NOT compiled, run, or re-attacked. Read each diff yourself before applying — see `docs/patching.md#reviewing-generated-patches` for what to look for.

**Input:** TRIAGE.json · **Repo:** /home/okey/Desktop/Projects/DRS · 9 findings → 8 diffs · 8 ACCEPT · 0 REJECT

---

## bug_01: [HIGH] io.ReadAll on request body in binding middleware — no MaxBytesReader  (f007)

`drs-verify/pkg/middleware/binding.go:34` · unbounded-read · owner: drs-verify
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_01/patch.diff`

**Rationale:** Replaced `io.LimitReader` with `http.MaxBytesReader` which caps allocation AND closes the connection on overrun. Tightened limit 1MiB→64KiB. Removed redundant post-read `len` check.
**Variants checked:** binding.go:checkRequestBinding — patched; mcp.go, a2a.go — no direct body reads; outbound client reads already bounded separately.
**Bypass considered:** Slow-drip with Content-Length:100 but 100MB actual body: MaxBytesReader fires at 64KiB+1, connection marked for close.

---

## bug_02: [MEDIUM] X-DRS-Bundle header decoded before size check — no header size cap  (f015)

`drs-verify/pkg/middleware/mcp.go:55` · unbounded-read · owner: drs-verify
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_02/patch.diff`

**Rationale:** Added `maxBundleHeaderBytes=87381` constant and `len(encoded)` guard at top of `decodeBundle` before `base64.RawURLEncoding.DecodeString`. Covers both mcp.go and a2a.go callers via shared function.
**Variants checked:** decodeBundle (mcp.go) — fixed; a2a.go — calls same function, covered; decode.go — operates on already-decoded fields.
**Bypass considered:** Exactly maxBundleHeaderBytes+1 bytes fires errBundleTooLarge before any allocation.

---

## bug_03: [MEDIUM] O(n*m) Vec::contains in capability attenuation check  (f011)

`drs-core/src/capability/policy.rs:167` · algorithmic-complexity · owner: drs-core
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_03/patch.diff`

**Rationale:** Added `HashSet<&String>` built once per allowlist section; replaced `Vec::contains` with `HashSet::contains` for all three sections (allowed_tools, allowed_resources, allowed_data_classes). O(n+m) per call vs O(n*m).
**Variants checked:** All three allowlist sections in check_policy_attenuation — all fixed; capability/index.rs — different pattern, unaffected.
**Bypass considered:** 500×500 input: was 250k comparisons, now 1000 ops. HashSet semantically identical for exact String equality.

---

## bug_04: [MEDIUM] Rust verify_chain has no depth cap — WASM stack overflow on deep chains  (f018)

`drs-core/src/chain/verify.rs:26` · unbounded-recursion · owner: drs-core
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_04/patch.diff`

**Rationale:** Added `const MAX_CHAIN_DEPTH: usize = 16` (mirroring Go layer's `maxChainDepth=16`) and guard immediately after `EMPTY_CHAIN` check. Returns `CHAIN_TOO_DEEP` before any JWT decoding or crypto work.
**Variants checked:** wasm/bindings.rs:wasm_verify_chain calls verify_chain directly — now protected.
**Bypass considered:** 17-receipt WASM bundle: depth check fires before any heap allocation for decoded-receipt vector.

---

## bug_05: [MEDIUM] Block C DID resolution is fully serial — 16 distinct issuers force 16 sequential HTTPS round trips  (f023)

`drs-verify/pkg/verify/chain.go:236` · serial-blocking-io · owner: drs-verify
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_05/patch.diff`

**Rationale:** Added `resolveIssuersParallel` (dedup + bounded goroutine pool via buffered channel semaphore of size 8, stdlib `sync.WaitGroup` only) and `verifyJWTSignatureWithKey` (network-free). Block C pre-resolves all unique issuer DIDs concurrently then verifies from map.
**Variants checked:** Both receipt loop (line 236) and invocation verification (line 243) converted; original `verifyJWTSignature` preserved.
**Bypass considered:** 16 did:web issuers at 10s each: was 160s serial, now 20s parallel. `resolvedKeys` map written sequentially after `wg.Wait()` — no race.
> **Reviewer note:** Original `verifyJWTSignature` is now dead code within `Chain` — clean up in a follow-up commit.

---

## bug_06: [MEDIUM] Redundant time.Now() validity check contradicts tst.GenTime — archived receipts falsely rejected  (f032)

`drs-verify/pkg/anchor/rfc3161.go:358` · timestamp-validation-logic · owner: drs-verify
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_06/patch.diff`

**Rationale:** Deleted 4-line `now := time.Now()` block from `VerifyTimestampTrusted`. The `cert.Verify(opts)` at lines 342-350 with `opts.CurrentTime=tst.GenTime` is the RFC 3161 §2.3-correct check; the deleted block was a logically contradictory duplicate using wall-clock time.
**Variants checked:** VerifyTimestamp (no-pool variant) — no redundant check; VerifyTimestampTrusted — sole occurrence of time.Now() in file.
**Bypass considered:** Cert not yet valid at GenTime: cert.Verify with CurrentTime:tst.GenTime already rejects this.

---

## bug_07: [MEDIUM] extractSignerCert matches on serial number only — RFC 5652 §10.2.3 requires issuer+serial  (f033)

`drs-verify/pkg/anchor/rfc3161.go:431` · insufficient-cert-matching · owner: drs-verify
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_07/patch.diff`

**Rationale:** Added `bytes.Equal(cert.RawIssuer, ias.Issuer.FullBytes)` conjunct to match condition in `extractSignerCert`; `bytes` package already imported. Covers both `VerifyTimestamp` and `VerifyTimestampTrusted`.
**Variants checked:** extractSignerCert — sole cert-selection function; both exported entry points call it.
**Bypass considered:** Attacker cert with matching serial but different issuer DN: bytes.Equal fails on raw DER mismatch.
> **Reviewer note:** `extractIntermediateCerts` line 395 uses serial-only exclusion — separate concern, lower severity, should be tracked separately.

---

## bug_08: [LOW] JCS key sort uses UTF-16 code unit order — diverges from RFC 8785 for supplementary-plane characters  (f037)

`drs-sdk/src/sdk/jcs.ts:30` · cryptographic-correctness · owner: drs-sdk
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_08/patch.diff`

**Rationale:** Replaced `.sort()` with `.sort(compareKeysByCodePoint)` in `jcs.ts` and `generate.mjs` (inlined copy). `compareKeysByCodePoint` iterates by `codePointAt()` advancing by 2 for supplementary chars. Added `jcs-016-supplementary-plane-key` vector (U+1D11E 𝄞 vs 'a').
**Variants checked:** jcs.ts — primary fix; generate.mjs — same bug, same fix; conformance.test.ts — imports production module, no duplication.
**Bypass considered:** U+1D11E vs 'a': old sort gave 𝄞 first (wrong); new sort gives 'a' first (code point 0x61 < 0x1D11E, correct per RFC 8785 §3.2.3).

---

## Skipped (no patch)

| Finding | Reason |
|---|---|
| f001 · HIGH · keygen.ts:23 | Already patched in current codebase; existing regression test guards property |
