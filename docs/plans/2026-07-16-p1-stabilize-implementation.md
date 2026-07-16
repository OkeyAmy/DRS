# P1 Stabilize — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute Phase P1 of `docs/specs/2026-07-16-drs-long-term-architecture-design.md` — fix the drs-core WASM clock panic and freeze the crate as non-normative, clean up the SDK verify-client contract, align all configuration sources, and publish the honesty documentation. No wire-format changes.

**Architecture:** drs-verify (Go) is the sole normative verifier. drs-core gets one bug fix (wasm clock), a non-normative label, and version 0.1.2, then freezes. The SDK's `/verify` HTTP client becomes the only supported verification path. Configuration truth consolidates on `pkg/config/config.go`.

**Tech Stack:** Rust (drs-core, wasm-bindgen/js-sys, wasm-pack test), TypeScript (drs-sdk, vitest, pnpm), Go (drs-verify), Docker Compose.

## Global Constraints

- **Never run `git commit` without Okey's explicit go-ahead.** At each "Commit" step: stage the files, show the proposed message, and wait for confirmation. If executing autonomously, stop at the first commit step and ask once whether to commit per-task or batch at the end.
- Always `pnpm`, never `npm`.
- Rust: no `unwrap()` in library code (test code may use it). `cargo fmt` before every commit.
- Go: `gofmt` clean; no `_` on error returns in production paths.
- TypeScript: `prettier` clean; never `catch (e: any)`.
- Fail-closed: any new validation error denies, never warns-and-continues.
- Wire format untouched: `drs_v` stays `"4.0"`; no receipt field changes in P1.
- Spec reference for every task: `docs/specs/2026-07-16-drs-long-term-architecture-design.md` (cited as "spec" below).

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `drs-core/tests/wasm_chain.rs` | Create | wasm32 regression test: full chain verifies without trapping |
| `drs-core/src/chain/verify.rs` | Modify | `unix_now()` gets a wasm32 branch (js_sys::Date) |
| `drs-core/Cargo.toml` | Modify | wasm32 target deps (js-sys, getrandom/js, wasm-bindgen-test); version 0.1.2 |
| `drs-core/README.md` | Modify | Non-normative reference label; drop "single source of truth" claim |
| `drs-sdk/src/verify/client.ts` | Modify | Drop X-DRS-Bundle header; 409 → REPLAY_DETECTED; drop 403 case |
| `drs-sdk/src/verify/client.test.ts` | Modify | Tests for the three contract changes |
| `drs-sdk/src/index.ts` | Modify | Remove WASM loader from public exports |
| `drs-sdk/src/wasm/loader.ts` | Modify | @deprecated notice |
| `drs-sdk/README.md` | Modify | "Verification = HTTP client" statement |
| `drs-verify/pkg/config/config.go` | Modify | Nonce TTL default 900; memory+TRUST_PROXY guard |
| `drs-verify/pkg/config/config_test.go` | Modify | Tests for both changes |
| `docker-compose.yml` | Modify | Pass TLS_CERT_FILE/TLS_KEY_FILE/DID_CACHE_SIZE/DID_CACHE_TTL_SECS/TSA_ROOT_CERT_PEM |
| `.env.example` | Modify | Document the five newly passed vars |
| `README.md` (root) | Modify | "What DRS proves — and what it does not" section |
| `docs/drs-source-of-truth.md` | Append | Claim-based policy fields; `/verify` HTTP status contract |
| `docs/production-readiness-checklist.md` | Append | Redis mandate for multi-replica deployments |
| `drs-verify/pkg/verify/chain.go` | Modify | Comment at `resolveIssuersParallel` buffered-channel idiom |

---

### Task 1: WASM regression test harness (write the failing test)

**Files:**
- Modify: `drs-core/Cargo.toml`
- Create: `drs-core/tests/wasm_chain.rs`

**Interfaces:**
- Consumes: `drs_core::{chain::verify::verify_chain, chain::hash::compute_chain_hash, did::key::encode_did_key, jwt::encode::build_jwt, types::ChainBundle}` — all existing public API.
- Produces: the failing test that Task 2 makes pass. Test name: `full_chain_verifies_on_wasm`.

- [ ] **Step 1: Add wasm32 target dependencies to Cargo.toml**

Append after the `[dev-dependencies]` section of `drs-core/Cargo.toml`:

```toml
# wasm32-only dependencies. js-sys provides Date::now() for unix_now();
# getrandom's "js" feature makes OsRng functional under wasm32-unknown-unknown.
[target.'cfg(target_arch = "wasm32")'.dependencies]
js-sys = "0.3"
getrandom = { version = "0.2", features = ["js"] }

[target.'cfg(target_arch = "wasm32")'.dev-dependencies]
wasm-bindgen-test = "0.3"
```

- [ ] **Step 2: Write the failing wasm test**

Create `drs-core/tests/wasm_chain.rs`:

```rust
//! WASM regression test for the Block E clock panic.
//!
//! `SystemTime::now()` panics on wasm32-unknown-unknown, so `verify_chain`
//! trapped on every bundle that reached Block E. This test builds a real
//! signed single-receipt chain and verifies it end-to-end under wasm.
//!
//! Run: wasm-pack test --node -- --features wasm
//!
//! Uses fixed key seeds and fixed JTIs: no RNG, no SystemTime in the test
//! itself, so the only clock call under test is verify_chain's own.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test;

use drs_core::chain::hash::compute_chain_hash;
use drs_core::chain::verify::verify_chain;
use drs_core::did::key::encode_did_key;
use drs_core::jwt::encode::build_jwt;
use drs_core::types::ChainBundle;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn fixed_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[wasm_bindgen_test]
fn full_chain_verifies_on_wasm() {
    let root_sk = fixed_signing_key(7);
    let agent_sk = fixed_signing_key(8);
    let root_did = encode_did_key(&root_sk.verifying_key().to_bytes());
    let agent_did = encode_did_key(&agent_sk.verifying_key().to_bytes());

    let root_jwt = build_jwt(
        &json!({
            "iss": root_did, "sub": root_did, "aud": agent_did,
            "drs_v": "4.0", "drs_type": "delegation-receipt",
            "cmd": "/mcp/tools/call",
            "policy": {},
            "nbf": 1_000_000_000i64, "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64, "jti": "dr:wasm-test-root",
            "prev_dr_hash": null,
            "drs_root_type": "human",
            "drs_consent": {
                "method": "explicit-ui-click",
                "timestamp": "2026-01-01T00:00:00Z",
                "session_id": "sess-wasm-1",
                "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "locale": "en-GB"
            }
        }),
        &root_sk,
    )
    .expect("root JWT builds");

    let invocation_jwt = build_jwt(
        &json!({
            "iss": agent_did, "sub": root_did,
            "drs_v": "4.0", "drs_type": "invocation-receipt",
            "cmd": "/mcp/tools/call",
            "args": {"tool": "web_search"},
            "dr_chain": [compute_chain_hash(&root_jwt)],
            "tool_server": "did:key:z6MkToolServer",
            "iat": 1_700_000_000i64, "jti": "inv:wasm-test-1"
        }),
        &agent_sk,
    )
    .expect("invocation JWT builds");

    let bundle = ChainBundle {
        bundle_version: "4.0".to_string(),
        invocation: invocation_jwt,
        receipts: vec![root_jwt],
    };

    let result = verify_chain(&bundle);
    assert!(
        result.valid,
        "valid chain must verify on wasm; error: {:?}",
        result.error
    );
}

#[wasm_bindgen_test]
fn tampered_receipt_fails_on_wasm() {
    let root_sk = fixed_signing_key(7);
    let agent_sk = fixed_signing_key(8);
    let root_did = encode_did_key(&root_sk.verifying_key().to_bytes());
    let agent_did = encode_did_key(&agent_sk.verifying_key().to_bytes());

    let root_jwt = build_jwt(
        &json!({
            "iss": root_did, "sub": root_did, "aud": agent_did,
            "drs_v": "4.0", "drs_type": "delegation-receipt",
            "cmd": "/mcp/tools/call",
            "policy": {},
            "nbf": 1_000_000_000i64, "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64, "jti": "dr:wasm-test-root",
            "prev_dr_hash": null,
            "drs_root_type": "human",
            "drs_consent": {
                "method": "explicit-ui-click",
                "timestamp": "2026-01-01T00:00:00Z",
                "session_id": "sess-wasm-1",
                "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "locale": "en-GB"
            }
        }),
        &root_sk,
    )
    .expect("root JWT builds");

    // Tamper: flip the last signature character.
    let mut tampered = root_jwt.clone();
    let last = if tampered.ends_with('A') { 'B' } else { 'A' };
    tampered.pop();
    tampered.push(last);

    let invocation_jwt = build_jwt(
        &json!({
            "iss": agent_did, "sub": root_did,
            "drs_v": "4.0", "drs_type": "invocation-receipt",
            "cmd": "/mcp/tools/call",
            "args": {"tool": "web_search"},
            "dr_chain": [compute_chain_hash(&tampered)],
            "tool_server": "did:key:z6MkToolServer",
            "iat": 1_700_000_000i64, "jti": "inv:wasm-test-2"
        }),
        &agent_sk,
    )
    .expect("invocation JWT builds");

    let bundle = ChainBundle {
        bundle_version: "4.0".to_string(),
        invocation: invocation_jwt,
        receipts: vec![tampered],
    };

    let result = verify_chain(&bundle);
    assert!(!result.valid, "tampered receipt must fail on wasm");
}
```

- [ ] **Step 3: Run the wasm test to verify it fails (the panic)**

```bash
cd drs-core && wasm-pack test --node -- --features wasm
```

Expected: FAIL — `full_chain_verifies_on_wasm` traps with `RuntimeError: unreachable` (the `SystemTime::now()` panic reaching Block E). `tampered_receipt_fails_on_wasm` passes (fails at Block C, before the clock).

If `wasm-pack` is not installed: `cargo install wasm-pack` first. If the build itself fails on `getrandom`, the Step 1 target dependency is missing — re-check Cargo.toml.

- [ ] **Step 4: Verify native tests still pass**

```bash
cd drs-core && cargo test
```

Expected: PASS (all existing tests unaffected).

- [ ] **Step 5: Stage + confirm commit with Okey**

```bash
git add drs-core/Cargo.toml drs-core/tests/wasm_chain.rs
# proposed: test(drs-core): add wasm32 regression test exposing Block E clock panic
```

---

### Task 2: Fix `unix_now()` for wasm32

**Files:**
- Modify: `drs-core/src/chain/verify.rs` (imports at line 1, `unix_now` at ~line 585)

**Interfaces:**
- Consumes: `js_sys::Date::now()` (added in Task 1's Cargo change).
- Produces: `fn unix_now() -> Result<i64, DrsError>` — same signature, now safe on wasm32. Task 1's test passes.

- [ ] **Step 1: Gate the std::time import**

In `drs-core/src/chain/verify.rs`, replace:

```rust
use std::time::{SystemTime, UNIX_EPOCH};
```

with:

```rust
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
```

- [ ] **Step 2: Split unix_now() by target**

Replace the existing `unix_now` function with:

```rust
/// Returns the current Unix time in seconds, or an error if the clock is
/// unavailable or out of range.
///
/// Fail-closed: callers must treat the error as a verification failure rather
/// than substituting a sentinel. Returning 0 on error (the previous behaviour)
/// made every receipt with a positive `exp` pass the expiry check — a temporal
/// bypass on any clock anomaly. The cast uses `i64::try_from` so a clock past
/// year 2262 fails closed instead of silently wrapping to a negative timestamp.
#[cfg(not(target_arch = "wasm32"))]
fn unix_now() -> Result<i64, crate::error::DrsError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::error::DrsError::ClockError)?
        .as_secs();
    i64::try_from(secs).map_err(|_| crate::error::DrsError::ClockError)
}

/// wasm32 variant: `SystemTime::now()` PANICS on wasm32-unknown-unknown
/// ("time not implemented on this platform"), which trapped `verify_chain`
/// on every bundle reaching Block E — unreachable by the fail-closed
/// `ClockError` path, because the panic fired before `duration_since`.
/// `js_sys::Date::now()` returns milliseconds since the Unix epoch as f64
/// from the host JS environment; non-finite or negative values fail closed.
#[cfg(target_arch = "wasm32")]
fn unix_now() -> Result<i64, crate::error::DrsError> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 {
        return Err(crate::error::DrsError::ClockError);
    }
    Ok((millis / 1000.0) as i64)
}
```

- [ ] **Step 3: Run the wasm test to verify it passes**

```bash
cd drs-core && wasm-pack test --node -- --features wasm
```

Expected: PASS — both `full_chain_verifies_on_wasm` and `tampered_receipt_fails_on_wasm`.

- [ ] **Step 4: Run native tests + fmt**

```bash
cd drs-core && cargo test && cargo fmt --check
```

Expected: PASS, no fmt diffs (run `cargo fmt` if needed).

- [ ] **Step 5: Stage + confirm commit with Okey**

```bash
git add drs-core/src/chain/verify.rs
# proposed: fix(drs-core): use js_sys::Date for unix_now on wasm32 — Block E no longer traps
```

---

### Task 3: Non-normative label + version 0.1.2

**Files:**
- Modify: `drs-core/Cargo.toml` (version line)
- Modify: `drs-core/README.md` (intro paragraphs)

**Interfaces:**
- Consumes: nothing.
- Produces: drs-core 0.1.2, frozen. No later task touches drs-core.

- [ ] **Step 1: Bump version**

In `drs-core/Cargo.toml`: `version = "0.1.1"` → `version = "0.1.2"`.

- [ ] **Step 2: Replace the misleading intro claim**

In `drs-core/README.md`, replace the paragraph beginning "This crate is the single source of truth…" with:

```markdown
> **Status: non-normative reference implementation.** The normative DRS
> verifier is [`drs-verify`](../drs-verify) (Go); all production verification
> goes through its HTTP `/verify` endpoint. This crate records the DRS
> algorithms (RFC 8785 JCS, SHA-256 chain hashing, Ed25519 verification,
> Blocks A–E) as reviewable Rust and is **feature-frozen** — it receives
> bug fixes only.
>
> Known, intentional gaps vs the normative verifier: no `tool_server`
> binding, no invocation `iat` freshness check, no replay protection, no
> revocation (Block F), `did:key` only. Do not use this crate's
> `verify_chain` as your production verifier.
```

- [ ] **Step 3: Build + test**

```bash
cd drs-core && cargo test && cargo package --allow-dirty --no-verify --list > /dev/null && echo package-ok
```

Expected: tests PASS, `package-ok` printed (README/Cargo metadata valid).

- [ ] **Step 4: Stage + confirm commit with Okey**

```bash
git add drs-core/Cargo.toml drs-core/README.md
# proposed: docs(drs-core): mark crate non-normative and feature-frozen; bump to 0.1.2
```

(Publishing 0.1.2 to crates.io is a separate release action Okey triggers — not part of this plan.)

---

### Task 4: SDK verify-client contract cleanup

**Files:**
- Modify: `drs-sdk/src/verify/client.ts`
- Modify: `drs-sdk/src/verify/client.test.ts`

**Interfaces:**
- Consumes: existing `DrsError` from `../sdk/types.js`.
- Produces: `VerifyClient.verify()` — same signature; new behaviour: no `X-DRS-Bundle` header; HTTP 409 throws `DrsError` with code `"REPLAY_DETECTED"`; any other non-OK status throws `VERIFY_SERVICE_ERROR` (the 403 pass-through is gone — `/verify` never returns 403; that status belongs to the in-process Go middleware only).

- [ ] **Step 1: Write the failing tests**

In `drs-sdk/src/verify/client.test.ts`:

(a) Replace the existing `it("returns invalid result on 403", ...)` test with:

```typescript
it("throws VERIFY_SERVICE_ERROR on 403 (no middleware pass-through)", async () => {
  const mockFetch = vi.fn().mockResolvedValue({
    ok: false,
    status: 403,
    json: async () => invalidResult,
  });
  vi.stubGlobal("fetch", mockFetch);

  const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
  await expect(
    client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
  ).rejects.toMatchObject({ code: "VERIFY_SERVICE_ERROR" });
  vi.unstubAllGlobals();
});
```

(b) Add:

```typescript
it("throws REPLAY_DETECTED on 409", async () => {
  const mockFetch = vi.fn().mockResolvedValue({
    ok: false,
    status: 409,
    json: async () => ({
      error: "REPLAY_DETECTED",
      detail: "jti inv:abc already seen",
      suggestion: "Generate a new invocation with a unique jti.",
    }),
  });
  vi.stubGlobal("fetch", mockFetch);

  const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
  await expect(
    client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
  ).rejects.toMatchObject({ code: "REPLAY_DETECTED" });
  vi.unstubAllGlobals();
});

it("does not send the X-DRS-Bundle header", async () => {
  const mockFetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({ valid: true }),
  });
  vi.stubGlobal("fetch", mockFetch);

  const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
  await client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" });

  const headers = mockFetch.mock.calls[0]![1]!.headers as Record<string, string>;
  expect(headers["X-DRS-Bundle"]).toBeUndefined();
  expect(headers["Content-Type"]).toBe("application/json");
  vi.unstubAllGlobals();
});
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pnpm --filter @okeyamy/drs-sdk test -- src/verify/client.test.ts
```

Expected: the three new/changed tests FAIL (403 currently passes through; 409 currently throws VERIFY_SERVICE_ERROR; header currently present).

- [ ] **Step 3: Implement the client changes**

In `drs-sdk/src/verify/client.ts`:

(a) Delete the import line `import { serialiseBundle } from "../sdk/bundle.js";`

(b) In the `fetch` call, replace the headers object with:

```typescript
headers: {
  "Content-Type": "application/json",
},
```

(c) Replace the status-handling block

```typescript
if (!response.ok && response.status !== 403) {
  throw new DrsError(
    "VERIFY_SERVICE_ERROR",
    `drs-verify returned unexpected status ${response.status}.`,
  );
}
```

with:

```typescript
if (response.status === 409) {
  // Replay rejection is not a VerificationResult — surface it typed.
  let detail = "";
  try {
    const body = (await response.json()) as Record<string, unknown>;
    if (typeof body["detail"] === "string") detail = ` ${body["detail"]}`;
  } catch {
    // body unreadable — throw without detail
  }
  throw new DrsError(
    "REPLAY_DETECTED",
    `drs-verify rejected the invocation as a replay.${detail}`,
  );
}
if (!response.ok) {
  throw new DrsError(
    "VERIFY_SERVICE_ERROR",
    `drs-verify returned unexpected status ${response.status}.`,
  );
}
```

(d) Update the class JSDoc: remove the sentence about the `X-DRS-Bundle` header if present in `bundle.ts` doc references — in `client.ts` only; `bundle.ts` (`serialiseBundle`) itself is untouched, it remains the transport encoding for the MCP `_meta` path.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pnpm --filter @okeyamy/drs-sdk test
```

Expected: PASS — full SDK suite (116+ tests), including the three new/changed ones.

- [ ] **Step 5: Stage + confirm commit with Okey**

```bash
git add drs-sdk/src/verify/client.ts drs-sdk/src/verify/client.test.ts
# proposed: fix(drs-sdk): drop dead X-DRS-Bundle header; type 409 as REPLAY_DETECTED; remove 403 pass-through
```

---

### Task 5: Deprecate the WASM loader in the SDK

**Files:**
- Modify: `drs-sdk/src/index.ts:51-52`
- Modify: `drs-sdk/src/wasm/loader.ts` (file header)
- Modify: `drs-sdk/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: `initWasm`/`getWasmModule`/`isWasmReady` no longer exported from the package root. `loader.ts` module remains for direct-path imports, marked deprecated. `loader.test.ts` keeps passing (it imports the module directly).

- [ ] **Step 1: Remove the public export**

In `drs-sdk/src/index.ts`, delete these lines:

```typescript
// WASM loader
export { initWasm, getWasmModule, isWasmReady } from "./wasm/loader.js";
```

- [ ] **Step 2: Add the deprecation header to loader.ts**

At the top of `drs-sdk/src/wasm/loader.ts`, above the existing doc comment, add:

```typescript
/**
 * @deprecated Experimental and unsupported. The normative DRS verifier is
 * drs-verify; use {@link VerifyClient} against its /verify endpoint. This
 * loader targets a `@drs/wasm` package that is not published. It is retained
 * only as an integration sketch and may be removed in a future release.
 */
```

- [ ] **Step 3: Update the SDK README**

In `drs-sdk/README.md`, find the section that mentions WASM/local verification (search for "wasm" case-insensitively). Replace its content with, or if absent add under the verification section:

```markdown
### Verification

SDK verification is an HTTP client (`VerifyClient`) against a running
[drs-verify](../drs-verify) service — full stop. There is no supported
in-process/WASM verification path; the `src/wasm` loader is an unpublished
experiment and is not exported from the package root.
```

- [ ] **Step 4: Verify nothing else consumed the export, then build + test**

```bash
grep -rn "from \"@okeyamy/drs-sdk\"" --include='*.ts' packages/ examples/ | grep -i wasm
pnpm --filter @okeyamy/drs-sdk build && pnpm --filter @okeyamy/drs-sdk test
```

Expected: grep finds nothing; build and full test suite PASS.

- [ ] **Step 5: Stage + confirm commit with Okey**

```bash
git add drs-sdk/src/index.ts drs-sdk/src/wasm/loader.ts drs-sdk/README.md
# proposed: chore(drs-sdk): deprecate WASM loader — HTTP VerifyClient is the only supported verification path
```

---

### Task 6: Config guard + nonce TTL default alignment (Go)

**Files:**
- Modify: `drs-verify/pkg/config/config.go:176` (default) and the validation block at ~line 208
- Modify: `drs-verify/pkg/config/config_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `config.Load()` — default `NonceStoreTTLSecs` becomes **900** (matches `.env.example` and docker-compose); returns an error when `NONCE_STORE_BACKEND=memory` (explicit or defaulted) and `TRUST_PROXY=true`.

- [ ] **Step 1: Write the failing tests**

Add to `drs-verify/pkg/config/config_test.go` (match the file's existing test style — `t.Setenv` for env isolation):

```go
func TestNonceTTLDefaultIs900(t *testing.T) {
	// No env set: default must match the documented quickstart default (900),
	// not the previous binary-only 3600. One default across binary, compose,
	// and .env.example — spec §4.4.
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NonceStoreTTLSecs != 900 {
		t.Fatalf("NonceStoreTTLSecs default = %d, want 900", cfg.NonceStoreTTLSecs)
	}
}

func TestMemoryNonceWithTrustProxyIsRejected(t *testing.T) {
	// TRUST_PROXY=true implies a real multi-hop deployment; in-memory replay
	// state that vanishes on restart is not acceptable there — spec §4.5.
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("NONCE_STORE_BACKEND", "memory")
	if _, err := Load(); err == nil {
		t.Fatal("Load must reject NONCE_STORE_BACKEND=memory with TRUST_PROXY=true")
	}
}

func TestRedisNonceWithTrustProxyIsAccepted(t *testing.T) {
	t.Setenv("TRUST_PROXY", "true")
	t.Setenv("NONCE_STORE_BACKEND", "redis")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	if _, err := Load(); err != nil {
		t.Fatalf("Load must accept redis backend with TRUST_PROXY=true: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/config/
```

Expected: FAIL — `TestNonceTTLDefaultIs900` (got 3600) and `TestMemoryNonceWithTrustProxyIsRejected` (no error returned).

- [ ] **Step 3: Implement**

In `drs-verify/pkg/config/config.go`:

(a) Change the default:

```go
	nonceTTL, err := getEnvInt64("NONCE_STORE_TTL_SECS", 900)
```

and update the struct field comment: `// Should match or exceed the maximum expected exp window. Default: 900 (15 min).`

(b) After the existing `NONCE_STORE_BACKEND` validation block (the `unknown backend` check), add:

```go
	// TRUST_PROXY=true means this verifier sits behind a reverse proxy — a
	// real deployment, likely multi-replica. In-memory replay state is lost
	// on restart and is not shared across replicas, silently reopening the
	// replay window. Fail fast at boot instead of degrading silently.
	if trustProxy && nonceBackend == "memory" {
		return Config{}, fmt.Errorf(
			"NONCE_STORE_BACKEND=memory is not allowed with TRUST_PROXY=true: " +
				"in-memory replay protection is lost on restart and not replica-shared; " +
				"set NONCE_STORE_BACKEND=redis and REDIS_URL")
	}
```

Note: `trustProxy` is read at ~line 191, before this block — no reordering needed.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd drs-verify && go test ./... && gofmt -l pkg/ cmd/
```

Expected: all packages PASS; `gofmt -l` prints nothing. If any other test asserted the old 3600 default, fix it to 900 (search: `grep -rn 3600 pkg/ cmd/`).

- [ ] **Step 5: Stage + confirm commit with Okey**

```bash
git add drs-verify/pkg/config/config.go drs-verify/pkg/config/config_test.go
# proposed: fix(drs-verify): align nonce TTL default to 900s; refuse memory nonce store behind trusted proxy
```

---

### Task 7: docker-compose + .env.example pass-through alignment

**Files:**
- Modify: `docker-compose.yml` (environment block)
- Modify: `.env.example`

**Interfaces:**
- Consumes: env var names from `config.go` (Task 6 unchanged names).
- Produces: every variable `config.go` reads is passed by compose and documented in `.env.example` (except `LISTEN_ADDR`, fixed to `:8080` in-container by design — documented as such).

- [ ] **Step 1: Add missing pass-throughs to docker-compose.yml**

In the `environment:` block of `docker-compose.yml`, after the `SERVER_IDENTITY` entry, add:

```yaml
      # TLS (optional): paths INSIDE the container. Mount the cert/key via
      # volumes if set; leave blank to serve plain HTTP behind a TLS proxy.
      TLS_CERT_FILE: "${TLS_CERT_FILE:-}"
      TLS_KEY_FILE: "${TLS_KEY_FILE:-}"

      # DID resolver cache
      DID_CACHE_SIZE: "${DID_CACHE_SIZE:-10000}"
      DID_CACHE_TTL_SECS: "${DID_CACHE_TTL_SECS:-3600}"

      # RFC 3161 trust root (PEM string). Empty uses system roots.
      TSA_ROOT_CERT_PEM: "${TSA_ROOT_CERT_PEM:-}"
```

- [ ] **Step 2: Document the same vars in .env.example**

Append to `.env.example` before the `-- Metrics --` section:

```bash
# -- TLS (optional) -------------------------------------------------------------

# Enable HTTPS by setting BOTH paths (inside the container when using Docker;
# mount the files via a volume). Setting only one fails fast at boot.
# Leave both blank to serve plain HTTP behind a TLS-terminating proxy.
TLS_CERT_FILE=
TLS_KEY_FILE=

# -- DID resolver cache ----------------------------------------------------------

# Max entries in the DID resolver LRU cache (~640 KB at 10000 entries).
DID_CACHE_SIZE=10000

# Seconds a resolved DID key stays cached.
DID_CACHE_TTL_SECS=3600

# -- RFC 3161 trust root (optional) ----------------------------------------------

# PEM-encoded root CA certificate(s) trusted for timestamp verification.
# Empty uses system roots. Only relevant when STORE_DIR and TSA_URL are set.
TSA_ROOT_CERT_PEM=
```

Also update the existing `NONCE_STORE_TTL_SECS=900` comment to note it now matches the binary default (Task 6), and add one line near the top: `# LISTEN_ADDR is fixed to :8080 inside the container; change the host port via DRS_VERIFY_PORT.`

- [ ] **Step 3: Validate compose config**

```bash
docker compose config -q && echo compose-ok
```

Expected: `compose-ok` (no YAML/interpolation errors).

- [ ] **Step 4: Cross-check nothing is missing**

```bash
grep -oE 'os\.Getenv\("[A-Z_]+"\)|getEnv[A-Za-z0-9]*\("[A-Z_]+"' drs-verify/pkg/config/config.go | grep -oE '"[A-Z_]+"' | sort -u
```

Expected: every printed var appears in both `docker-compose.yml` and `.env.example`, except `LISTEN_ADDR` (documented exception).

- [ ] **Step 5: Stage + confirm commit with Okey**

```bash
git add docker-compose.yml .env.example
# proposed: fix(config): compose passes all binary env vars; .env.example documents them
```

---

### Task 8: Honesty documentation + code comments

**Files:**
- Modify: `README.md` (root)
- Append: `docs/drs-source-of-truth.md`
- Append: `docs/production-readiness-checklist.md`
- Modify: `drs-verify/pkg/verify/chain.go` (~line 599, comment only)

**Interfaces:**
- Consumes: nothing.
- Produces: documentation only — no behaviour change. `go test ./...` must stay green (comment-only Go change).

- [ ] **Step 1: Add the honesty section to the root README**

Insert after the feature/overview section of `README.md` (before installation/quickstart):

```markdown
## What DRS proves — and what it does not

DRS receipts are cryptographic evidence of **authorisation and claims**, not
of runtime behaviour. Read this before designing your policy model:

| Policy field | What the verifier proves |
|---|---|
| `max_cost_usd` | The invoker **claimed** `estimated_cost_usd` within the limit — it signed that claim. The verifier cannot know the actual cost. **The tool owner must validate real cost.** |
| `pii_access`, `write_access` | The invoker **claimed** compliance. Enforcement of actual data access is the tool owner's responsibility. |
| `allowed_tools`, `allowed_resources`, `allowed_data_classes` | The named tool/resource/class in the signed args is within the delegated set. The binding check (`body` ↔ `invocation.args`) additionally proves the executed request matches the signed args. |
| `max_calls` | **Nothing — informational only.** The verifier is stateless; call counting belongs in your session layer, using the leaf policy returned in `VerificationContext`. |

Two further operational notes:

- `/verify` is unauthenticated by design in the current release. Anyone
  holding a captured bundle can consume its replay nonce (JTI) at the
  endpoint before the legitimate tool server does — a denial-of-service on
  that one invocation, not an authorisation bypass. Rate limiting bounds it;
  API-key authentication closes it in a future release.
- Human-consent records (`drs_consent`) currently prove consent **existed**
  (method, session, timestamp). The `policy_hash` field is checked for
  presence, not yet bound to the policy content — the canonical preimage is
  defined in DRS 4.1.
```

- [ ] **Step 2: Append the /verify status contract to docs/drs-source-of-truth.md**

Append at the end of the file:

```markdown
## /verify HTTP status contract (normative)

| Status | Body | Meaning |
|---|---|---|
| 200 | `VerificationResult` JSON | Chain processed. `valid` is the verdict — a `valid: false` chain is still HTTP 200. |
| 400 | `{"error": ...}` | Request body is not a decodable ChainBundle, or the invocation JTI cannot be decoded. |
| 409 | `{"error":"REPLAY_DETECTED","detail":...,"suggestion":...}` | The invocation JTI was already consumed. Clients surface this as a typed replay error, not a verification result. |
| 413 | text | Body exceeded `MAX_BODY_BYTES`. |
| 429 | text | Rate limit exceeded (per-IP or global). |
| 503 | `{"error":...}` | Replay protection unavailable (nonce store down / exhausted) — fail closed, retry later. |

HTTP 403 is **never** returned by `/verify`. It belongs exclusively to the
in-process Go middleware (`pkg/middleware`) enforcing mode on tool servers.

## Claim-based policy fields (normative)

`max_cost_usd`, `pii_access`, and `write_access` are **claim-based**: the
verifier evaluates the invoker's own signed claims in `invocation.args`
against the delegated policy. Truthfulness of those claims is enforced by
the tool owner, not by DRS. `max_calls` is **informational**: the stateless
verifier performs no call counting; integrators enforce it in their session
layer from `VerificationContext.leaf_policy`.
```

- [ ] **Step 3: Append the Redis mandate to docs/production-readiness-checklist.md**

Append:

```markdown
- [ ] **Replay protection backend:** `NONCE_STORE_BACKEND=redis` (with
      `REDIS_URL`) for ANY multi-replica or restart-durable deployment.
      The in-memory backend loses all replay state on restart and is not
      shared across replicas. The binary refuses `memory` + `TRUST_PROXY=true`
      at boot.
```

- [ ] **Step 4: Add the buffered-channel comment in chain.go**

In `drs-verify/pkg/verify/chain.go`, inside `resolveIssuersParallel`, directly above `results := make(chan resolveResult, len(unique))`, add:

```go
	// INVARIANT: results must be buffered to len(unique). The workers send
	// exactly one result each and wg.Wait() runs BEFORE the drain loop below —
	// with an unbuffered (or under-sized) channel every send would block and
	// wg.Wait() would deadlock. If you refactor this, drain concurrently or
	// keep the buffer sized to the number of sends.
```

- [ ] **Step 5: Verify Go still compiles and tests pass**

```bash
cd drs-verify && go test ./... && gofmt -l pkg/
```

Expected: PASS, no fmt output.

- [ ] **Step 6: Stage + confirm commit with Okey**

```bash
git add README.md docs/drs-source-of-truth.md docs/production-readiness-checklist.md drs-verify/pkg/verify/chain.go
# proposed: docs: claim-based policy honesty, /verify status contract, redis mandate; comment channel invariant
```

---

## Completion checklist

- [ ] `cd drs-core && cargo test` — green
- [ ] `cd drs-core && wasm-pack test --node -- --features wasm` — green (2 tests)
- [ ] `pnpm --filter @okeyamy/drs-sdk build && pnpm --filter @okeyamy/drs-sdk test` — green
- [ ] `cd drs-verify && go test ./...` — green
- [ ] `docker compose config -q` — clean
- [ ] No wire-format change anywhere (`drs_v` still `"4.0"`, no receipt field edits)
- [ ] All commits confirmed by Okey before executing
