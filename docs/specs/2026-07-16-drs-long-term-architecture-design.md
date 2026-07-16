# DRS Long-Term Architecture — Design Decision Record

**Date:** 2026-07-16
**Status:** Approved by Okey (brainstorm session)
**Supersedes:** nothing — narrows scope within the v3 architecture (`docs/Drs_language&algorithms.md`)

---

## 1. Product thesis

DRS's product is **trust**. The deliverable customers pay for is a verifier a
stranger can rely on, plus an SDK that makes correct issuance take five
minutes. Every decision below follows from that.

**Trajectory:** shared verification service per organisation → hosted SaaS
(design on paper now, implementation deferred). Embedded in-process
verification (WASM/edge) is **dropped as a goal** — revivable later because
drs-core remains published.

**Issuer scope:** mixed — an org's own agents plus receipts rooted at external
partners. Multi-issuer support is therefore mandatory, not optional.

## 2. The single-verifier decision

**drs-verify (Go) is the one and only normative verifier.** Everything else —
SDK, MCP middleware, A2A interceptor, future integrations — plugs into it over
HTTP `/verify`. There is exactly one implementation of the verification
algorithm that counts.

Consequences:

- The verifier-drift problem (the class of failure that killed v1 and v2, and
  which the 2026-07-16 review found reproduced internally: Rust/WASM missing
  the D4c `tool_server` binding and invocation `iat` freshness checks that Go
  enforces at `drs-verify/pkg/verify/chain.go:342-357` and `:409-421`) is
  eliminated **by construction**, not by conformance machinery.
- No Portable/Full profile split in the spec. One profile: what drs-verify does.
- No `@drs/wasm` npm package, no wasm-pack CI, no D4c/iat port to Rust, no
  wazero embedding.
- Trade-off accepted: every verification is an HTTP round trip (~1–5 ms on an
  org network). Edge/serverless in-process verification is not offered.

### drs-core is parked, not deleted

`drs-core` stays in the repo and on crates.io as the **non-normative reference
implementation** of the algorithms (JCS, chain hash, Blocks A–E). Its README
and the spec state this label explicitly. It receives **no new features**.

**One bug is fixed before freezing** (ship-blocker from the review):

> `drs-core/src/chain/verify.rs:586` — `unix_now()` calls
> `SystemTime::now()`, which **panics** on `wasm32-unknown-unknown` (the
> `wasm-pack --target web` build advertised in `wasm/bindings.rs`). The
> `CLOCK_ERROR` fail-closed path guards `duration_since` and is unreachable —
> the panic fires one call earlier. With `panic = "abort"` in the release
> profile the module traps → `RuntimeError` in JS. `wasm_verify_chain`
> violates its own "never panics" contract on every bundle reaching Block E,
> on exactly the platform the WASM feature exists for. Native tests cannot
> catch it.

Fix: `#[cfg(target_arch = "wasm32")]` branch in `unix_now()` using
`js_sys::Date::now()` (js-sys is already a wasm-feature dependency), plus a
wasm-pack test that verifies one full chain end-to-end. Cut `drs-core 0.1.2`
with the fix and the non-normative label, then freeze. A published crypto
crate with an advertised WASM feature that traps at runtime is a reputation
hole for a trust product; fixing costs ~20 lines.

The remaining Rust/WASM gaps vs Go (D4c, iat, replay, revocation, did:web —
see review table) are **documented** in the drs-core README as inherent to the
non-normative reference, not fixed.

## 3. DRS 4.1 spec changes

**Version tracks, disambiguated.** Two independent version lines exist and
must not be conflated:

- **Release versions** — git tags / crates.io / npm: `v0.1.0` and `v0.1.1`
  shipped so far. Next drs-core patch is `0.1.2`; the release that ships the
  4.1 wire changes below would be `v0.2.0`.
- **Wire-format version** — the `drs_v` field inside every receipt, currently
  `"4.0"` (enforced at `chain.go:159` / `verify.rs:18`). "DRS 4.1" in this
  document bumps this field only, not the release tag.

### 3.1 Multi-issuer revocation (`drs_status`)

The current design is single-tenant: one global `STATUS_LIST_BASE_URL` and a
flat status-list index namespace. Issuer A's index 5 and issuer B's index 5
collide in the local revocation store — revoking one affects the other. This
is the biggest structural misfit found in the review and is incompatible with
the mixed-issuer product scenario.

New receipt field, replacing bare `drs_status_list_index`:

```json
"drs_status": {
  "list_url": "https://issuer-a.com/status/1",
  "index": 42
}
```

- Verifier fetches and caches **per `list_url`**: LRU map
  `list_url → {bitstring, fetchedAt}`, per-list TTL, per-list singleflight
  (reuse the resolver's inflight pattern from `pkg/resolver/did.go`).
- `list_url` is attacker-controllable content ⇒ it inherits the full did:web
  SSRF defence set: HTTPS-only, `safeDialContext` private-IP rejection at
  connect time, redirects forbidden, response size cap (128 KiB per list —
  tighter than the current 1 MiB, sized for realistic bitstring lists), LRU
  cap on number of cached lists.
- Fail-closed **per list**: an unreachable list fails that receipt with
  `REVOCATION_CHECK_FAILED`; other issuers' receipts are unaffected.
- `/readyz` no longer gates on a global warm-up; lists warm on first use.
- Migration: during a deprecation window the verifier still accepts 4.0
  receipts carrying `drs_status_list_index`, checked against
  `STATUS_LIST_BASE_URL` when configured. New receipts must use `drs_status`.
- Version acceptance: the verifier currently hard-rejects `drs_v != "4.0"`
  (`chain.go:159`). With 4.1 it accepts `drs_v ∈ {"4.0", "4.1"}`; per-receipt
  behaviour (which status field is honoured, whether policy_hash equality is
  enforced per §3.4) keys off each receipt's own `drs_v`. Mixed-version
  chains are legal during the window.

### 3.2 Local revocation keyed by JTI

`POST /admin/revoke` takes `{"jti": "dr:..."}` instead of a bare index.
File-backed store mechanics unchanged (append + fsync); only the key changes.
This removes the cross-issuer index collision outright.

### 3.3 Honesty labels on policy fields

The verifier proves "the agent **claimed** cost ≤ limit", not "cost **was** ≤
limit". `estimated_cost_usd`, `pii_access`, `write_access` are claims the
invoker itself signs; the binding check proves args match the request body,
not that the claims are true. `max_calls` is not enforced at all (stateless
verifier; comment at `pkg/policy/evaluate.go:19-23`).

Spec + README changes, loud and unmissable:

- Spec marks these fields **claim-based** and names the tool owner as the
  party responsible for validating actual cost/PII/write behaviour.
- `max_calls` marked **informational**; enforcement belongs in the
  integrator's session layer using the leaf policy from `VerificationContext`.
- `VerificationContext` gains `claim_based_fields: [...]` so integrators see
  the distinction at runtime, not only in documentation.

Rationale: a trust product that lets customers discover this after an incident
is finished. Lose the naive customer at the README, not at the postmortem.

### 3.4 `consent.policy_hash` preimage (spec debt, tracked)

Today the consent record's `policy_hash` is checked for presence but not bound
to the policy (`verify.rs:186`, `chain.go:764`) because the spec does not
define the canonical preimage. The flagship "human consent" feature currently
proves consent *existed*, not consent *to this policy*. DRS 4.1 must define
the preimage (JCS-canonical bytes of the `policy` object, SHA-256, `sha256:`
prefix) and the verifier must enforce equality once issuers emit it.
Enforcement is gated on a spec version field to avoid rejecting legitimate
4.0 chains.

## 4. drs-verify work (all feature energy here)

Priority order:

1. **Multi-issuer status cache** (§3.1) — the product feature. Without it the
   shared-service pitch is false advertising.
2. **JTI-keyed local revoke** (§3.2) — correctness bug in product terms.
3. **Storage retention caps.** Keep storage + RFC 3161 TSA (decision:
   differentiating audit feature), but harden: when `STORE_DIR` is set,
   `STORE_MAX_BYTES` and `STORE_RETENTION_DAYS` become **required** — refuse
   to boot without them. Oldest-first eviction. Today
   `NewFilesystemStore(dir, 0)` grows without bound on every valid verify
   (`chain.go:477`) — a guaranteed operational incident under sustained
   traffic.
4. **Config truth.** One source: `config.go`. Fix drift found in review:
   compose default `NONCE_STORE_TTL_SECS:-900` vs binary default `3600`
   (`config.go:176`); `.env.example` omits vars the binary reads
   (`LISTEN_ADDR`, `TLS_CERT_FILE`/`TLS_KEY_FILE`, `DID_CACHE_SIZE`,
   `DID_CACHE_TTL_SECS`, `TSA_ROOT_CERT_PEM`); docker-compose silently drops
   TLS and DID-cache vars a user sets in `.env`. Align all three: compose
   passes everything, `.env.example` documents everything, defaults identical.
5. **Replay protection stays in the verifier, Redis-backed** (decision).
   Redis is the right primitive (`SET NX EX` = atomic claim-if-new + TTL +
   replica-shared). Documented caveats: Redis availability couples to verifier
   availability (fail-closed 503 — correct, inherent); nonce-burn DoS on the
   unauthenticated `/verify` (anyone holding a captured bundle can consume its
   JTI first) is accepted for now, mitigated by rate limiting, and closed by
   API-key auth in the SaaS phase. Additional guard: refuse
   `NONCE_STORE_BACKEND=memory` when `TRUST_PROXY=true` — a proxy implies a
   real deployment, and in-memory replay state that vanishes on restart is not
   acceptable there.
6. **`/verify` response contract.** Replay currently returns 409 JSON that is
   not a `VerificationResult` (`pkg/middleware/decode.go:107`), while the SDK
   special-cases 403 — a status `/verify` never returns (403 belongs to the
   in-process middleware only). Decision: keep 409 for replay but document the
   status contract of `/verify` normatively (200 = VerificationResult,
   400/409/413/429/503 = error JSON `{error, detail, suggestion}`), and fix
   the SDK to match (§5).
7. **Code-watch note** (no change now): `resolveIssuersParallel`
   (`chain.go:614`) drains its results channel after `wg.Wait()`, safe only
   because the channel is buffered to `len(unique)`. Fragile idiom — one
   refactor from deadlock. Comment added at the site.

### SaaS phase — paper only

Recorded here as design, **zero implementation** until shared-service mode has
real mileage:

- API-key auth on `/verify`; key → tenant config (server_identity, rate
  limits, storage quota, allowed issuers). Closes the nonce-burn DoS.
- Single-tenant mode remains the zero-config default; a sidecar user never
  sees tenancy.
- Redis mandatory in shared/SaaS mode.
- Billing/metering out of scope for this document.

## 5. drs-sdk work (the adoption funnel)

The verifier wins deals; the SDK wins users. Issuing a receipt correctly must
not require reading three files.

1. **Delete the dead `X-DRS-Bundle` header** in `verify/client.ts:70`. The
   `/verify` handler never reads it; it duplicates the entire bundle and can
   push total headers past Go's default 1 MB `MaxHeaderBytes` → 431 before the
   body cap applies.
2. **Typed replay handling.** Client maps 409 → `DrsError("REPLAY_DETECTED")`.
   Remove the dead 403 special-case (`client.ts:85`).
3. **WASM loader** (`src/wasm/loader.ts`) removed from public exports or
   marked experimental-unsupported. README states plainly: SDK verification =
   HTTP client against drs-verify, full stop, today.
4. **High-level DX entry point** — the highest-ROI item: a `Drs` facade that
   does keygen → root delegation → invocation bundle → verify-against-URL in
   ~5 lines, mirrored in the README and the expense-agent example.
5. **Issuance emits `drs_status`** when the caller supplies revocation info
   (4.1 schema).
6. Conformance vectors (`fixtures/conformance`) are retained with a narrowed
   job: issuer↔verifier byte-compatibility (JCS bytes, chain hash, JWT
   signing input) between the TS SDK and the Go verifier. They are no longer
   verifier↔verifier parity machinery.

## 6. Boundaries reaffirmed (what we deliberately do NOT do)

- No wazero / FFI embedding of Rust in the Go server.
- No verifier-parity conformance suite (single verifier makes it moot).
- No new drs-core features; crate frozen after 0.1.2.
- No TSA expansion; anchoring stays as-is (revisit issuance-time anchoring
  only if an audit customer asks).
- MCP/A2A middleware stay thin, dumb plugs into `/verify` — fail-closed on
  unreachable verifier, hard runtime dependency documented.
- No SaaS code in this cycle.
- Keep as-is (validated by review): JWT + JCS + Ed25519 + did:key/did:web;
  bitstring status-list format; in-process LRU DID cache; in-process
  token-bucket rate limiting; Go server; TS issuance.

## 7. Housekeeping (from the 2026-07-16 review)

- `examples/drs-expense-agent/.env` holds a live Gemini API key. Gitignored,
  never committed — local-only. Rotate if the machine/folder was ever shared
  or screen-recorded.
- Production checklist: mandate `NONCE_STORE_BACKEND=redis` for any
  multi-replica or restart-durable deployment (in-memory warning already
  logged at boot).

## 8. Phases

| Phase | Contents | Wire changes |
|---|---|---|
| **P1 — Stabilize (days)** | drs-core WASM clock fix + non-normative label + freeze (0.1.2); SDK cleanups (header, 409, loader label); config truth (compose/.env/config.go alignment); honesty labels in README/spec (§3.3) | none |
| **P2 — DRS 4.1 (the release)** | `drs_status` multi-issuer revocation; JTI-keyed `/admin/revoke`; storage retention caps (required when STORE_DIR set); `claim_based_fields` in VerificationContext; SDK `drs_status` issuance + DX facade; `consent.policy_hash` preimage defined in spec | `drs_status` field; 4.0 accepted in deprecation window |
| **P3 — Prove & paper** | Dogfood a shared instance with multi-issuer traffic (expense-agent + a second issuer); write SaaS spec section into docs (auth, tenancy, Redis-mandatory); no SaaS code | none |

## 9. Testing requirements

- Every new check gets pass + fail vectors (per project testing rules).
- Multi-issuer cache: concurrent fetch/singleflight test, SSRF rejection test
  (private IP list URL), per-list fail-closed test, LRU eviction test.
- JTI revoke: revoke issuer-A receipt, verify issuer-B receipt with same old
  index still passes.
- Storage caps: eviction under `STORE_MAX_BYTES`, boot refusal without caps.
- drs-core: wasm-pack test verifying a full chain (regression for the clock
  panic).
- SDK: 409 → `REPLAY_DETECTED` test; request contains no `X-DRS-Bundle`
  header.
- Integration suite (`integration-tests/`) gains a two-issuer revocation
  scenario.
