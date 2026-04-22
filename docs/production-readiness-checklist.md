# DRS Production Readiness Checklist

**Status:** Current implementation checklist  
**Applies to:** The JWT/JCS/Ed25519 DRS system implemented in this repository  
**Companion docs:** `docs/drs-source-of-truth.md`, `README.md`, `docs-site/src/how-to/operators/*`

---

## 1. Purpose

This document is the practical go-live checklist for the DRS system as it exists in this repository today.

It is intentionally different from the historical architecture documents:

- `docs/DRS_architecture_v1.md` and `docs/Drs_architecture_v2.md` are historical records.
- `docs/drs-source-of-truth.md` defines the current implementation contract.
- **This file answers a narrower question:** what must be true before DRS should be called production-ready for real deployments.

This checklist is based on the implemented system, not on roadmap claims.

---

## 2. What This Checklist Applies To

This checklist applies to the current three-layer DRS system:

- **`drs-core`** — Rust crypto, canonicalization, chain hashing, and core verification rules
- **`drs-verify`** — Go verification service, middleware, revocation, storage, and operator-facing HTTP endpoints
- **`drs-sdk`** — TypeScript issuance SDK and verification client

It also applies to the current MCP/A2A transport binding described in `docs/drs-source-of-truth.md`:

- HTTP-terminated shape using `X-DRS-Bundle`
- JSON-RPC metadata shape using `_meta["X-DRS-Bundle"]`

It does **not** claim that DRS is a protocol-native part of MCP or A2A. In the current repository, DRS is an additional receipt and verification layer attached to those systems.

---

## 3. Current Implemented DRS Profile

Before evaluating readiness, confirm everyone involved is using the same mental model.

The implemented DRS profile in this repository is:

- JWT receipts
- RFC 8785 JCS canonicalization
- Ed25519 signatures
- `did:key` in core flows, with `did:web` support in the Go verifier
- SHA-256 chain linkage through `prev_dr_hash` and `dr_chain`

Transport binding and conformance boundaries are described in `docs/drs-source-of-truth.md`.

---

## 4. Short Verdict

At the time of writing, DRS should be described as:

- **production-worthy cryptographic foundation**
- **promising verification service**
- **not yet production-complete as a general control plane for arbitrary MCP/A2A systems**

The main reason is not weak cryptography. The main remaining risks are systems-level:

- binding signed intent to actual executed requests
- replay protection across restarts and replicas
- durable revocation behavior
- operational clarity about what `drs-verify` actually is: verifier service, middleware component, or transparent proxy

---

## 5. Readiness Levels

Use these labels consistently.

### 5.1 Safe to say today

The following are defensible claims today:

- DRS can verify signed delegation chains and invocation receipts.
- DRS can enforce receipt structure, version, signature validity, attenuation, temporal validity, and revocation checks.
- DRS supports fail-closed middleware by default for HTTP-terminated MCP and A2A routes.
- DRS can be adopted without cloning the repository through the published SDK package and verifier container image.

### 5.2 Safe only for pilot / controlled rollout

The following are acceptable only if your deployment is constrained and your operators understand the caveats:

- single-instance deployment with in-memory emergency revocation
- limited-scale replay protection with process-local nonce state
- advisory or partially manual timestamping workflows
- custom MCP/A2A integration where your own handlers perform final request binding

### 5.3 Not safe to claim yet

Do **not** claim these until the checklist blockers are resolved:

- “drop-in production proxy for MCP or A2A”
- “globally durable replay protection”
- “durable local revocation across restart and replicas”
- “hard real-world AI spend cap” via `max_cost_usd`
- “full evidence of exactly what was executed” unless request binding is enforced

---

## 6. Must-Fix Blockers Before General Production

These are the blockers that should be treated as **go/no-go** for general production deployment.

### 6.1 Bind the signed invocation to the actual executed request

- [ ] The server must reject any request whose actual MCP/A2A payload does not match the signed invocation arguments.
- [ ] Or the server must execute directly from the verified signed arguments rather than from an unbound downstream body.

**Why this is blocking**

Current middleware verifies the bundle and attaches `VerificationContext` to the request context, but it does not itself compare the signed invocation arguments with the actual application request body.

Current behavior to note:

- `drs-verify/pkg/middleware/mcp.go` verifies `X-DRS-Bundle` and attaches context.
- `drs-verify/pkg/middleware/a2a.go` does the same for A2A routes.

That means DRS can currently prove that a signed invocation was valid, but your final application integration still decides whether the verified intent and the executed request are actually the same thing.

**Production requirement**

At least one of these must be true:

1. the downstream handler reconstructs execution exclusively from verified signed arguments, or
2. the downstream handler rejects any mismatch between the signed arguments and the received request body.

Without this, DRS remains a strong authorization and provenance primitive, but not a complete execution-integrity guarantee.

### 6.2 Replace process-local replay protection with deployment-safe replay protection

- [ ] Replay protection must remain correct across process restart.
- [ ] Replay protection must remain correct across multiple verifier instances.
- [ ] Retry behavior must be documented and tested.

**Why this is blocking**

`drs-verify/pkg/nonce/store.go` is a bounded, TTL-based **in-memory** nonce store. `drs-verify/pkg/middleware/decode.go` explicitly documents that the nonce is consumed **before** `verify.Chain()` runs.

That is a deliberate trade-off for CPU protection, but it also means:

- a restart clears replay state
- horizontally scaled replicas do not share replay state
- a failed verification attempt still consumes the nonce
- clients must regenerate invocations after a failed verification

These semantics may be acceptable in a pilot, but not as a general production claim unless your deployment shape and retry model are explicitly designed around them.

### 6.3 Make revocation durable enough for your threat model

- [ ] Durable revocation behavior must exist for restart and replica scenarios.
- [ ] Operators must know which revocation path is immediate and which is durable.
- [ ] Emergency runbooks must explicitly cover status-list updates and cache windows.

**Why this is blocking**

`drs-verify/pkg/revocation/local.go` states clearly that the local revocation store is **in-memory only** and does not survive restart. `docs-site/src/how-to/operators/revocation.md` says the same thing.

This gives you an immediate emergency revoke path, but it is not durable by itself. Durable revocation today depends on the remote W3C Bitstring Status List served at `STATUS_LIST_BASE_URL`.

### 6.4 Decide and ship the real product boundary of `drs-verify`

- [ ] Public docs must describe `drs-verify` exactly as it behaves.
- [ ] If it is a verification service, say that.
- [ ] If it is meant to be a proxy, implement full forwarding behavior before claiming it is one.

**Why this is blocking**

`drs-verify/cmd/server/main.go` exposes:

- `/verify`
- `/admin/revoke`
- `/healthz`
- `/readyz`
- `/mcp/*`
- `/a2a/*`

But the `/mcp/*` and `/a2a/*` handlers currently return `200` after middleware verification. They are not, by themselves, a transparent upstream proxy.

So the go-live question is not just technical. It is also product-definition clarity.

---

## 7. Pilot-Only Limitations

These items are not necessarily fatal for a controlled pilot, but they should be disclosed and consciously accepted.

### 7.1 Local emergency revocation is immediate but not durable

- [ ] Operators understand that `POST /admin/revoke` affects only the current process.
- [ ] Operators understand that restart clears local emergency revocations.

Use the local store for immediate response. Use the remote status list for durable propagation.

### 7.2 Tier 3 / Tier 4 storage posture is partial, not absolute

- [ ] No one is describing Tier 3 or Tier 4 as immutable WORM storage unless you add real WORM guarantees outside this repo.
- [ ] Timestamping is described as evidence enhancement, not absolute execution gating.

`docs-site/src/how-to/operators/storage-tiers.md` is explicit:

- Tier 2 is not implemented
- Tier 3 is partial
- Tier 4 is partial
- Tier 5 is not implemented

Tier 3 currently means filesystem storage plus best-effort RFC 3161 timestamping. The receipt is still stored if the TSA is unavailable, and WORM semantics are not enforced by the current filesystem backend.

### 7.3 `max_calls` is not verifier-enforced runtime control

- [ ] Docs and UI do not present `max_calls` as a live runtime call limiter.
- [ ] Integrators implement their own session-aware counter if they want real enforcement.

This is stated in both:

- `drs-sdk/src/sdk/types.ts`
- `drs-verify/pkg/types/types.go`
- `drs-verify/pkg/policy/evaluate.go`

`max_calls` is carried in policy and checked for attenuation, but not enforced at runtime by the stateless verifier.

### 7.4 The no-clone install path exists, but advanced use still requires integration work

- [ ] Product messaging distinguishes “installable without cloning” from “fully turnkey integration.”

Today users can start without cloning because the repo exposes:

- `@okeyamy/drs-sdk`
- `ghcr.io/okeyamy/drs-verify:latest`
- published MCP helper packages

But advanced integration still requires glue code, deployment decisions, and in many cases application-specific request binding.

---

## 8. Operational Readiness Checklist

These are the operator checks that should be complete before launch.

### 8.1 Base configuration

- [ ] `LISTEN_ADDR` intentionally set
- [ ] `SERVER_IDENTITY` intentionally set if invocation destination binding is required
- [ ] `LOG_LEVEL` intentionally set
- [ ] `MAX_BODY_BYTES` reviewed for your deployment shape
- [ ] `METRICS_ADDR` intentionally set or intentionally left empty (empty = metrics disabled; set to `127.0.0.1:9090` for production, `:9090` for dev)

**Why it matters**

`drs-verify/pkg/config/config.go` drives all runtime configuration from environment variables. `SERVER_IDENTITY` is especially important because `drs-verify/pkg/verify/chain.go` uses it to bind `invocation.tool_server` to the intended target server when configured.

### 8.2 Revocation operations

- [ ] `STATUS_LIST_BASE_URL` configured if durable revocation is required
- [ ] `STATUS_CACHE_TTL_SECS` intentionally chosen
- [ ] `DRS_ADMIN_TOKEN` configured if immediate local emergency revoke is required
- [ ] revocation cache window documented in the incident runbook

**Why it matters**

Remote status-list revocation is durable but cache-window based. Local revocation is immediate but in-memory only.

### 8.3 Replay operations

- [ ] `NONCE_STORE_MAX_ENTRIES` sized for expected concurrency and retry patterns
- [ ] `NONCE_STORE_TTL_SECS` sized to match your expected invocation lifetime
- [ ] retry behavior documented for clients

**Why it matters**

Replay handling is a security control and an operational control. An undersized store can lead to `NONCE_STORE_EXHAUSTED`; an ill-matched TTL can lead to false assumptions about retry safety.

### 8.4 Storage and timestamping

- [ ] `STORE_DIR` intentionally configured or intentionally omitted
- [ ] `TSA_URL` configured only if timestamping is actually required
- [ ] `TSA_ROOT_CERT_PEM` configured when custom trust anchoring is required
- [ ] storage tier choice documented for auditors and operators

### 8.5 Readiness and health

- [ ] `/healthz` checked in deployment automation
- [ ] `/readyz` checked in deployment automation
- [ ] operators understand that readiness depends on status-list warm-up only when status-list configuration is enabled

---

## 9. Security and Key Management Checklist

### 9.1 Receipt and invocation verification

- [ ] The deployment verifies every delegation receipt signature.
- [ ] The deployment verifies the invocation signature.
- [ ] The deployment rejects wrong DRS version, wrong type, malformed JWTs, and broken hash chains.

This is already part of the implemented verification path in `drs-verify/pkg/verify/chain.go`.

### 9.2 DID handling

- [ ] `did:key` and `did:web` expectations are documented for operators
- [ ] `did:web` usage is reviewed as a network and trust-boundary expansion
- [ ] SSRF, timeout, and caching expectations are part of the deployment review

`did:key` is simpler operationally. `did:web` adds DNS/TLS/network dependency and should not be treated as equivalent from an operational risk perspective.

### 9.3 Server identity binding

- [ ] `SERVER_IDENTITY` is set wherever invocation destination binding matters
- [ ] application owners know that leaving it unset disables this binding check

### 9.4 Optional vs required enforcement

- [ ] Required routes use `MCPMiddleware` / `A2AMiddleware`
- [ ] Optional routes use `OptionalMCPMiddleware` / `OptionalA2AMiddleware` only by deliberate design
- [ ] optional mode is never mistaken for enforced mode

---

## 10. MCP and A2A Integration Checklist

### 10.1 HTTP-terminated shape

- [ ] `X-DRS-Bundle` transport is used consistently where HTTP transport exists
- [ ] bundle encoding uses base64url JSON as defined in `docs/drs-source-of-truth.md`
- [ ] missing bundles return 401 where fail-closed enforcement is required

### 10.2 JSON-RPC metadata shape

- [ ] `_meta["X-DRS-Bundle"]` is used consistently for pure JSON-RPC transport
- [ ] clients and servers agree on the same encoding and extraction rules
- [ ] missing-bundle behavior is defined at the application layer

### 10.3 Method scope

- [ ] DRS verification is applied only to tool-call methods
- [ ] non-tool methods are not incorrectly blocked by DRS middleware

The source-of-truth doc is explicit that DRS verification applies to tool-call methods like `tools/call`, not to `initialize`, `resources/list`, or prompt retrieval routes.

### 10.4 Header and transport realities

- [ ] proxy/header-size limits are tested with realistic bundle sizes
- [ ] retry and forwarding behavior are tested across real infrastructure
- [ ] gateway behavior for 400, 401, 403, and 409 responses is tested end-to-end

---

## 11. Policy Enforcement Checklist

This section exists to stop policy claims from drifting beyond what the verifier really does.

### 11.1 Enforced today

- [ ] `max_cost_usd` checked against `args["estimated_cost_usd"]`
- [ ] `pii_access` checked when the invocation includes `pii_access`
- [ ] `write_access` checked when the invocation includes `write_access`
- [ ] `allowed_tools` checked against `args["tool"]`
- [ ] `allowed_resources` checked against `args["resource_uri"]`
- [ ] `allowed_data_classes` checked against `args["data_class"]`
- [ ] child policy attenuation enforced against parent policy

These semantics are implemented in `drs-verify/pkg/policy/evaluate.go`.

### 11.2 Not enforced today by the stateless verifier

- [ ] `max_calls` must not be described as verifier-enforced runtime control
- [ ] cumulative or account-level budget tracking must not be described as part of verifier policy enforcement
- [ ] real-world billing truth must not be described as part of verifier policy enforcement

### 11.3 Attenuation is not the same as runtime accounting

- [ ] Docs and UI distinguish “child cannot loosen the parent’s policy” from “the system has durable runtime accounting”

This distinction matters because attenuation is implemented today; durable runtime session accounting is not.

---

## 12. `max_cost_usd` Semantics

This field deserves special handling because it is easy to overstate.

### 12.1 What it means today

`max_cost_usd` is an optional policy field. If present, the verifier checks that:

- the invocation provides `estimated_cost_usd`
- that value is finite and non-negative
- that value is not greater than `max_cost_usd`

It is also part of attenuation rules:

- a child may not omit `max_cost_usd` if the parent set it
- a child may not increase it above the parent’s limit

### 12.2 What it does **not** mean today

`max_cost_usd` is **not** a hard guarantee of actual real-world AI spend.

It is not tied directly to:

- provider billing truth
- post-hoc invoice reconciliation
- retries and downstream fan-out
- streaming expansion
- cumulative session spend across multiple invocations

### 12.3 Safe wording

Use wording like this:

> `max_cost_usd` is a signed per-invocation budget cap evaluated against the invocation’s declared estimated cost.

Do **not** use wording like this:

> DRS guarantees the system will never spend more than this amount.

### 12.4 Production requirement

- [ ] Any product or UI that exposes `max_cost_usd` must describe it as **admission-time estimate control**, not accounting truth.
- [ ] If hard spend control matters, the tool or billing layer must enforce it separately.

---

## 13. Storage, Revocation, and Timestamping Caveats

### 13.1 Storage caveats

- [ ] Tier 0 is never described as durable
- [ ] Tier 1 is understood as local filesystem durability only
- [ ] Tier 2 is not claimed because it is not implemented
- [ ] Tier 5 is not claimed because it is not implemented

### 13.2 Revocation caveats

- [ ] Local revoke is documented as immediate but non-persistent
- [ ] Remote revoke is documented as durable but cache-window based

### 13.3 Timestamping caveats

- [ ] RFC 3161 timestamping is described as evidence-strengthening behavior
- [ ] lack of timestamp availability is not described as automatic receipt invalidity unless you add that policy externally

`drs-verify/pkg/verify/chain.go` documents that timestamp failures are reported in the result when requested, but do not fail the overall chain verification.

---

## 14. Evidence Required Before Launch

Do not go live on confidence alone. Collect evidence.

### 14.1 Security evidence

- [ ] end-to-end test showing broken hash chain rejection
- [ ] end-to-end test showing invalid signature rejection
- [ ] end-to-end test showing revoked receipt rejection
- [ ] end-to-end test showing expired receipt rejection
- [ ] end-to-end test showing missing bundle rejection on fail-closed routes

### 14.2 Integration evidence

- [ ] MCP integration tested with real header transport
- [ ] A2A integration tested with real route handling
- [ ] request-binding test proving the executed request matches the signed invocation
- [ ] proxy or gateway compatibility test for realistic bundle sizes

### 14.3 Operational evidence

- [ ] status-list endpoint failure tested
- [ ] restart behavior tested for local revocation and replay state
- [ ] multi-instance behavior tested if you intend multi-instance rollout
- [ ] readiness behavior tested under warm-up failure and recovery

### 14.4 Documentation evidence

- [ ] operator docs match actual deployment behavior
- [ ] SDK docs match actual package behavior
- [ ] product claims do not exceed implemented semantics

---

## 15. Explicit Non-Goals

Until additional work is done, DRS in this repository should **not** be presented as:

- a complete OAuth 2.1 implementation
- an RFC 8693 token exchange implementation
- a UCAN implementation
- a general-purpose transparent proxy that can front any MCP/A2A system without integration work
- a full billing and cost-accounting engine
- a distributed session runtime with built-in cumulative quota tracking

---

## 16. Final Go/No-Go Decision

Use this final gate.

### 16.1 Greenlight for controlled pilot only if

- [ ] required routes are fail-closed
- [ ] request-binding gap is handled in your application integration
- [ ] replay semantics are acceptable for your deployment shape
- [ ] operators understand local vs remote revocation
- [ ] product/docs do not overstate `max_cost_usd`, `max_calls`, or storage tiers

### 16.2 Greenlight for general production only if

- [ ] request binding is enforced end-to-end
- [ ] replay protection is correct for restarts and replica topology
- [ ] revocation is durable enough for your threat model
- [ ] storage/timestamping claims match the actual deployment controls
- [ ] integration tests prove the real MCP/A2A path, not just the verifier in isolation

### 16.3 Red flag — do not call it production-ready if any of these are still true

- [ ] signed invocation and executed request can diverge
- [ ] replay protection disappears on restart without compensating controls
- [ ] local revoke is the only revocation path relied on in production
- [ ] `max_cost_usd` is marketed as a hard spend guarantee
- [ ] docs claim tiers or proxy behavior that the deployed system does not actually provide

---

## 17. Source References

Primary references for this checklist:

- `docs/drs-source-of-truth.md`
- `README.md`
- `drs-verify/pkg/verify/chain.go`
- `drs-verify/pkg/middleware/mcp.go`
- `drs-verify/pkg/middleware/a2a.go`
- `drs-verify/pkg/middleware/decode.go`
- `drs-verify/pkg/policy/evaluate.go`
- `drs-verify/pkg/nonce/store.go`
- `drs-verify/pkg/revocation/local.go`
- `drs-verify/pkg/config/config.go`
- `drs-verify/cmd/server/main.go`
- `drs-sdk/src/sdk/types.ts`
- `drs-verify/pkg/types/types.go`
- `docs-site/src/how-to/operators/storage-tiers.md`
- `docs-site/src/how-to/operators/revocation.md`

If any of these sources change materially, this checklist should be reviewed before the next release decision.
