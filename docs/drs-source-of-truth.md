# Architecture Decision: Source of Truth Model

**Date:** 2026-04-13
**Status:** Accepted
**Applies to:** DRS v4.0

---

## Context

DRS has three implementation layers: Rust (`drs-core`), Go (`drs-verify`), and TypeScript (`drs-sdk`). Each layer implements portions of the DRS protocol: JCS canonicalization, chain hash computation, policy attenuation, Ed25519 signing/verification, and chain validation.

The implemented protocol profile in this repository is:

- JWT receipts
- RFC 8785 JCS canonicalization
- Ed25519 signatures
- `did:key` identifiers in core flows, with `did:web` resolution in the Go verifier
- SHA-256 hash chaining via `prev_dr_hash` and `dr_chain`

OAuth 2.1 and RFC 8693 appear in the surrounding problem framing and ecosystem positioning, but they are not implemented here as runtime protocol flows.

Without a canonical contract binding these implementations together, protocol drift is inevitable. A receipt that TypeScript accepts but Go rejects (or vice versa) is a security incident, not a bug.

Two models were considered.

---

## Options Evaluated

### Option A: Rust as the canonical protocol engine

All protocol logic lives exclusively in `drs-core`. TypeScript and Go become thin wrappers calling Rust via WASM (for TS) or C FFI / native binary (for Go). There is exactly one implementation of every protocol rule.

Advantages: zero drift risk, single audit surface, maximum consistency.

Disadvantages: WASM overhead in the issuance path, C FFI complexity in Go, loss of Go's native Ed25519 verifier and HTTP ergonomics, harder for contributors who do not write Rust.

### Option B: Spec + conformance vectors are canonical (chosen)

The protocol is defined by a shared fixture suite in `fixtures/conformance/`. TypeScript, Rust, and Go are peer implementations. All three must pass every conformance vector. Rust is treated as the internal reference implementation: when ambiguity arises in a vector definition, Rust's output decides.

Advantages: each language uses its native strengths (Go for verification server performance, TS for developer adoption, Rust for cryptographic correctness anchor), contributors can work in any layer, the protocol is testable independently of any single implementation.

Disadvantages: requires discipline to keep the conformance suite comprehensive, drift is detected at test time rather than prevented by construction.

---

## Decision

DRS adopts **Option B**: the conformance suite is the protocol contract.

---

## Role of Each Layer

| Layer | Language | Primary role | Protocol authority |
|---|---|---|---|
| `drs-core` | Rust | Cryptographic primitives, JCS canonicalization, capability index, reference verification | Internal reference. When a new vector is ambiguous, Rust output decides. |
| `drs-sdk` | TypeScript | Developer-facing SDK, issuance path, CLI, bundle composition | Peer implementation. Must pass all conformance vectors. |
| `drs-verify` | Go | Verification server, MCP/A2A middleware, revocation, storage, timestamping | Peer implementation. Must pass all conformance vectors. |

---

## How Conformance Vectors Work

All vectors live in `fixtures/conformance/`. Each vector file is a JSON document with a `vectors` array. Every vector has a unique `id` field.

The CI workflow (`.github/workflows/conformance.yml`) runs all three language test suites against the same fixture files on every push and pull request. A conformance failure in any language blocks the merge.

Test files:
- Rust: `drs-core/tests/test_conformance.rs`
- Go: `drs-verify/pkg/verify/conformance_test.go`
- TypeScript: `drs-sdk/src/sdk/conformance.test.ts`

---

## Adding a New Vector

1. Define the vector in `fixtures/conformance/generate.mjs`.
2. Run the generator: `node fixtures/conformance/generate.mjs`.
3. The generator uses Rust-compatible algorithms (same JCS rules, same SHA-256 computation, same Ed25519 signing with `@noble/ed25519`). If the generator output does not match the Rust implementation, the Rust output is authoritative and the generator must be corrected.
4. Run all three conformance test suites locally before pushing.
5. The CI matrix job verifies the same vectors in all three languages.

---

## What "Rust as Internal Reference" Means

Rust is not the sole engine. All three implementations are equally valid in production. But when a disagreement occurs:

1. The conformance vector output is checked against `drs-core`.
2. If Rust produces a different result from the fixture, the fixture is wrong and must be regenerated from Rust output.
3. If Go or TypeScript produces a different result from the fixture, those implementations have a bug and must be fixed.

This does not mean Rust code is always right. It means Rust is the tiebreaker when two implementations disagree and the spec text does not resolve it.

---

## DRS-over-MCP Transport Binding

DRS bundles can travel over two transport shapes. The encoding and placement rules
differ per shape, and client/server implementations must agree on which shape is
in use.

### Shape 1: HTTP-terminated MCP (Go middleware)

Used when the tool server is implemented in Go and imports
`github.com/drs-protocol/drs-verify/pkg/middleware`. The middleware runs
in-process inside the tool server and calls `verify.Chain()` directly —
drs-verify itself is never in the traffic path.

| Aspect | Value |
|--------|-------|
| **Placement** | HTTP request header `X-DRS-Bundle` |
| **Encoding** | `base64url(JSON.stringify(bundle))` — no padding (`=` omitted) |
| **Verification** | In-process via `verify.Chain()` or forwarded to `POST /verify` |
| **Missing bundle** | HTTP 401 (fail-closed) or pass-through (optional mode) |
| **Invalid bundle** | HTTP 400 (decode failure) or HTTP 403 (verification failure) |
| **Implementation** | `drs-verify/pkg/middleware/mcp.go` |

### Shape 2: JSON-RPC metadata (TypeScript SDK)

Used when MCP traffic is pure JSON-RPC over stdio or WebSocket, and there is no
HTTP header layer available.

| Aspect | Value |
|--------|-------|
| **Placement** | `message.params._meta["X-DRS-Bundle"]` |
| **Encoding** | `base64url(JSON.stringify(bundle))` — same encoding as Shape 1 |
| **Verification** | Remote `POST` to a `/verify` endpoint with the decoded JSON bundle body |
| **Missing bundle** | Structured `MISSING_BUNDLE` error in return value |
| **Invalid bundle** | Structured `MALFORMED_BUNDLE` or `VERIFICATION_FAILED` error |
| **Client** | `packages/drs-mcp-client/src/client.ts` |
| **Server** | `packages/drs-mcp-server/src/middleware.ts` |

### Encoding rule (both shapes)

The bundle is always transmitted as a **base64url string** (RFC 4648 section 5,
no padding). The receiver decodes base64url to get JSON bytes, then parses JSON
to get the `ChainBundle` object.

This means:

- The client calls `base64url(JSON.stringify(bundle))` before attaching.
- The server calls `JSON.parse(base64urlDecode(raw))` to recover the bundle.
- Both shapes use the same encoding, so a bridge between Shape 1 and Shape 2
  only needs to move the string between HTTP header and `_meta` field.

### Method scope

DRS verification applies only to tool-call methods:

- `tools/call` (standard MCP)

Non-tool methods (`resources/list`, `prompts/get`, `initialize`, etc.) must
**not** be subject to DRS verification.

---

## Conformance Coverage Boundary

The conformance suite in `fixtures/conformance/` covers:

- JCS canonicalization (RFC 8785)
- Chain hash computation (SHA-256)
- Policy attenuation (pass and fail)
- Temporal validity
- Revocation status lookup
- Receipt signatures and full chain bundle verification

The conformance suite does **not** cover:

- RFC 3161 timestamping
- Storage tier selection or persistence
- HTTP API behavior (`/verify`, `/admin/revoke`)
- MCP transport binding (Shape 1 / Shape 2 wire format)
- Admin revocation endpoint

These areas are tested by unit and integration tests within each language layer,
not by cross-language conformance vectors.

---

## CI Enforcement

The conformance workflow (`.github/workflows/conformance.yml`) runs on:

- Push to `main` or `master` (with path filters)
- Pull requests (with path filters matching `fixtures/`, `drs-core/`, `drs-sdk/`, `drs-verify/`)
- Manual dispatch (`workflow_dispatch`)

A conformance failure blocks the merge **only if branch protection rules require
the workflow status check**. Repository administrators must enable this protection
for the gate to be enforced.

---

## Implications

- No protocol-affecting code change ships without a conformance vector covering it.
- Cross-language conformance is a CI gate, not an afterthought.
- Contributors working in one language can verify their changes against the shared fixtures without needing to build the other two languages locally.
