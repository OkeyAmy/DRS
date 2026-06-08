# Threat Model: DRS (Delegation Receipt Standard) v3

## 1. System context

DRS is a JWT-based delegation-receipt system for agentic accountability. It lets
a human (or machine) delegate a narrow capability to an AI agent, have that agent
sub-delegate under attenuation, and lets a verifier prove — at the moment a tool is
invoked — that the whole chain from root consent to leaf invocation is authentic,
unexpired, un-revoked, and within policy. The trust primitives are Ed25519
signatures, `did:key`/`did:web` identity, SHA-256 hash chaining between receipts,
and RFC 8785 (JCS) canonicalisation.

The implementation is a three-layer polyglot stack: **`drs-core`** (Rust, ~3.1k LOC)
holds the crypto primitives, JCS canonicalisation, chain-hash computation, and
capability index, and compiles to native + WASM; **`drs-verify`** (Go, ~11.2k LOC)
is the verification server, exposing `/verify`, `/admin/revoke`, health and metrics
endpoints, plus MCP and A2A middleware adapters, LRU DID-resolver caching, and a
revocation status-list cache; **`@okeyamy/drs-sdk`** (TypeScript, ~2.6k LOC) is the
developer-facing issuance path and CLI. DRS is designed to be deployed as a sidecar
or standalone verifier in front of an MCP/A2A tool server. It deliberately does
**not** authenticate users, transport messages, store agent state, or define what
capabilities mean — those belong to the wallet/IDP, MCP/A2A, the agent runtime, and
the tool owner respectively. The codebase carries a prior security audit
(`docs/security_audit_report_2026-04-08.md`, 1 critical / 4 high / 5 medium) whose
findings have largely been remediated in subsequent `security/group*` PRs; this
model treats those findings as **evidence** that the corresponding threat classes
are live for this system, and scores residual likelihood against the current code.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Delegation chain integrity | The verified authorization decision (`valid`/`invalid`) for a chain + invocation. The whole product exists to make this trustworthy. | critical |
| Ed25519 signing keys | Issuer private keys held on the SDK/issuer side. The verifier holds only public keys, but a key compromise forges any chain. | critical |
| Revocation status | The status-list bitstring plus local revocation store that decide whether a receipt is still valid. | high |
| Admin revocation control | The `POST /admin/revoke` token-gated ability to revoke a status-list index. | high |
| Audit / consent / regulatory metadata | Human-consent records and regulatory fields surfaced in `VerificationContext` for compliance and audit export. | high |
| Verifier availability | The verifier sits in the request path of every protected tool call; if it stalls, protected traffic stalls. | high |
| RFC 3161 timestamp evidence | Tier-3 trusted-timestamp tokens proving a receipt existed at a given time. | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| POST /verify | Core six-block chain verification of an attacker-supplied bundle, with optional request-body↔`invocation.args` binding. | unauth network → verification decision | Delegation chain integrity, Revocation status, Audit / consent / regulatory metadata, Verifier availability |
| MCP/A2A middleware (`X-DRS-Bundle`) | Fail-closed enforcement adapters in front of protected tool routes; `Optional*` variants pass through when the header is absent. | unauth network → protected tool execution | Delegation chain integrity, Verifier availability |
| POST /admin/revoke | Admin-token-gated revocation of a status-list index. | unauth network → admin revocation control | Admin revocation control, Revocation status |
| did:web resolution (egress) | Outbound HTTPS fetch of issuer DID documents during signature verification; the issuer DID is attacker-controlled. | verifier → attacker-influenced URL | Verifier availability |
| status-list fetch (egress) | Outbound HTTP fetch of the revocation status bitstring. | verifier → remote status list | Revocation status, Verifier availability |
| RFC 3161 TSA (egress) | Outbound timestamp request/verify against a Timestamp Authority. | verifier → TSA | RFC 3161 timestamp evidence |
| /metrics | Prometheus metrics on a separate listener (`METRICS_ADDR`). | ops network → operational telemetry | Verifier availability |
| WASM / SDK boundary | Rust core compiled to WASM, loaded by the TS SDK for issuance; plus CLI verify/audit. | developer input → signed receipt | Ed25519 signing keys, Delegation chain integrity |
| Supply chain | `ed25519-dalek`, `golang-lru/v2`, `@noble/*`, `go-redis`, GitHub Actions (cosign/Trivy/govulncheck). | third-party code → verifier/SDK process | Delegation chain integrity, Ed25519 signing keys |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Supply-chain compromise of a crypto dependency delivers malicious signing or verification code | supply_chain | Supply chain | Ed25519 signing keys, Delegation chain integrity | critical | possible | partially_mitigated | Trivy SARIF + govulncheck in CI; cosign keyless signing; Dependabot; SHA-pinned actions | eea2bbb, ddd899e, f60fda0 (noble/ed25519 v3 migration) |
| T2 | Middleware misconfiguration leaves protected MCP/A2A routes open to unauthenticated tool invocation | remote_unauth | MCP/A2A middleware (X-DRS-Bundle) | Delegation chain integrity, Verifier availability | critical | possible | partially_mitigated | `MCPMiddleware`/`A2AMiddleware` now fail-closed (401); `Optional*` variants exist for advisory use; documented in code comments | audit-2026-04-08 #1 (CRITICAL — now fixed in code; risk shifts to operator misconfiguration choosing Optional* variant) |
| T3 | Ed25519 signing key compromise enables forging of arbitrary valid delegation chains | insider | WASM / SDK boundary | Ed25519 signing keys, Delegation chain integrity | critical | rare | partially_mitigated | `verify_strict` + manual S-canonicality check (closes malleability); no key escrow visible in codebase | 8a02602, eea88a9 (strict S-range check added) |
| T4 | SSRF via attacker-controlled `did:web` issuer DID targeting internal infrastructure | remote_unauth | did:web resolution (egress) | Verifier availability | high | possible | partially_mitigated | HTTPS-only; redirect/DNS-rebind block (2eb5b61); 1 MiB body cap; circuit breaker; LRU-bounded cache | 2eb5b61, 6ded127 |
| T5 | Revocation bypass: partial or truncated status-list fetch silently makes revoked receipts appear valid | remote_unauth | status-list fetch (egress) | Revocation status, Delegation chain integrity | high | possible | partially_mitigated | Fail-closed when no snapshot exists (5c13eec); explicit fetchTimeout + ctx cancellation (e02ea0b); partial-read fix needed (audit #4 body) | audit-2026-04-08 #4, 5c13eec, e02ea0b |
| T6 | Confused-deputy / cross-server replay: valid invocation re-submitted to a different tool server with same chain | remote_auth | POST /verify, MCP/A2A middleware (X-DRS-Bundle) | Delegation chain integrity, Audit / consent / regulatory metadata | high | possible | partially_mitigated | D4b: `invocation.sub == root_sub` enforced; D4c: `invocation.tool_server` checked **only when `ServerIdentity` is configured** — opt-in | audit-2026-04-08 #2 (fixed in code; residual risk if `ServerIdentity` left empty) |
| T7 | DoS via global DID-resolver lock: slow `did:web` fetch serialises all verification traffic | remote_unauth | did:web resolution (egress), POST /verify | Verifier availability | high | possible | partially_mitigated | Circuit breaker (6ded127); 10 s HTTP timeout; LRU-bounded cache; underlying lock not yet decomposed to per-key singleflight | audit-2026-04-08 #3 |
| T8 | RFC 3161 timestamp trust spoofed: attacker presents self-signed TSA token accepted as trusted evidence | remote_auth | RFC 3161 TSA (egress) | RFC 3161 timestamp evidence, Audit / consent / regulatory metadata | high | rare | partially_mitigated | `VerifyTimestampTrusted` now accepts a `TSARootPool`; timestamp failures non-fatal (don't fail chain); EKU validation gap remains | audit-2026-04-08 #5 |
| T9 | `max_calls` policy field declared in receipts but never enforced at verify time, enabling unlimited invocations | remote_auth | POST /verify | Delegation chain integrity | high | likely | unmitigated | Attenuation check prevents child raising `max_calls`; runtime call-count enforcement absent by design (requires external session state) | audit-2026-04-08 #10 |
| T10 | Admin token brute-forced or leaked, enabling unauthorised revocation of live delegations | remote_unauth | POST /admin/revoke | Admin revocation control, Revocation status | high | rare | partially_mitigated | Token compared via `sha256.Sum256` (constant-time byte compare; 6119342 length-leak fix); no rate limit on `/admin/revoke` observed | 6119342 |
| T11 | Rate-limit bypass via `X-Forwarded-For` spoofing enables flooding of `/verify` | remote_unauth | POST /verify | Verifier availability | medium | possible | partially_mitigated | Per-IP before global check; `TRUST_PROXY` env var controls XFF trust; per-IP token bucket | b54a693 |
| T12 | Nonce pre-exhaustion: attacker drains a known JTI nonce slot using a malformed (invalid-sig) bundle | remote_unauth | MCP/A2A middleware (X-DRS-Bundle) | Delegation chain integrity | medium | rare | mitigated | Nonce committed only after valid signature (aa45f3a fix; verify → nonce → binding order enforced) | aa45f3a |
| T13 | Prometheus `/metrics` endpoint leaks rate-limit state, chain counts, or timing data to ops network | adjacent_network | /metrics | Verifier availability | medium | possible | partially_mitigated | Served on separate `METRICS_ADDR` listener since 064f255; still no auth on the metrics port itself | 064f255, b79408d |
| T14 | DoS via maximally-deep chain (16 receipts × full crypto verify + DID resolve per receipt) | remote_unauth | POST /verify | Verifier availability | medium | possible | partially_mitigated | `maxChainDepth = 16` cap; rate limiting; HTTP server timeouts (4212f75) | audit-2026-04-08 #9 (timeout fix) |
| T15 | Audit-trail spoofing: `drs_consent` and regulatory metadata present in signed payload but not re-validated cross-layer | remote_auth | POST /verify | Audit / consent / regulatory metadata | medium | possible | partially_mitigated | Fields are inside signed JWT payload (tamper-evident); `DrsRootType=human` requires `DrsConsent` (B2 block); downstream consumers must validate semantics | (no specific evidence; STRIDE gap-fill) |
| T16 | Store tiers bypassed: receipts never persisted in verification flow, breaking audit-retention and Tier-3 anchoring | local_admin | POST /verify | RFC 3161 timestamp evidence, Audit / consent / regulatory metadata | medium | likely | partially_mitigated | `deps.Store.Put` now called in verification flow (current code); non-fatal (store failures logged, not chain-failed) | audit-2026-04-08 #6 (partially remediated) |

## 5. Deprioritized

| threat | reason |
|---|---|
| SQL injection | No database in the verification path; state is file-backed or Redis key-value; no query construction. |
| XSS / CSRF | No browser-facing UI; all endpoints are JSON APIs consumed by agents and middleware. |
| Memory corruption (RCE via parsing) | Go and Rust memory-safe runtimes; the one native surface (WASM) is sandboxed in the browser. Excluded unless a future C/C++ dependency is introduced. |
| Privilege escalation within the OS | Verifier is a single-user Go binary with no setuid, no privileged syscalls; container-deployed with read-only root fs in the Docker setup. |
| Physical access | Out of scope; deployment model is cloud/container. |
| Repudiation by the verifier | The verifier is stateless on the happy path; logs via `slog`; it does not take actions that need attribution. Downstream integrators are responsible for audit logging. |
| Insider key theft from the verifier | Verifier holds only public keys; private keys never cross into `drs-verify`. |

## 6. Open questions

- **`ServerIdentity` deployment**: Is `SERVER_IDENTITY` configured in production deployments? If left empty, the `tool_server` binding check (D4c) is silently skipped, leaving T6 (confused-deputy replay) partially open. This is the single most impactful operator configuration question.
- **`Optional*` middleware usage**: Do any downstream integrators use `OptionalMCPMiddleware` or `OptionalA2AMiddleware` in production? If so, those routes are intentionally unverified and T2's residual risk is live.
- **Status-list provider reliability**: Who hosts the revocation status list and what is the SLA? The partial-read fix (T5) is not complete; a slow/truncated response during a refresh window can still produce a partial bitstring.
- **RFC 3161 TSA trust roots**: Is `TSA_ROOT_CERT_PEM` configured in production? If not, `system roots` is used — which may or may not include the deployed TSA's CA. EKU (`id-kp-timeStamping`) validation coverage is unclear.
- **`max_calls` intent**: Is `max_calls` intended to be informational-only (document it clearly) or enforcement-bound (requires a session store + atomic counters)? The current gap is the single largest policy-expressiveness-vs-enforcement mismatch.
- **Redis nonce store persistence**: Under pod restart, does the Redis nonce store survive? A non-persistent store creates a replay window sized to the TTL of in-flight nonces across restarts.
- **Network exposure of `/verify`**: Is the verifier exposed directly to the internet, or only within a private network? T4 (SSRF), T7 (DoS), T11 (rate-limit bypass) scores should be revised upward if internet-exposed.
- **Metrics port network policy**: Is `METRICS_ADDR` reachable only from the ops network? If exposed more broadly, T13 moves from `medium` to `high`.

## 7. Provenance

- mode: bootstrap
- date: 2026-06-06
- target: /home/okey/Desktop/Projects/DRS @ 92a4c69
- inputs: git-log (security-keyword grep, all branches) + docs/security_audit_report_2026-04-08.md + live code reads (chain.go, middleware/{mcp,a2a}.go, resolver/did.go, crypto/ed25519.rs)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Make `SERVER_IDENTITY` required (not opt-in) — fail startup if unset; document in README and docker-compose | T6 | yes | S |
| Complete partial-read fix in status-list refresh: use `io.ReadAll` + `Content-Length` cross-check; reject and retain previous snapshot on any error | T5 | yes | S |
| Decompose global resolver lock: per-DID singleflight for network misses; read-lock for cache hits | T7 | yes | M |
| Formally declare `max_calls` as informational or implement session-state enforcement with atomic counters and a durable store | T9 | yes | L |
| Add rate limit to `POST /admin/revoke`; consider IP-allowlist or mTLS for the admin endpoint | T10 | partial | S |
| Add TSA EKU (`id-kp-timeStamping`) validation inside `VerifyTimestampTrusted`; document TSA allowlist policy | T8 | partial | M |
| Enforce network policy restricting `METRICS_ADDR` to the ops subnet; add basic auth or mTLS to metrics port | T13 | yes | S |
| Add SBOM + Dependabot auto-merge for `ed25519-dalek` patch releases; verify `verify_strict` is called (not `verify`) in any future Rust upgrade | T1, T3 | partial | M |
