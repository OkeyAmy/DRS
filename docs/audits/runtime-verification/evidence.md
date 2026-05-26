# DRS Runtime Verification Evidence

This file is the assessment evidence record. A workstream is `Proven` only when
it has an executed command, a pass/fail result, and an evidence path. Work that
does not exist is marked `Not implemented`; work that could not run is marked
`Blocked` with the exact blocker. Latest full local evidence run:
`.local/drs-assessment/live-*/`.

| Workstream | Status | Executed command | Evidence path / blocker | What is proven |
|---|---|---|---|---|
| Persona verifier happy path | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-verify-happy-path.json` | Real SDK-issued bundle verifies against real local `drs-verify`. |
| Audit context | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-audit-context.json` | Consent, root type, session id, and regulatory metadata are surfaced by verifier context. |
| Policy denial | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-policy-violation.json` | Tool outside `allowed_tools` returns `POLICY_VIOLATION`. |
| Verifier body-binding mismatch | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-body-binding-mismatch.json` | Untampered chain can be valid while mismatched body is reported as `binding: "mismatch"`. |
| Node HTTP middleware handler blocking | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-middleware-handler-block.json` | `createDrsHttpMiddleware` returns `BINDING_MISMATCH` and the protected handler is not called. |
| Metadata validation | Proven | `pnpm --filter drs-persona-walkthrough test` | `examples/drs-persona-walkthrough/src/metadata.test.ts` | Canonical framework ids and metadata fields validate; display labels are rejected as raw ids. |
| MCP middleware unit behavior | Proven by unit tests | `pnpm --filter @drs/mcp-server test` | `packages/drs-mcp-server/src/http.test.ts`, `packages/drs-mcp-server/src/middleware.test.ts` | Missing bundles, invalid verifier result, binding mismatch, and verifier outage fail closed in middleware unit tests. |
| Go revocation/admin behavior | Proven by Go tests | `go test ./pkg/revocation` | `drs-verify/pkg/revocation/*_test.go` | Admin token checks, local revocation, file-backed revocation, and status-cache behavior pass package tests. |
| Go metrics behavior | Proven by Go tests | `go test ./pkg/metrics ./cmd/server` | `drs-verify/pkg/metrics/metrics_test.go`, `drs-verify/cmd/server/main_test.go` | Metrics registration and server binding paths pass package tests. |
| Go nonce/replay primitives | Proven by Go tests | `go test ./pkg/nonce ./pkg/middleware` | `drs-verify/pkg/nonce/*_test.go`, `drs-verify/pkg/middleware/*_test.go` | In-memory/Redis nonce code and middleware replay helpers pass package tests. |
| Live chain tamper | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-live-chain-tamper.json` | Mutating a receipt without updating invocation chain references returns `CHAIN_REFERENCE_MISMATCH`. |
| Live receipt signature tamper | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-live-receipt-signature-tamper.json` | Mutating a receipt payload and updating the invocation chain hash returns `INVALID_SIGNATURE`. |
| Live nonce replay | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-live-replay.json` | Reusing the same invocation JTI returns HTTP `409` with `REPLAY_DETECTED`. |
| Live admin revocation | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-live-admin-revoke-*.json` | Wrong bearer token is denied; correct token revokes a status index and later verification returns `REVOKED`. |
| Live metrics listener | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/responses/S-live-metrics.json` | Metrics listener exposes Prometheus verification/binding counters when `METRICS_ADDR` is configured. |
| Product readiness review | Documented | Manual audit synthesis | `product-readiness.md` | Pilot-safe and production-unsafe claims are separated from runtime evidence. |
| Go operator review | Documented | Manual audit synthesis | `operator-guide.md` | Proven local operator surfaces and blocked Docker/Redis evidence are separated. |
| MCP/A2A shape review | Documented | Manual audit synthesis | `integration-shapes.md` | Shape 1 execution-integrity evidence is separated from Shape 2/A2A limitations. |
| Follow-up issue list | Documented | Manual audit synthesis | `follow-up.md` | Blocked and not-implemented work is converted into issue-ready items. |
| Docker / published image E2E | Blocked locally | `./run.sh` from `integration-tests/` | Local `docker-compose` failed before startup with `Not supported URL scheme http+docker`. | Not proven in this environment. |
| Redis replay across deployed verifier | Blocked locally | `./run.sh` from `integration-tests/` | Same Docker Compose failure as above. | Not proven in this environment. |
| Published artifact comparison | Blocked locally | `./run.sh` from `integration-tests/` | Same Docker Compose failure; no successful published-image run captured. | Not proven in this environment. |
| Benchmarks | Not implemented | No benchmark command exists or was executed. | `performance.md` records the missing workload and reporting requirements. | No latency, throughput, p50, p95, p99, or capacity claim is proven. |
| Trivy/local scanner | Intentionally not run | Not executed. | User previously asked not to install/run local Trivy due large downloads. | Security scanner evidence remains CI/web-only. |
| TypeScript SDK/client/middleware tests | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/logs/typescript-tests.log` | 140 TypeScript tests passed across SDK and MCP packages. |
| Go verifier package tests | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/logs/go-tests.log` | All `drs-verify` packages passed, including anchor, binding, nonce, resolver, revocation, middleware, metrics, verify. |
| Rust core tests | Proven | `scripts/assessment/run-live-assessment.sh` | `.local/drs-assessment/live-*/logs/rust-tests.log` | `drs-core` tests passed, including Ed25519, JCS, JWT, policy, capability, chain verification, conformance. |

## Docker Blocker Detail

Attempted command:

```bash
cd integration-tests
./run.sh
```

Observed blocker:

```text
docker.errors.DockerException: Error while fetching server API version: Not supported URL scheme http+docker
```

The assessment must not mark Docker, Redis, or published-image behavior `Proven`
until this environment issue is fixed or a CI run provides equivalent evidence.
