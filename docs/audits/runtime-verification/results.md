# DRS Practical Assessment Results

## Evidence Standard

Each scenario records command, environment, request shape, status, response body,
log excerpt where relevant, metric signal where relevant, expected behavior,
observed behavior, and verdict. Raw logs and captures stay under
`.local/drs-assessment/`; this report contains only sanitized summaries.

## Current Verified Scenarios

Latest evidence run: `.local/drs-assessment/live-*/`.

| Scenario | Category | Command | Expected | Observed | Evidence path | Verdict |
|---|---|---|---|---|---|---|
| S-verify-happy-path | Functional | `scripts/assessment/run-live-assessment.sh` | Valid SDK-issued bundle returns `valid: true` and `binding: "match"`. | 4-test walkthrough passed and capture verdict is `pass` against real local `drs-verify`. | `.local/drs-assessment/live-*/responses/S-verify-happy-path.json` | Pass |
| S-policy-violation | Security / authorization | `scripts/assessment/run-live-assessment.sh` | Tool absent from `allowed_tools` returns `POLICY_VIOLATION`. | `refund_customer` denied by verifier policy evaluation. | `.local/drs-assessment/live-*/responses/S-policy-violation.json` | Pass |
| S-body-binding-mismatch | Security / integrity | `scripts/assessment/run-live-assessment.sh` | Chain may be cryptographically valid, but mismatched body reports `binding: "mismatch"`. | Signed `customer_id=cus_001` with posted `customer_id=cus_999` produced `binding: "mismatch"`. This proves detection, not handler rejection. | `.local/drs-assessment/live-*/responses/S-body-binding-mismatch.json` | Pass for detection only |
| S-audit-context | Auditability | `scripts/assessment/run-live-assessment.sh` | Verifier context includes human root, session ID, consent record, and regulatory metadata. | Context returned `root_type: "human"`, session ID, and canonical framework ids `eu-ai-act-art12`, `eu-ai-act-art13`, `soc2-security`. | `.local/drs-assessment/live-*/responses/S-audit-context.json` | Pass |
| S-metadata-validation | Auditability / metadata | `pnpm --filter drs-persona-walkthrough test` | Canonical framework ids, consent fields, policy hash, risk level, and retention fields validate; display-label framework ids fail. | Metadata tests validate schema/policy boundaries and reject overclaim-style labels. | `examples/drs-persona-walkthrough/src/metadata.test.ts` | Pass |
| S-middleware-handler-block | Security / integrity | `scripts/assessment/run-live-assessment.sh` | Node HTTP middleware rejects body-binding mismatch before the protected handler runs. | Real local verifier returned binding mismatch; `createDrsHttpMiddleware` returned `BINDING_MISMATCH` and captured `handlerCalls: 0`. | `.local/drs-assessment/live-*/responses/S-middleware-handler-block.json` | Pass |
| S-live-chain-tamper | Data integrity | `scripts/assessment/run-live-assessment.sh` | Mutated receipt breaks invocation hash linkage. | Live verifier returned `valid: false` with `CHAIN_REFERENCE_MISMATCH`. | `.local/drs-assessment/live-*/responses/S-live-chain-tamper.json` | Pass |
| S-live-receipt-signature-tamper | Data integrity / crypto | `scripts/assessment/run-live-assessment.sh` | Payload mutation with matching chain hash still fails signature verification. | Live verifier returned `valid: false` with `INVALID_SIGNATURE`. | `.local/drs-assessment/live-*/responses/S-live-receipt-signature-tamper.json` | Pass |
| S-live-replay | Security / replay | `scripts/assessment/run-live-assessment.sh` | Reused invocation JTI is rejected after a first successful verification. | First `/verify` returned `valid: true`; second returned HTTP `409` with `REPLAY_DETECTED`. | `.local/drs-assessment/live-*/responses/S-live-replay.json` | Pass |
| S-live-admin-revoke-wrong-token | Authorization | `scripts/assessment/run-live-assessment.sh` | Wrong admin token is denied. | Live `/admin/revoke` returned HTTP `401`. | `.local/drs-assessment/live-*/responses/S-live-admin-revoke-wrong-token.json` | Pass |
| S-live-admin-revoke-correct-token-and-reject | Revocation | `scripts/assessment/run-live-assessment.sh` | Correct admin token records revocation and future verification rejects the receipt. | Before revoke verified, revoke returned `revoked: true`, after revoke returned `REVOKED`. | `.local/drs-assessment/live-*/responses/S-live-admin-revoke-correct-token-and-reject.json` | Pass |
| S-live-metrics | Observability | `scripts/assessment/run-live-assessment.sh` | Metrics listener exposes verification counters when enabled. | Live `/metrics` returned Prometheus samples including verification or binding counters. | `.local/drs-assessment/live-*/responses/S-live-metrics.json` | Pass |

## Blocked or Not Implemented Scenarios

| Scenario | Category | Expected | Evidence needed |
|---|---|---|---|
| S-redis-replay | Security / distributed replay | Replay is rejected across verifier instances sharing Redis. | Blocked in this local environment: `integration-tests/run.sh` fails before service startup with `docker.errors.DockerException: Not supported URL scheme http+docker`. No Redis distributed replay behavior is proven. |

See `evidence.md` for the current evidence record.

## Current Codebase Test Evidence

| Surface | Command | Evidence path | Result |
|---|---|---|---|
| TypeScript SDK and MCP packages | `pnpm typecheck && pnpm test` | `.local/drs-assessment/live-*/logs/typescript-typecheck.log`, `logs/typescript-tests.log` | Passed; 140 tests across SDK and MCP packages. |
| Go verifier packages | `go test ./...` in `drs-verify` | `.local/drs-assessment/live-*/logs/go-tests.log` | Passed across all verifier packages. |
| Rust core | `cargo test` in `drs-core` | `.local/drs-assessment/live-*/logs/rust-tests.log` | Passed across core/unit/integration tests. |

## Reader Warning

Passing examples are evidence for the tested local conditions only. They do not
replace production threat modeling, key management review, load testing, or
deployment-specific controls.
