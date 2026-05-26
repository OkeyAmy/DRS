# DRS Runtime Verification Audit

This directory contains the public, sanitized DRS runtime verification review.
It is written for contributors who need to
understand what was proven, what was blocked, and what does not exist yet.

## Evidence Rule

Only real controlled-environment execution counts as final assessment evidence:
real SDK issuance, real `drs-verify` HTTP behavior, real Node middleware
behavior, real logs, real metrics, and real command output. Mocks and static
examples may help development, but they are not final proof.

## Document Map

| File | Purpose |
|---|---|
| `scope.md` | Scope, evidence rules, safety rules, workstreams, and success criteria. |
| `workplan.md` | Original implementation plan plus status handoff to `status.md`. |
| `status.md` | Line-by-line accounting of audit workstreams and plan tasks. |
| `evidence.md` | Executed commands, evidence paths, and explicit blockers/not-implemented items. |
| `results.md` | Sanitized behavior results from live local verifier and middleware scenarios. |
| `claims.md` | Public claims mapped to runtime surfaces and evidence status. |
| `threat-model.md` | STRIDE model grounded in observed runtime behavior. |
| `risk-register.md` | Validated risks and follow-up actions. |
| `metadata.md` | Regulatory/audit metadata validation boundary. |
| `performance.md` | Benchmark requirements and explicit not-implemented status. |
| `product-readiness.md` | Product evaluator review and pilot/production boundaries. |
| `operator-guide.md` | Go verifier operator review and deployment evidence boundaries. |
| `integration-shapes.md` | MCP/A2A integration shape review and execution-integrity boundaries. |
| `follow-up.md` | Issue-ready follow-up work from audit gaps. |
| `reproduce.md` | Commands for reproducing local evidence. |
| `personas/` | Persona-specific assessment entry points. |
| `runbooks/` | Repeatable operator procedures for assessment scenarios. |

## Current Evidence Snapshot

Latest full local run: `.local/drs-assessment/live-*/`.

Proven locally:
- TypeScript typecheck and tests,
- SDK and MCP server builds,
- Go verifier package tests,
- Rust core tests,
- live verifier happy path,
- malformed `/verify` body rejection,
- chain-reference tamper rejection,
- receipt-signature tamper rejection,
- replay rejection,
- admin-token revocation path,
- metrics listener exposure,
- persona walkthrough and metadata validation.

Blocked locally:
- Docker Compose / published-image E2E,
- Redis-backed distributed replay,
- container-level health/readiness/log evidence.

Not implemented:
- benchmark runner and benchmark results,

Documented evaluations now exist for product readiness, Go verifier operation,
MCP/A2A integration shapes, and follow-up work. They are evidence reviews, not
substitutes for the blocked Docker/Redis runs.
