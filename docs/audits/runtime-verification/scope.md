# DRS Runtime Verification Audit Scope

**Status:** Audit scope and evidence rules  
**Scope:** Current DRS repository behavior, deployed-like local runtime behavior, and published-artifact behavior where explicitly selected.

## Goal

Build a rigorous, evidence-driven understanding of how DRS works in practice by exercising the real application surfaces: Rust core tests, Go verifier service, TypeScript SDK issuance, Node middleware, Docker/E2E deployment, Redis-backed replay protection, revocation paths, metrics, logs, and documentation claims.

The assessment must not stop at code reading. Every behavior claim and every security finding must be supported by runtime evidence captured from real DRS components running in a controlled environment.

## Non-Negotiable Evidence Rule

Mocks are not valid proof for this assessment.

Allowed evidence sources:

- real `drs-verify` binary or Docker image
- real Redis service when testing Redis nonce behavior
- real TypeScript SDK issuance calls
- real Node middleware calls
- real HTTP requests to `/verify`, `/healthz`, `/readyz`, `/metrics`, and `/admin/revoke`
- real generated Ed25519 keys and DRS bundles
- real local controlled status-list or `did:web` service when those flows are tested
- real logs, HTTP responses, metrics, and benchmark output from the controlled environment

Not accepted as final evidence:

- mocked verifier responses
- mocked middleware fetch calls
- hand-waved code-reading conclusions
- static-only claims without executing the relevant runtime path
- external attacks against systems not owned or controlled by this project

Unit tests and mocks may still help developers isolate implementation details, but they cannot be the basis for assessment conclusions.

## Environment Model

The assessment uses two runtime classes:

1. **Controlled live-like local environment**
   - Docker Compose services
   - real verifier container or locally built binary
   - Redis where replay-sharing behavior matters
   - metrics listener
   - local-only generated keys and bundles
   - loopback-only auxiliary services for status-list or `did:web` when needed

2. **Published-artifact environment**
   - published npm packages and container images where selected
   - same scenarios as local where practical
   - used to detect drift between source-tree behavior and shipped artifacts

No scenario may depend on attacking third-party services, production systems, or public internet infrastructure.

## Workstreams

### 1. Claims Inventory

Create a claims inventory from:

- `README.md`
- `SECURITY.md`
- `docs/drs-source-of-truth.md`
- `docs/production-readiness-checklist.md`
- `docs-site/src/**/*`
- `integration-tests/**/*`
- package manifests and examples

Each claim must map to one of:

- already proven by existing real-runtime evidence
- proven by conformance/unit tests only
- requires a new live-like scenario
- documented limitation
- stale or contradicted claim

### 2. Runtime Harness

Reuse existing harnesses before adding new ones:

- `integration-tests/run.sh`
- `integration-tests/docker-compose.test.yml`
- root `docker-compose.yml`
- `docker-compose.monitoring.yml`
- package scripts in `package.json`

Add small scenario runners only when existing harnesses cannot capture evidence cleanly.

### 3. Functional and Integration Validation

Validate core behavior using real components:

- SDK issues root and invocation receipts
- verifier accepts valid bundles
- verifier rejects malformed bundles
- verifier enforces chain linkage
- verifier enforces policy attenuation
- verifier enforces temporal validity
- middleware rejects missing or malformed bundles
- middleware accepts verified body-bound requests

### 4. Security and Abuse Validation

Use local-only controlled proof-of-concept scenarios for:

- tampered JWT signature
- Ed25519 non-canonical signature where applicable
- broken `prev_dr_hash` or `dr_chain`
- policy escalation
- replay of the same invocation
- memory nonce restart behavior
- Redis nonce behavior
- local revocation with wrong token
- local revocation with correct token
- revoked receipt verification behavior
- mismatched request body versus signed invocation arguments
- missing `X-DRS-Bundle`
- malformed bundle header
- oversized or malformed request body
- `did:web` SSRF protections using controlled local targets only
- metrics exposure behavior

Findings must use STRIDE categories and include severity, likelihood, impact, affected layer, reproduction steps, and recommended next action.

### 5. Deployment and Observability Validation

Exercise live-like deployment behavior:

- Docker image startup
- environment-variable configuration
- health readiness
- metrics listener behavior
- log messages for accepted, rejected, replayed, and revoked requests
- failure behavior when Redis or revocation dependencies are unavailable

### 6. Benchmark Study

Measure behavior using real verifier paths:

- chain depth 1, 3, and 10
- `did:key` baseline
- warm and cold resolver cache behavior where supported safely
- memory nonce versus Redis nonce
- with and without body binding
- valid request versus rejected request paths

Benchmarks must report p50, p95, p99, throughput, error rate, environment details, and command used.

### 7. Usability and Product Analysis

Evaluate whether the project is understandable and usable for:

- SDK integrator
- Node middleware integrator
- Go verifier operator
- MCP/A2A builder
- auditor/compliance reviewer
- security engineer
- product evaluator

Each persona gets a targeted example or walkthrough based on real runnable behavior.

### 8. Documentation Package

Publish sanitized outputs:

- behavior matrix
- practical assessment report
- STRIDE threat model
- risk register
- benchmark evidence document
- reproduction document
- persona examples
- operator runbooks
- prioritized follow-up issue list

## Contributor-Facing Artifact Layout

Public, sanitized artifacts:

```text
docs/audits/runtime-verification/
  README.md
  scope.md
  workplan.md
  claims.md
  results.md
  threat-model.md
  risk-register.md
  metadata.md
  evidence.md
  status.md
  performance.md
  reproduce.md
  personas/
  runbooks/
scripts/assessment/
```

Private local artifacts:

```text
.local/drs-assessment/
  generated-keys/
  raw-logs/
  http-captures/
  benchmark-raw/
  local-db/
  secrets/
  scanner-output/
```

The implementation plan must add `.local/drs-assessment/` to `.gitignore` before generating private evidence.

## Safety Rules

- Use only local or controlled environments.
- Do not attack third-party systems.
- Do not run large local scanners by default; use GitHub Actions for Trivy-style scans unless explicitly requested.
- Do not commit generated private keys, tokens, logs, captures, or raw benchmark dumps.
- Do not claim vulnerabilities from code reading alone.
- Do not rewrite project architecture during assessment; create follow-up issues for fixes.
- Do not mix assessment evidence, product fixes, and security fixes in one unreviewable commit.

## Success Criteria

The assessment is successful when it produces:

1. a claims inventory tied to real evidence,
2. live-like scenario scripts or commands for each major behavior,
3. sanitized evidence reports for expected and unexpected behavior,
4. a STRIDE threat model grounded in runtime observations,
5. benchmark results with reproducible commands,
6. persona-specific examples that a real user can follow,
7. a prioritized list of validated risks, gaps, and follow-up work.
