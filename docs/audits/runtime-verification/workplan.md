# DRS Runtime Verification Audit Workplan

> **For agentic workers:** execute this plan task-by-task. Every behavior claim must be backed by real DRS runtime evidence from a controlled environment. Mocks are not valid final proof.

**Goal:** Build a practical, reproducible assessment of DRS behavior, security posture, usability, and performance using real DRS components.

**Architecture:** The assessment is evidence-first. Public docs and sanitized scripts live in the repository; private raw logs, keys, captures, and benchmark dumps live under `.local/drs-assessment/` and are gitignored.

**Tech Stack:** Rust `drs-core`, Go `drs-verify`, TypeScript `drs-sdk`, Node middleware packages, Docker Compose, Redis, shell/Node scenario runners, markdown reports.

---

## Execution Status

The status record for this plan is maintained in `status.md`. It records each
plan task and audit workstream as `Proven`, `Mixed`,
`Blocked`, or `Not implemented` using real current-codebase evidence paths. The latest full local evidence run is
`.local/drs-assessment/live-*/`.

Do not treat unchecked historical task boxes below as the source of truth for
completion status; they are the original implementation recipe. The executable
status record is `status.md` plus `evidence.md`.

## Task 1: Artifact Guardrails

**Files:**
- Modify: `.gitignore`
- Create: `.local/drs-assessment/` during execution only; do not commit contents

- [ ] **Step 1: Add private assessment output root to `.gitignore`**

Add this block:

```gitignore
# ── Local DRS practical assessment artifacts (never commit) ──────────────────
.local/drs-assessment/
```

- [ ] **Step 2: Verify the ignore rule**

Run:

```bash
mkdir -p .local/drs-assessment/raw-logs
printf 'private test log\n' > .local/drs-assessment/raw-logs/probe.log
git status --short .local/drs-assessment
```

Expected: no output.

- [ ] **Step 3: Remove the probe file or leave it ignored**

Run:

```bash
rm -f .local/drs-assessment/raw-logs/probe.log
```

Expected: command exits 0.

## Task 2: Claims Matrix Skeleton

**Files:**
- Create: `docs/audits/runtime-verification/claims.md`

- [ ] **Step 1: Create the matrix with concrete initial claims**

Write:

```markdown
# DRS Claims Matrix

| ID | Claim | Source | Runtime surface | Evidence status | Scenario |
|---|---|---|---|---|---|
| C-001 | DRS verifies signed delegation chains and invocation receipts. | README.md | `/verify` + SDK-issued bundle | Proven by live local evidence | S-verify-happy-path, S-live-verify-happy-path |
| C-002 | Chain tampering is detected through SHA-256 hash linkage. | README.md, docs/drs-source-of-truth.md | `/verify` | Proven by live local evidence | S-live-chain-tamper, S-live-receipt-signature-tamper |
| C-003 | `/verify` reports mismatched body binding; middleware must enforce rejection before handler execution. | docs/production-readiness-checklist.md | Node HTTP middleware + `/verify` | Proven by staged live local evidence | S-body-binding-mismatch, S-middleware-handler-block |
| C-004 | Replay protection rejects a reused invocation. | README.md, SECURITY.md | `/verify` with nonce store | Proven by live local evidence; Redis deployment remains blocked | S-live-replay |
| C-005 | Redis nonce backend provides shared replay protection. | docs/production-readiness-checklist.md | Docker Compose + Redis | Blocked locally by Docker Compose `http+docker` failure; no Redis replay claim is proven | S-redis-replay |
| C-006 | `/admin/revoke` requires an admin token. | README.md, docs-site reference | `/admin/revoke` | Proven by live local evidence | S-live-admin-revoke-wrong-token, S-live-admin-revoke-correct-token-and-reject |
| C-007 | Metrics are available on the configured metrics listener. | README.md | `/metrics` | Proven by live local evidence | S-live-metrics |
| C-008 | Pure JSON-RPC Shape 2 is provenance-only until params binding exists. | SECURITY.md | `packages/drs-mcp-server/src/middleware.ts` | Documented limitation; needs walkthrough | S-shape2-limitation |
```

- [ ] **Step 2: Verify no template-only status text exists**

Run:

```bash
grep -nE 'T[B]D|T[O]DO|fill[[:space:]]+in[[:space:]]+details|Not[[:space:]]+run[[:space:]]+yet' docs/audits/runtime-verification/claims.md || true
```

Expected: no matches.

## Task 3: Live Scenario Runner Skeleton

**Files:**
- Create: `scripts/assessment/README.md`
- Create: `scripts/assessment/run-live-assessment.sh`

- [ ] **Step 1: Create `scripts/assessment/README.md`**

Write:

```markdown
# DRS Assessment Scripts

These scripts run against real DRS components in a controlled environment. They do not mock verifier responses or middleware behavior.

Raw outputs go under `.local/drs-assessment/` and must not be committed. Sanitized summaries belong under `docs/audits/runtime-verification/`.

## First command

```bash
scripts/assessment/run-live-assessment.sh
```
```

- [ ] **Step 2: Create `run-live-assessment.sh`**

Write:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/.local/drs-assessment/live-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/responses" "$OUT/logs" "$OUT/benchmarks"

echo "DRS assessment output: $OUT"

cd "$ROOT"
pnpm --filter @okeyamy/drs-sdk --filter @drs/mcp-server build

cd "$ROOT/integration-tests"
DRS_VERIFY_IMAGE="${DRS_VERIFY_IMAGE:-ghcr.io/okeyamy/drs-verify:latest}" ./run.sh | tee "$OUT/logs/integration-tests.log"

echo "Integration evidence captured at $OUT/logs/integration-tests.log"
```

- [ ] **Step 3: Make the runner executable**

Run:

```bash
chmod +x scripts/assessment/run-live-assessment.sh
```

Expected: command exits 0.

## Task 4: Behavior Report Skeleton

**Files:**
- Create: `docs/audits/runtime-verification/results.md`

- [ ] **Step 1: Create the report template**

Write:

```markdown
# DRS Practical Behavior Report

## Evidence Standard

Each scenario records command, environment, request, status, response body, log excerpt, metric signal, expected behavior, observed behavior, and verdict.

## Scenario Results

| Scenario | Category | Expected | Observed | Evidence path | Verdict |
|---|---|---|---|---|---|
| S-verify-happy-path | Functional | Valid SDK-issued bundle returns valid verification. | See `results.md` current evidence row. | `.local/drs-assessment/live-*/responses/S-verify-happy-path.json` | Proven |
| S-live-chain-tamper | Data integrity | Tampered chain is rejected. | See `results.md` current evidence row. | `.local/drs-assessment/live-*/responses/S-live-chain-tamper.json` | Proven |
| S-live-receipt-signature-tamper | Data integrity / crypto | Mutated signed receipt is rejected. | See `results.md` current evidence row. | `.local/drs-assessment/live-*/responses/S-live-receipt-signature-tamper.json` | Proven |
| S-body-binding-mismatch | Security/data integrity | Verifier-only scenario reports `binding: "mismatch"`; middleware scenario rejects before handler execution. | See `results.md` current evidence rows. | `.local/drs-assessment/live-*/responses/S-body-binding-mismatch.json`, `S-middleware-handler-block.json` | Proven |
| S-live-replay | Security/replay | Reused invocation is rejected. | See `results.md` current evidence row. | `.local/drs-assessment/live-*/responses/S-live-replay.json` | Proven |
| S-live-admin-token | Authorization | Wrong admin token returns 401; correct token records revocation. | See `results.md` current evidence rows. | `.local/drs-assessment/live-*/responses/S-live-admin-revoke-*.json` | Proven |
```

## Task 5: Threat Model Skeleton

**Files:**
- Create: `docs/audits/runtime-verification/threat-model.md`

- [ ] **Step 1: Create STRIDE model**

Write:

```markdown
# DRS Practical Threat Model

## Scope

This threat model covers DRS source HEAD and deployed-like controlled environments. It does not cover attacks against third-party systems.

## STRIDE Matrix

| STRIDE | DRS concern | Practical scenario | Evidence requirement |
|---|---|---|---|
| Spoofing | forged issuer DID or wrong admin token | malformed DID, wrong revoke token | HTTP status, response body, logs |
| Tampering | modified JWT, chain hash, or request body | signature mutation, `prev_dr_hash` mutation, binding mismatch | rejected response and no handler execution |
| Repudiation | unclear audit trail | successful verification and revocation logs | log excerpt with no secrets |
| Information Disclosure | logs/metrics leak sensitive data | inspect `/metrics` and rejection logs | sanitized excerpts |
| Denial of Service | oversized body, resolver slow path, replay storm | bounded local workload | latency/error summary |
| Elevation of Privilege | policy escalation or Shape 2 body-binding gap | policy mutation, Shape 2 walkthrough | observed denial or documented limitation |
```

## Task 6: Benchmark Plan Skeleton

**Files:**
- Create: `docs/audits/runtime-verification/performance.md`
- Create: `docs/audits/runtime-verification/metadata.md`
- Create: `docs/audits/runtime-verification/evidence.md`

- [ ] **Step 1: Create benchmark evidence document**

Write:

```markdown
# DRS Benchmark Report

## Method

Benchmarks use real verifier paths in a controlled environment. Raw outputs stay in `.local/drs-assessment/benchmark-raw/`.

## Workloads

| Workload | Chain depth | DID mode | Nonce backend | Body binding | Metrics |
|---|---:|---|---|---|---|
| B-001 | 1 | did:key | memory | off | p50/p95/p99, throughput, errors |
| B-002 | 3 | did:key | memory | off | p50/p95/p99, throughput, errors |
| B-003 | 10 | did:key | memory | off | p50/p95/p99, throughput, errors |
| B-004 | 1 | did:key | Redis | off | p50/p95/p99, throughput, errors |
| B-005 | 1 | did:key | Redis | on | p50/p95/p99, throughput, errors |

## Results

No benchmark results have been recorded yet.
```

## Task 7: Persona Examples Skeleton

**Files:**
- Create: `docs/audits/runtime-verification/personas/README.md`

- [ ] **Step 1: Create persona index**

Write:

```markdown
# DRS Persona Examples

Each persona example must be backed by a real controlled-environment run, not mocked behavior.

| Persona | Question answered | Required evidence |
|---|---|---|
| SDK integrator | How do I issue receipts and submit a bundle? | SDK command/script and `/verify` response |
| Node middleware integrator | How does body binding protect my handler? | middleware run showing handler executes once and rejects tamper |
| Go verifier operator | How do I deploy and monitor verifier health? | Docker logs, health/readiness, metrics |
| MCP/A2A builder | Which integration shape is safe for execution integrity? | Shape 1 pass and Shape 2 limitation walkthrough |
| Auditor | How do I reconstruct evidence? | bundle, chain hash, verification response |
| Security engineer | What abuse cases were tested? | threat model and runtime results links |
| Product evaluator | What is production-ready and what is pilot-only? | readiness mapping and risk register |
```

## Task 8: Verification Commands

**Files:**
- No new files

- [ ] **Step 1: Verify docs and scripts exist**

Run:

```bash
test -f docs/audits/runtime-verification/scope.md
test -f docs/audits/runtime-verification/workplan.md
test -x scripts/assessment/run-live-assessment.sh
```

Expected: all commands exit 0.

- [ ] **Step 2: Run lightweight syntax checks**

Run:

```bash
bash -n scripts/assessment/run-live-assessment.sh
grep -R "mock evidence accepted\|fake proof accepted" docs/audits/runtime-verification scripts/assessment || true
```

Expected: `bash -n` exits 0; grep returns no language that permits fake proof as final evidence.
