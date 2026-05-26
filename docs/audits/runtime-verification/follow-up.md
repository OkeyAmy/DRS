# Follow-Up Work

This file records audit follow-up work as issue-ready items. It is not evidence
that the work is complete.

| Priority | Title | Why it matters | Evidence needed to close |
|---|---|---|---|
| P0 | Fix local Docker Compose audit environment | Docker, Redis, and published-image behavior cannot be proven while Compose fails with `Not supported URL scheme http+docker`. | `integration-tests/run.sh` exits 0 and captures `/healthz`, `/readyz`, `/metrics`, replay, and tamper responses. |
| P0 | Prove Redis replay across verifier instances | Local memory replay is proven, but multi-replica replay safety requires shared nonce state. | Two verifier instances sharing Redis reject the same invocation JTI across instances. |
| P1 | Add live Shape 2 JSON-RPC params-binding scenario | Shape 2 remains provenance-only until signed args are bound to JSON-RPC `params`. | Tampered JSON-RPC `params` are rejected before handler execution. |
| P1 | Add live A2A middleware walkthrough | Package tests are not a substitute for an operator-readable A2A runtime example. | A2A handler receives valid request once and is not called on tampered payload. |
| P1 | Add Docker operator runbook | Operators need container startup, readiness, metrics, and log evidence. | Runbook captures startup command, env vars, health/readiness, metrics, logs, and cleanup. |
| P1 | Add benchmark runner | No latency, throughput, or capacity claim is supported today. | Reproducible p50/p95/p99, throughput, error rate, environment details, and raw output. |
| P2 | Add live `did:web` controlled resolver scenario | SSRF protections are proven by Go tests but not by a live controlled server. | Local controlled `did:web` service proves allowed and blocked resolution paths. |
| P2 | Add file-backed revocation live scenario | Package tests cover file-backed revocation; the live runner uses memory revocation. | Restart verifier with `REVOCATION_STORE_PATH` and prove revocation persists. |
| P2 | Automate docs claim extraction | `claims.md` is manually reviewed; automation would reduce drift. | Script extracts candidate claims from public docs and links each to a claim row. |
