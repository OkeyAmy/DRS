# Go Verifier Operator Review

This review is for operators running `drs-verify` as a sidecar or standalone
verification service.

## Operator-Safe Summary

The local source-tree verifier is proven for `/verify`, `/admin/revoke`,
`/metrics`, package tests, and security abuse scenarios. Container startup,
Compose networking, Redis-backed replay, and published-image parity are not
proven in this local environment because Docker Compose fails before services
start.

## Proven Local Operator Surfaces

| Surface | Evidence | Operational meaning |
|---|---|---|
| `/verify` | `results.md`, `S-live-verify-happy-path.json` | Valid bundles verify through the Go HTTP service. |
| Malformed `/verify` request | `results.md`, `S-live-malformed-verify-body.json` | Malformed JSON is rejected with HTTP `400`. |
| Replay protection | `results.md`, `S-live-replay.json` | Reused invocation JTI returns HTTP `409` locally. |
| `/admin/revoke` auth | `results.md`, `S-live-admin-revoke-wrong-token.json` | Wrong bearer token is denied. |
| `/admin/revoke` effect | `results.md`, `S-live-admin-revoke-correct-token-and-reject.json` | Authorized revocation causes later verification to return `REVOKED`. |
| `/metrics` | `results.md`, `S-live-metrics.json` | Metrics listener exposes Prometheus counters when `METRICS_ADDR` is set. |
| Go package behavior | `evidence.md`, `logs/go-tests.log` | Verifier packages pass unit/integration package tests. |

## Required Configuration Review

| Variable | Product decision | Audit status |
|---|---|---|
| `LISTEN_ADDR` | Bind verifier HTTP endpoint. | Proven in local runner with loopback port. |
| `METRICS_ADDR` | Bind metrics listener or leave disabled. | Proven in local runner with loopback metrics port. |
| `DRS_ADMIN_TOKEN` | Required for `/admin/revoke`. | Proven: wrong token denied, correct token accepted. |
| `NONCE_STORE_BACKEND` | `memory` for single process; `redis` for shared replay. | Memory proven locally; Redis deployment blocked locally. |
| `REDIS_URL` | Required when Redis nonce backend is selected. | Not proven locally. |
| `REVOCATION_STORE_PATH` | Needed for file-backed local revocation durability. | Package tests pass; local live runner uses in-memory revocation. |
| `STATUS_LIST_BASE_URL` | Required for remote status-list revocation. | Package tests pass; live remote status-list scenario not run. |

## Operator Runbook Gap

No Docker/operator runbook is marked proven in this audit. The runbook remains
blocked until the local Docker Compose failure is fixed or CI supplies equivalent
evidence.

Blocked command:

```bash
cd integration-tests
./run.sh
```

Observed blocker:

```text
docker.errors.DockerException: Error while fetching server API version: Not supported URL scheme http+docker
```

## Operator Recommendation

For a controlled pilot, operate `drs-verify` with loopback/private-network
listeners, explicit `DRS_ADMIN_TOKEN`, deployment-specific replay backend choice,
and documented revocation durability. Do not use this audit to claim published
image or multi-replica Redis behavior until those runs produce evidence.
