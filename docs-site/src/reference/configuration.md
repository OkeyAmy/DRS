# Configuration Reference

All configuration is via environment variables. No hard-coded URLs, ports, or keys in any DRS component.

## drs-verify environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address (e.g. `0.0.0.0:8080`, `:443`) |
| `TLS_CERT_FILE` | — | Path to the PEM server certificate. Set **both** `TLS_CERT_FILE` and `TLS_KEY_FILE` to serve HTTPS directly. Setting only one fails fast at startup. When neither is set, the server listens on plain HTTP and should be fronted by a TLS-terminating proxy. |
| `TLS_KEY_FILE` | — | Path to the PEM private key matching `TLS_CERT_FILE`. |
| `DID_CACHE_SIZE` | `10000` | LRU DID resolver cache maximum entries. Hard cap — entries are evicted when full (~640 KB at 10 000 entries). |
| `DID_CACHE_TTL_SECS` | `3600` | DID resolver cache entry TTL in seconds. |
| `STATUS_LIST_BASE_URL` | — | W3C Bitstring Status List endpoint base URL. Required for remote revocation (Block F). |
| `STATUS_CACHE_TTL_SECS` | `300` | Bitstring Status List cache TTL in seconds. Revocations take effect within this window. |
| `MAX_BODY_BYTES` | `1048576` | Maximum request body size in bytes for `/verify` (default 1 MiB). |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, or `error`. |
| `LOG_FORMAT` | `text` | Log format: `text` or `json`. Use `json` for log aggregation. |
| `SERVER_IDENTITY` | — | This verifier's DID or server identifier. When set, `/verify` rejects invocations whose `tool_server` does not match (`TOOL_SERVER_MISMATCH`). **When unset, the verifier is fail-closed:** any invocation that names a `tool_server` is still rejected, because a bundle minted for server A must not verify on a server B that simply left this unset (cross-server replay). Leave unset only if no issuer ever sets `tool_server`. |
| `DRS_ADMIN_TOKEN` | — | Bearer token required for `POST /admin/revoke`. **If not set, the endpoint responds 503.** No default — set explicitly to enable. |
| `REVOCATION_STORE_PATH` | — | Optional file path for durable local `/admin/revoke` state. Empty uses in-memory local revocation only. |
| `NONCE_STORE_BACKEND` | `memory` | Replay-protection backend: `memory` for single-process deployments, `redis` for restart-safe and multi-replica deployments. **`memory` is refused at boot when `TRUST_PROXY=true`** — a proxied deployment is presumed multi-instance, and a per-process store cannot deduplicate JTIs across instances. |
| `NONCE_STORE_MAX_ENTRIES` | `100000` | Maximum number of invocation JTIs held in the replay-protection store. |
| `NONCE_STORE_TTL_SECS` | `900` | TTL in seconds for nonce store entries. Also bounds the invocation replay window: an invocation older than this is rejected as `INVOCATION_STALE`. Raise it only if legitimate invocation latency can exceed 15 minutes. |
| `REDIS_URL` | — | Required when `NONCE_STORE_BACKEND=redis`. Supports `redis://` and `rediss://` URLs. |
| `CIRCUIT_BREAKER_THRESHOLD` | `5` | Consecutive `did:web` resolution failures before the circuit opens for that DID. |
| `CIRCUIT_BREAKER_COOLDOWN_SECS` | `60` | Seconds to wait before allowing a probe request through an open `did:web` circuit. |
| `TRUST_PROXY` | `false` | When `true`, rate limiting uses the rightmost `X-Forwarded-For` entry. Enable only behind a trusted reverse proxy. Requires `NONCE_STORE_BACKEND=redis` — the server refuses to boot with the memory nonce store. |
| `RATE_LIMIT_PER_IP` | `100` | Sustained requests per second per client IP. |
| `RATE_LIMIT_GLOBAL` | `1000` | Sustained requests per second across all clients. |
| `STORE_DIR` | — | Base directory for the filesystem store. Empty = Tier 0 in-memory (dev/test). Set to select Tier 1 (local filesystem). Ignored when `S3_BUCKET` is also set — S3 wins. |
| `STORE_TTL_SECS` | `172800` | Tier-1 (local filesystem) receipt retention in seconds (default 48 h). Must be > 0. **Tier 3 ignores this value — compliance evidence stored under Object Lock is never auto-deleted by the application.** |
| `S3_ENDPOINT` | — | S3-compatible host and port (e.g. `s3.amazonaws.com`, `minio:9000`). Required when `S3_BUCKET` is set. |
| `S3_BUCKET` | — | Bucket name. Setting this variable selects Tier 2 or Tier 3 (durable S3 backend). Requires `S3_ENDPOINT`, `S3_ACCESS_KEY`, and `S3_SECRET_KEY` — the server fails to boot if any are missing. **For Tier 3 the bucket must be created with Object Lock enabled at the bucket level before first use.** |
| `S3_ACCESS_KEY` | — | S3 access key credential. Required when `S3_BUCKET` is set. |
| `S3_SECRET_KEY` | — | S3 secret key credential. Required when `S3_BUCKET` is set. |
| `S3_REGION` | `us-east-1` | S3 region. |
| `S3_USE_SSL` | `false` | Set to `true` to use HTTPS for S3 connections. |
| `S3_OBJECT_LOCK` | `false` | Set to `true` to enable WORM Object Lock retention on every write. **Required for Tier 3** — the server fails to boot if `TSA_URL` is set without `S3_OBJECT_LOCK=true`. |
| `S3_RETENTION_DAYS` | `2555` | Object Lock retention period applied per object when `S3_OBJECT_LOCK=true` (~7 years). |
| `ASYNC_QUEUE_SIZE` | `4096` | Async write pipeline queue depth. Writes to the S3 backend are non-blocking on the verify path; this is the maximum number of pending writes before back-pressure is applied. |
| `ASYNC_WORKERS` | `4` | Number of async flush workers draining the write queue to S3. |
| `TSA_URL` | — | RFC 3161 Timestamp Authority endpoint. Requires `S3_BUCKET` + `S3_OBJECT_LOCK=true` (Tier 3). The server fails to boot if `TSA_URL` is set without a durable WORM backend. Providers: `https://freetsa.org/tsr` (free), `https://timestamp.digicert.com`. |
| `TSA_ROOT_CERT_PEM` | — | Optional PEM root pool for RFC 3161 timestamp verification. Empty uses system roots. |

**Tier selection** is determined by which env vars are set at boot:

| Tier | Condition | Behaviour |
|---|---|---|
| **0 — memory** | No `STORE_DIR`, no `S3_BUCKET` | In-memory LRU only. Dev/test. Receipts lost on restart. |
| **1 — filesystem** | `STORE_DIR` set, no `S3_BUCKET` | Local filesystem, `STORE_TTL_SECS` retention, background janitor for expired receipts. Reads are integrity-verified. |
| **2 — S3 durable** | `S3_BUCKET` set, no `TSA_URL` | Durable S3 object store. Writes are async and non-blocking on the verify path. Reads are integrity-verified. |
| **3 — S3 WORM + RFC 3161** | `S3_BUCKET` + `TSA_URL` (+ `S3_OBJECT_LOCK=true` required) | Durable S3 with Object Lock (WORM) and RFC 3161 timestamps. Compliance evidence is immutable; `STORE_TTL_SECS` is ignored. Disposition is governed entirely by the bucket's Object Lock retention and lifecycle policy. |

If both `S3_BUCKET` and `STORE_DIR` are set, **S3 wins**.
| `METRICS_ADDR` | — | Listen address for the separate Prometheus `/metrics` endpoint (e.g. `:9090` for dev, `127.0.0.1:9090` for production). Empty disables the metrics endpoint. Served on its own listener so it can be firewalled independently of the main API port. |

## drs-sdk CLI environment variables

| Variable | Default | Description |
|---|---|---|
| `DRS_VERIFY_URL` | — | drs-verify base URL used by `drs verify` and `VerifyClient`. |

## Example configurations

```bash
# Tier 0 — in-memory (development default)
LISTEN_ADDR=:8080 ./drs-verify

# Tier 1 — filesystem store (dev/staging)
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  STORE_TTL_SECS=172800 \
  STATUS_LIST_BASE_URL=https://status.example.com \
  ./drs-verify

# Tier 2 — durable S3 object store
LISTEN_ADDR=:8080 \
  S3_ENDPOINT=s3.amazonaws.com \
  S3_BUCKET=drs-receipts \
  S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
  S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  S3_REGION=us-east-1 \
  S3_USE_SSL=true \
  STATUS_LIST_BASE_URL=https://status.example.com \
  ./drs-verify

# Tier 3 — S3 WORM + RFC 3161 timestamp anchor (regulated deployments)
# The bucket MUST be created with Object Lock enabled at the bucket level.
LISTEN_ADDR=:8080 \
  S3_ENDPOINT=s3.amazonaws.com \
  S3_BUCKET=drs-receipts-worm \
  S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
  S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  S3_REGION=us-east-1 \
  S3_USE_SSL=true \
  S3_OBJECT_LOCK=true \
  S3_RETENTION_DAYS=2555 \
  TSA_URL=https://freetsa.org/tsr \
  DRS_ADMIN_TOKEN=your-secret-token \
  STATUS_LIST_BASE_URL=https://status.example.com \
  ./drs-verify

# Direct HTTPS (no TLS-terminating proxy in front)
LISTEN_ADDR=:443 \
  TLS_CERT_FILE=/etc/drs/tls/server.crt \
  TLS_KEY_FILE=/etc/drs/tls/server.key \
  ./drs-verify
```

## Docker Compose example

```yaml
version: '3.8'
services:
  drs-verify:
    image: ghcr.io/okeyamy/drs-verify:latest
    ports:
      - "8080:8080"
    environment:
      LISTEN_ADDR: ":8080"
      DID_CACHE_SIZE: "10000"
      DID_CACHE_TTL_SECS: "3600"
      STATUS_LIST_BASE_URL: "https://status.example.com"
      STATUS_CACHE_TTL_SECS: "300"
      DRS_ADMIN_TOKEN: "${DRS_ADMIN_TOKEN}"
      REVOCATION_STORE_PATH: "/data/revoked.log"
      NONCE_STORE_BACKEND: "memory"
      SERVER_IDENTITY: "did:key:z6MkToolServer..."
      STORE_DIR: "/data"
      TSA_URL: "https://freetsa.org/tsr"
    volumes:
      - drs-data:/data

volumes:
  drs-data:
```

The published image is distroless, so container-internal shell healthcheck commands such as `wget` or `curl` are not available. Probe `/healthz` and `/readyz` from Docker, Kubernetes, or your external load balancer instead.
