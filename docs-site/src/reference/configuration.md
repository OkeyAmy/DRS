# Configuration Reference

All configuration is via environment variables. No hard-coded URLs, ports, or keys in any DRS component.

## drs-verify environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | HTTP listen address (e.g. `0.0.0.0:8080`, `:443`) |
| `DID_CACHE_SIZE` | `10000` | LRU DID resolver cache maximum entries. Hard cap — entries are evicted when full (~640 KB at 10 000 entries). |
| `DID_CACHE_TTL_SECS` | `3600` | DID resolver cache entry TTL in seconds. |
| `STATUS_LIST_BASE_URL` | — | W3C Bitstring Status List endpoint base URL. Required for remote revocation (Block F). |
| `STATUS_CACHE_TTL_SECS` | `300` | Bitstring Status List cache TTL in seconds. Revocations take effect within this window. |
| `MAX_BODY_BYTES` | `1048576` | Maximum request body size in bytes for `/verify` (default 1 MiB). |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, or `error`. |
| `DRS_ADMIN_TOKEN` | — | Bearer token required for `POST /admin/revoke`. **If not set, the endpoint responds 503.** No default — set explicitly to enable. |
| `STORE_DIR` | — | Base directory for the filesystem store. Empty = Tier 0 in-memory (dev/test). Set for Tier 1 or Tier 3. |
| `TSA_URL` | — | RFC 3161 Timestamp Authority endpoint. Enables Tier 3 trusted timestamping **only when `STORE_DIR` is also set** — if `STORE_DIR` is empty, `TSA_URL` is silently ignored and the server falls back to Tier 0 (in-memory). Providers: `https://freetsa.org/tsr` (free), `https://timestamp.digicert.com`. |

## drs-sdk CLI environment variables

| Variable | Default | Description |
|---|---|---|
| `DRS_VERIFY_URL` | — | drs-verify base URL used by `drs verify` and `VerifyClient`. |

## Example configurations

```bash
# Tier 0 — in-memory (development default)
LISTEN_ADDR=:8080 ./drs-verify

# Tier 1 — filesystem store
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  STATUS_LIST_BASE_URL=https://status.example.com \
  ./drs-verify

# Tier 3 — filesystem + RFC 3161 timestamp anchor (regulated deployments)
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  TSA_URL=https://freetsa.org/tsr \
  DRS_ADMIN_TOKEN=your-secret-token \
  STATUS_LIST_BASE_URL=https://status.example.com \
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
      STORE_DIR: "/data"
      TSA_URL: "https://freetsa.org/tsr"
    volumes:
      - drs-data:/data
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/healthz"]
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  drs-data:
```
