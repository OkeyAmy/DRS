# Configuration Reference

All configuration is via environment variables. No hard-coded URLs, ports, or keys in any DRS component.

## drs-verify environment variables

| Variable | Default | Description |
|---|---|---|
| `DRS_LISTEN_ADDR` | `:8080` | HTTP listen address (e.g. `0.0.0.0:8080`, `:8443`) |
| `DRS_CACHE_SIZE` | `10000` | LRU DID resolver cache maximum entries. Hard cap — entries are evicted when full. |
| `DRS_CACHE_TTL` | `1h` | DID resolver cache entry TTL. Format: `30s`, `5m`, `1h`, `24h`. |
| `DRS_STATUS_CACHE_TTL` | `5m` | Bitstring Status List cache TTL. Revocations take effect within this window. |
| `DRS_REQUIRE_BUNDLE` | `false` | When `true`, requests to `/mcp/*` without `X-DRS-Bundle` header return `403`. |
| `DRS_UPSTREAM` | — | When set, drs-verify acts as a reverse proxy to this URL (sidecar mode). |
| `DRS_STORAGE_TIER` | `0` | Receipt storage tier: `0`=memory, `1`=filesystem, `2`=S3, `3`=WORM S3, `4`=on-chain. |
| `DRS_S3_BUCKET` | — | S3 bucket name (required for tier 2–3). |
| `DRS_S3_REGION` | `us-east-1` | AWS region for S3 bucket. |
| `DRS_S3_WORM_POLICY` | `false` | Enable S3 Object Lock (WORM) — required for tier 3. |
| `DRS_RETENTION_DAYS` | `0` | Receipt retention in days. `0` = indefinite. Used for tier 3 WORM policy. |
| `DRS_ADMIN_TOKEN` | — | Bearer token required for `/admin/*` endpoints. |

## drs-sdk CLI environment variables

| Variable | Default | Description |
|---|---|---|
| `DRS_VERIFY_URL` | — | drs-verify base URL used by `drs verify` and `VerifyClient`. |

## OperatorConfig fields

See [Operator Configuration](../how-to/operators/operator-config.md) for the full OperatorConfig JSON schema and field descriptions.

## Docker Compose example

```yaml
version: '3.8'
services:
  drs-verify:
    image: ghcr.io/yourorg/drs-verify:latest
    ports:
      - "8080:8080"
    environment:
      DRS_LISTEN_ADDR: ":8080"
      DRS_CACHE_SIZE: "10000"
      DRS_CACHE_TTL: "1h"
      DRS_STATUS_CACHE_TTL: "5m"
      DRS_REQUIRE_BUNDLE: "true"
      DRS_STORAGE_TIER: "2"
      DRS_S3_BUCKET: "my-drs-receipts"
      DRS_S3_REGION: "eu-west-1"
    secrets:
      - aws_credentials

secrets:
  aws_credentials:
    file: ./aws-credentials
```
