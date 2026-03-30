# Revocation

DRS supports two revocation mechanisms that work together:

1. **Remote Bitstring Status List** — W3C standard; fetched from `STATUS_LIST_BASE_URL` with a configurable TTL cache (default 5 minutes). Revocations take effect within the cache window.
2. **Local revocation store** — in-memory; updated immediately via `POST /admin/revoke`. Takes effect on the next request. Does not survive process restart.

Both are checked in Block F of `verify_chain`. A DR is revoked if its `drs_status_list_index` is marked in either source.

## Revoking a delegation (immediate effect)

The local revocation store takes effect on the next verification request — no cache window:

```bash
curl -X POST http://localhost:8080/admin/revoke \
  -H "Authorization: Bearer $DRS_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status_list_index": 42}'

# Response: {"revoked":true,"status_list_index":42}
```

`DRS_ADMIN_TOKEN` must be set as an environment variable. If not set, the endpoint responds 503:
```json
{"error": "admin endpoint not configured — set DRS_ADMIN_TOKEN"}
```

> **Note:** The local revocation store is in-memory. Revocations are lost on process restart. For durable revocation that survives restarts, update the W3C Bitstring Status List served at `STATUS_LIST_BASE_URL`.

## Revoking via the remote Bitstring Status List

To revoke durably (surviving restarts and across multiple drs-verify instances), update the W3C Bitstring Status List at the URL configured in `STATUS_LIST_BASE_URL`. drs-verify fetches and caches this list; the TTL is `STATUS_CACHE_TTL_SECS` (default 300 seconds / 5 minutes).

## Reducing the cache window

For deployments where faster remote revocation propagation is needed:

```bash
STATUS_CACHE_TTL_SECS=30 ./drs-verify
```

Setting this too low increases load on the status list endpoint. 300 seconds is appropriate for most deployments. For emergency revocations, use `POST /admin/revoke` for immediate effect alongside updating the remote list.

## How Block F works

```
for each DR in bundle:
  if DR.drs_status_list_index is set:
    if remote_status_list.is_revoked(DR.drs_status_list_index):
      return RECEIPT_REVOKED
    if local_revocation_store.is_revoked(DR.drs_status_list_index):
      return RECEIPT_REVOKED
```

## Status list cache concurrency

The status list cache uses `sync.Once` internally to prevent double-fetch race conditions under concurrent load. When the cache expires and multiple goroutines arrive simultaneously, only one HTTP request is made — all others wait and reuse the result.
