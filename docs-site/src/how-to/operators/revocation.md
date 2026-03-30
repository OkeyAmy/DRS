# Revocation

DRS uses the W3C Bitstring Status List specification for revocation. Revoked receipts fail Block F of `verify_chain`.

## How revocation works

1. When issuing a DR, optionally include a `drs_status_list_index` integer field
2. The issuer maintains a Bitstring Status List — a bitfield where each position corresponds to a JTI
3. To revoke a DR, set the bit at its `drs_status_list_index` to `1`
4. drs-verify fetches the status list (5-minute TTL cache) and checks the bit at the DR's index
5. Bit `1` = revoked — verification fails with `RECEIPT_REVOKED`

## Revoking a delegation

Via the drs-verify admin API:

```bash
curl -X POST http://localhost:8080/admin/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jti": "dr:8f3a2b1c-4d5e-4xxx-8b9c-0d1e2f3a4b5c"}'

# Response: {"revoked": true, "jti": "dr:8f3a2b1c-..."}
```

## Cache window

Revocations take effect within 5 minutes (the default status list cache TTL). For high-security deployments that require faster revocation:

```bash
DRS_STATUS_CACHE_TTL=30s
```

Setting this too low increases load on the status list endpoint. For most deployments, 5 minutes is appropriate.

## Emergency revocation

For compromised keys, revoke all active delegations issued by the compromised key:

```bash
# Revoke all active DRs for a given issuer DID
curl -X POST http://localhost:8080/admin/revoke-by-issuer \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"issuer_did": "did:key:z6MkCompromised..."}'
```

After revoking, rotate the compromised key and issue new root delegations from the new key.

## Status list cache concurrency

The status list cache uses `sync.Once` internally to prevent double-fetch race conditions under concurrent load. When the cache expires and multiple requests arrive simultaneously, only one fetch is made — the others wait and use the result.
