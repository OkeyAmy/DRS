# Storage Tiers

DRS uses a six-tier storage model. The canonical reference lives in
`docs/storage-tiers.md`; this page summarizes it and highlights what is actually
implemented today.

## Tier reference

| Tier | Name | Backend | Env vars | Status |
|---|---|---|---|---|
| 0 | Session | In-memory | *(none)* | Implemented |
| 1 | Ephemeral | Local filesystem | `STORE_DIR` | Implemented |
| 2 | Durable | S3-compatible object store | roadmap | Not implemented |
| 3 | Compliant | Filesystem + RFC 3161 timestamping | `STORE_DIR` + `TSA_URL` | Partially implemented |
| 4 | Timestamped | Tier 3 deployment posture with timestamp retrieval/reporting | `STORE_DIR` + `TSA_URL` | Partially implemented |
| 5 | On-chain | Tier 3 + Ethereum anchor | roadmap | Not implemented |

## What is actually implemented today

**Tier 0:** default when `STORE_DIR` is unset. Receipts are lost on restart.

**Tier 1:** receipts are written to the local filesystem and survive restart.

**Tier 2:** documented target only. There is no S3-compatible store in the
current codebase.

**Tier 3:** when `TSA_URL` is set, `drs-verify` stores the receipt and attempts
RFC 3161 timestamping. This is best-effort:

- the receipt is still stored if the TSA is unavailable
- the timestamp is stored alongside the receipt when available
- WORM semantics are not enforced by the current filesystem backend

**Tier 4:** same backend as Tier 3. Today this is a reporting / operator posture
rather than a separate storage engine.

**Tier 5:** Ethereum anchoring is a roadmap item, not a delivered feature.

## Configuration

```bash
# Tier 0 — session / in-memory
LISTEN_ADDR=:8080 ./drs-verify

# Tier 1 — filesystem
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  ./drs-verify

# Tier 3 / Tier 4 — filesystem + RFC 3161 timestamping
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  TSA_URL=https://freetsa.org/tsr \
  ./drs-verify
```

For the full canonical model, caveats, and tier semantics, see
[Canonical Storage Tiers](../../../docs/storage-tiers.md).
