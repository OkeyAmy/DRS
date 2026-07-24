# Storage Tiers

DRS uses a four-tier storage model. The tier is selected automatically at boot based
on which environment variables are set — no code changes are required to move between
tiers.

## Tier reference

| Tier | Name | Backend | Env vars required | Writes | Retention |
|---|---|---|---|---|---|
| **0** | Memory | In-process LRU | *(none)* | Synchronous | Lost on restart |
| **1** | Filesystem | Local disk | `STORE_DIR` | Synchronous | `STORE_TTL_SECS` (default 48 h), janitor-swept |
| **2** | S3 durable | S3-compatible object store | `S3_BUCKET` (+ endpoint + credentials) | Async, non-blocking | Governed by S3 lifecycle policy |
| **3** | S3 WORM + RFC 3161 | S3 Object Lock + Timestamp Authority | `S3_BUCKET` + `TSA_URL` + `S3_OBJECT_LOCK=true` | Async, non-blocking | Immutable — Object Lock retention/lifecycle only |

**Tier selection rule:** if `S3_BUCKET` is set, S3 wins over `STORE_DIR`. Tier 3
activates when both `S3_BUCKET` and `TSA_URL` are set.

## Tier details

### Tier 0 — Memory (dev/test)

Default when neither `STORE_DIR` nor `S3_BUCKET` is set. Receipts are held in an
in-process LRU cache and are lost on restart. Suitable for local development and
unit test fixtures only.

### Tier 1 — Filesystem (dev/staging)

Receipts are written to the directory named by `STORE_DIR` and survive restart.
Reads are integrity-verified against the stored hash. A background janitor sweeps
expired entries based on `STORE_TTL_SECS` (default 172800 s / 48 h). This is a
dev and staging posture — the local filesystem is not durable across host failure
and is not appropriate for production compliance requirements.

### Tier 2 — S3 durable

Receipts are written to an S3-compatible object store. Writes are asynchronous and
non-blocking on the verify path — the `/verify` response is returned before the
write completes. A bounded async queue (`ASYNC_QUEUE_SIZE`, default 4096) and a
pool of flush workers (`ASYNC_WORKERS`, default 4) drain writes in the background.
Reads are integrity-verified.

This tier is appropriate for production deployments where durability and availability
matter but regulatory immutability is not required.

### Tier 3 — S3 WORM + RFC 3161 (compliance)

Tier 3 combines S3 Object Lock (WORM) with RFC 3161 trusted timestamping to produce
tamper-evident, immutable compliance evidence.

**Key properties:**

- Every receipt is written with an Object Lock retention hold
  (`S3_RETENTION_DAYS`, default 2555 — approximately 7 years).
- An RFC 3161 timestamp token is requested from `TSA_URL` and stored alongside the
  receipt. The timestamp proves the receipt existed before a given point in time
  under a trusted third-party signature.
- **Compliance evidence is never auto-deleted by the application.** `STORE_TTL_SECS`
  is ignored at Tier 3. Disposition — when and how receipts may eventually be
  deleted — is governed entirely by the bucket's Object Lock retention period and
  lifecycle policy, not by drs-verify.
- `S3_DELETE` through the store API is a no-op while Object Lock is active;
  deletion requires an explicit legal-hold release or expiry of the retention period
  at the bucket level.

**Requirements:**

- The bucket **must** be created with Object Lock enabled at the bucket level before
  first use. Object Lock cannot be enabled on an existing bucket.
- `S3_OBJECT_LOCK=true` must be set. The server fails to boot if `TSA_URL` is set
  without it.
- The local filesystem backend (`STORE_DIR` without `S3_BUCKET`) is dev-only and
  does not provide WORM semantics. Tier 3 requires the durable S3 backend.

## Configuration examples

```bash
# Tier 0 — in-memory (development default)
LISTEN_ADDR=:8080 ./drs-verify

# Tier 1 — filesystem (dev/staging)
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  STORE_TTL_SECS=172800 \
  ./drs-verify

# Tier 2 — durable S3
LISTEN_ADDR=:8080 \
  S3_ENDPOINT=s3.amazonaws.com \
  S3_BUCKET=drs-receipts \
  S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
  S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  S3_USE_SSL=true \
  ./drs-verify

# Tier 3 — S3 WORM + RFC 3161 (regulated deployments)
# Create the bucket with Object Lock enabled BEFORE running this.
LISTEN_ADDR=:8080 \
  S3_ENDPOINT=s3.amazonaws.com \
  S3_BUCKET=drs-receipts-worm \
  S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE \
  S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  S3_USE_SSL=true \
  S3_OBJECT_LOCK=true \
  S3_RETENTION_DAYS=2555 \
  TSA_URL=https://freetsa.org/tsr \
  ./drs-verify
```

## Local MinIO (Tier 2 / Tier 3 development)

The integration-test compose file (`integration-tests/docker-compose.test.yml`)
includes a MinIO service on port `19000` for exercising the S3 path locally:

```bash
docker compose -f integration-tests/docker-compose.test.yml up minio

# Point drs-verify at it:
S3_ENDPOINT=localhost:19000 \
  S3_BUCKET=drs-test \
  S3_ACCESS_KEY=minioadmin \
  S3_SECRET_KEY=minioadmin \
  S3_USE_SSL=false \
  ./drs-verify
```

For the full environment-variable reference and boot-validation rules, see
[Configuration Reference](../../reference/configuration.md).
