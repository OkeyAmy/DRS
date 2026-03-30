# Storage Tiers

DRS defines four storage tiers for delegation receipts, ordered by durability and compliance requirements.

## Tier reference

| Tier | Name | Backend | Env vars required | Use case |
|---|---|---|---|---|
| 0 | In-memory | LRU cache (process lifetime) | *(none — default)* | Development, testing |
| 1 | Filesystem | Local disk | `STORE_DIR` | Standard production |
| 3 | WORM + RFC 3161 | Filesystem + trusted timestamp | `STORE_DIR` + `TSA_URL` | Regulated deployments (HIPAA, EU AI Act, financial) |
| 4 | Blockchain | Tier 3 + on-chain anchor | *(not yet implemented)* | Blockchain-native enterprise opt-in |

> **Note on Tier 2:** There is no Tier 2 in the current implementation. S3 or other object storage backends are a roadmap item.

## When to use each tier

**Tier 0 (In-memory):** Default when `STORE_DIR` is not set. Receipts are lost on process restart. Use only for local development and tests.

**Tier 1 (Filesystem):** Set `STORE_DIR` to a directory path. Receipts are written as files and survive process restart. No compliance controls — suitable for production deployments where regulatory requirements do not mandate timestamping.

**Tier 3 (WORM + RFC 3161):** Set both `STORE_DIR` and `TSA_URL`. Every stored receipt is timestamped by an RFC 3161 Trusted Signing Authority (TSA). The TSA signs `SHA-256(DR bytes)` with the current time and returns a DER timestamp token. This token is stored alongside the DR.

RFC 3161 is an IETF standard from 2001. Timestamp tokens are legally recognised under EU eIDAS and in US federal courts. TSA failure is best-effort — if the TSA is unreachable, the receipt is still stored (Tier 1 semantics) and the error is logged. Storage is never blocked by TSA availability.

**Tier 4 (Blockchain):** Not implemented. When built, this will be an explicit opt-in for customers who require on-chain proof and understand the gas cost implications. The default anchor mechanism is RFC 3161 (Tier 3), not blockchain.

## Configuration

```bash
# Tier 0 — in-memory (default)
LISTEN_ADDR=:8080 ./drs-verify

# Tier 1 — filesystem
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  ./drs-verify

# Tier 3 — filesystem + RFC 3161 trusted timestamp
LISTEN_ADDR=:8080 \
  STORE_DIR=/data/drs \
  TSA_URL=https://freetsa.org/tsr \
  ./drs-verify
```

## TSA providers

| Provider | URL | Cost | Notes |
|---|---|---|---|
| FreeTSA | `https://freetsa.org/tsr` | Free | Non-commercial use; rate-limited |
| DigiCert | `https://timestamp.digicert.com` | Free (DigiCert customers) | Production-grade |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | Commercial | AATL/WebTrust certified |

## Why not blockchain by default?

The core DRS guarantees (tamper-evident receipts, Ed25519 signatures, hash-chained custody) require zero blockchain. The only problem blockchain was solving in the v1/v2 architecture was "immutable third-party timestamp" — and RFC 3161 solves that problem better:

| Property | RFC 3161 | Blockchain |
|---|---|---|
| User pays gas fees | No | Yes |
| Latency | ~200 ms | 400 ms–12 s |
| Legal recognition | EU eIDAS, US federal courts, ISO 18014 | Unclear / jurisdiction-dependent |
| Requires wallet / token | No | Yes |
| Battle-tested | 20+ years | 4 months–10 years depending on chain |
| Free tier | Yes (FreeTSA) | No |

Blockchain anchoring is available as Tier 4 for customers who specifically require it — for example, blockchain-native enterprises whose compliance teams are already comfortable with on-chain evidence. It is never the default.
