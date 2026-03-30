# Storage Tiers

DRS defines five storage tiers for delegation receipts, ordered by durability and compliance requirements.

## Tier reference

| Tier | `storage_tier` | Backend | Retention | Use case |
|---|---|---|---|---|
| Session | `0` | In-memory | Process lifetime | Development, testing |
| Ephemeral | `1` | Local filesystem | Configurable TTL | Non-regulated production |
| Durable | `2` | S3 / GCS / Azure Blob | Configurable | Standard production |
| Compliant | `3` | WORM-enabled object storage | 7 years minimum | HIPAA, financial services, SOC 2 |
| On-chain | `4` | Monad EVM | Permanent | Highest-assurance regulatory, AIUC-1 |

## When to use each tier

**Tier 0 (Session):** Use only for local development and tests. Receipts are lost on process restart.

**Tier 1 (Ephemeral):** Non-regulated production deployments where receipts are needed for debugging and short-term audit but not long-term compliance. Configure TTL to match your operational requirements.

**Tier 2 (Durable):** Standard production. Object storage provides high durability and availability. No special compliance controls — suitable when regulatory requirements do not mandate WORM.

**Tier 3 (Compliant):** Required for HIPAA, SOC 2, financial services, and EU AI Act high-risk deployments. Uses WORM-enabled object storage (S3 Object Lock, Azure Blob Immutable Storage, GCS Bucket Lock). Minimum 7-year retention.

**Tier 4 (On-chain):** Permanent, publicly auditable. Receipts are anchored to the Monad EVM. Use when you need independent third-party auditability or when the evidence must be verifiable without any operator infrastructure.

## Configuration

```bash
# Tier 2 — Durable (S3)
DRS_STORAGE_TIER=2
DRS_S3_BUCKET=my-drs-receipts
DRS_S3_REGION=eu-west-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...

# Tier 3 — Compliant (WORM S3)
DRS_STORAGE_TIER=3
DRS_S3_BUCKET=my-drs-receipts-compliant
DRS_S3_WORM_POLICY=true
DRS_RETENTION_DAYS=2555    # 7 years
```

## Setting it in OperatorConfig

```json
{
  "storage_tier": 3
}
```

The tier is set once in the operator configuration and applies to all receipts issued by that operator.
