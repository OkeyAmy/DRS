# HIPAA Audit Evidence

For healthcare deployments handling Protected Health Information (PHI), HIPAA §164.312(b) requires audit controls that record and examine activity in information systems containing PHI.

## What DRS provides for HIPAA

| HIPAA Requirement | DRS Mechanism |
|---|---|
| Record activity in PHI systems | Invocation Receipts — every agent action recorded and signed |
| Verify authorisation was granted before access | Delegation Receipts — signed proof of authorisation before invocation |
| Tamper-evident audit trail | Ed25519 signatures + `prev_dr_hash` chain |
| Independent auditability | `did:key` resolution — no central authority needed |
| Retention (7 years minimum) | Tier 3 storage — WORM-enabled with configurable retention |

## Retrieving evidence for a HIPAA audit

```bash
# Retrieve all invocations by an agent that touched PHI systems
pnpm exec drs audit retrieve \
  --tool-server "did:key:z6MkPHISystem..." \
  --date-range "2026-01-01/2026-03-31" \
  --output hipaa-audit-trail.json

# Verify the entire set
pnpm exec drs verify hipaa-audit-trail.json

# Print human-readable audit trail
pnpm exec drs audit hipaa-audit-trail.json
```

## Required storage configuration for HIPAA

PHI-touching deployments must use Tier 3 storage:

```bash
DRS_STORAGE_TIER=3
DRS_S3_WORM_POLICY=true
DRS_RETENTION_DAYS=2555    # 7 years = 365 × 7
```

Or in `OperatorConfig`:
```json
{
  "storage_tier": 3,
  "drs_regulatory": {
    "frameworks": ["hipaa-164.312b"],
    "retention_days": 2555
  }
}
```

## Demonstrating authorisation for BAA compliance

Under a Business Associate Agreement (BAA), you must demonstrate that agent access to PHI was:
1. Authorised by an identified individual (the `iss` of the root DR, with valid signature)
2. Within the scope of the authorisation (Block D policy compliance)
3. Logged with a tamper-evident record (the signed invocation receipt)

```bash
# Export HIPAA evidence for a specific invocation
pnpm exec drs audit export \
  --inv-jti "inv:7h5c4d3e-..." \
  --format hipaa \
  --output hipaa-single-event.json
```

The output includes: delegation chain with signatures, invocation record, verification result, and retention metadata.
