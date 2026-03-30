# Regulatory Alignment

DRS is designed to produce evidence that satisfies the specific record-keeping requirements of AI governance regulations. The receipts are cryptographically signed and independently verifiable — an auditor does not need operator cooperation to authenticate the evidence.

## EU AI Act

**Article 12 — Record-keeping for high-risk AI systems**

Article 12 requires high-risk AI systems to automatically log events with sufficient detail to enable post-market monitoring and investigation. DRS Delegation Receipts satisfy this:
- **Tamper-evident:** Ed25519 signatures; any modification breaks verification
- **Independently verifiable:** Public keys are encoded in the DID — no central authority needed
- **Comprehensive:** Every delegation hop and every invocation is receipted

**Article 13 — Transparency**

Article 13 requires transparency in the operation of high-risk AI systems. DRS provides:
- Human-readable policy translation at the point of consent (the `drs_consent.policy_hash` covers the text the user saw — not just the machine-readable JSON)
- Complete chain reconstruction without operator involvement
- Per-invocation records linking every agent action to the authorising human

**Export:**
```bash
pnpm exec drs audit export --inv-jti "inv:..." --format eu-ai-act --output evidence.json
```

## HIPAA §164.312(b) — Audit Controls

For healthcare deployments handling PHI, HIPAA §164.312(b) requires audit controls that record and examine activity. DRS provides:
- Invocation Receipts recording every agent action with full delegation provenance
- Signed proof that access was authorised before it occurred (not just a log that it happened)
- Tier 3 (Compliant) storage with WORM policy and 7-year retention

## AIUC-1 Certification

AIUC (AI Underwriting Company, founded July 2025 with $15M seed) certifies AI systems for insurance underwriting. AIUC-1 requires demonstrable proof of authorisation for every agent action — not just server logs.

The AIUC-1 requirement: *"For any agent action, provide cryptographic proof that the action was within the scope of an authorisation granted by an identifiable principal."*

DRS Delegation Receipts satisfy this directly. AIUC-1 is identified as the primary near-term commercial opportunity for DRS-based deployments.

## SOC 2 Type II

SOC 2 requires continuous evidence of access controls. DRS provides:
- Signed receipts for every delegation grant (who authorised what, when, with what constraints)
- Tamper-evident chain linking every action to its authorisation
- Revocation mechanism for compromised keys

## FINOS AI Governance Framework

FINOS Tier 3–4 levels require chain-of-custody evidence admissible in legal proceedings. DRS Delegation Receipts are:
- Based on open standards (Ed25519, JWT, OAuth 2.1) — no proprietary formats
- Independently verifiable — no vendor lock-in for evidence authentication
- Exportable in structured formats

Relevant financial regulations: SR 11-7 (Federal Reserve model risk management), EBA Guidelines on ICT risk, GDPR Article 22 (automated decision-making explainability), MiFID II audit trails.

## Storage tiers and retention

| Tier | `storage_tier` | Backend | Retention | Use case |
|---|---|---|---|---|
| Session | `0` | In-memory | Process lifetime | Development, testing |
| Ephemeral | `1` | Local filesystem | Configurable TTL | Non-regulated production |
| Durable | `2` | S3 / GCS / Azure Blob | Configurable | Standard production |
| Compliant | `3` | WORM object storage | 7 years minimum | HIPAA, financial services |
| On-chain | `4` | Monad EVM | Permanent | Highest-assurance regulatory |

Configure via `storage_tier` in the [Operator Configuration](../how-to/operators/operator-config.md).
