# Export Evidence for EU AI Act

DRS provides a dedicated export format for EU AI Act compliance evidence. The export covers Article 12 (record-keeping) and Article 13 (transparency) requirements.

## Export command

```bash
pnpm exec drs audit export \
  --inv-jti "inv:7h5c4d3e-..." \
  --format eu-ai-act \
  --output eu-ai-act-evidence.json
```

## What the export contains

```json
{
  "export_format": "eu-ai-act",
  "export_timestamp": "2026-03-30T10:00:00Z",
  "article_12_evidence": {
    "delegation_chain": [
      {
        "receipt_index": 0,
        "type": "root-delegation",
        "issuer": "did:key:z6MkHuman...",
        "audience": "did:key:z6MkAgent1...",
        "issued_at": "2026-03-28T10:30:00Z",
        "valid_until": "2026-05-28T10:30:00Z",
        "policy_summary": "web_search only, max £50",
        "signature_valid": true,
        "jwt": "<root-dr-jwt>"
      }
    ],
    "invocation": {
      "type": "invocation-receipt",
      "issuer": "did:key:z6MkAgent2...",
      "tool": "web_search",
      "args_summary": "query: Monad TPS benchmarks",
      "cost_usd": 0.02,
      "signature_valid": true,
      "jwt": "<invocation-jwt>"
    },
    "chain_verification": {
      "all_signatures_valid": true,
      "chain_intact": true,
      "no_revocations": true,
      "blocks_passed": ["A", "B", "C", "D", "E", "F"]
    }
  },
  "article_13_evidence": {
    "consent_record": {
      "method": "explicit-ui-click",
      "timestamp": "2026-03-28T10:30:00Z",
      "locale": "en-GB",
      "policy_hash": "sha256:a1b2c3...",
      "policy_text_shown_to_user": "Research Agent wants permission to:\n✓  Search the web\n✗  Cannot spend more than £50.00"
    }
  }
}
```

## Submitting the evidence

Submit `eu-ai-act-evidence.json` to:
- Your internal compliance officer for review
- The notified body conducting a conformity assessment
- The national market surveillance authority if requested

The evidence is self-contained — no operator cooperation is needed to authenticate it. All signatures are verifiable from the public keys encoded in the DIDs.

## Batch export

For a date range of invocations:

```bash
pnpm exec drs audit export \
  --subject "did:key:z6MkHuman..." \
  --date-range "2026-01-01/2026-03-31" \
  --format eu-ai-act \
  --output q1-2026-eu-ai-act.json
```
