# Persona Walkthrough Runbook

## Purpose

Capture practical evidence for SDK issuance, verifier acceptance, policy denial,
audit context, and body-binding mismatch using real local DRS components.

## Command

```bash
pnpm --filter drs-persona-walkthrough test
pnpm --filter drs-persona-walkthrough capture -- .local/drs-assessment/responses
pnpm --filter drs-persona-walkthrough start
```

## Expected Results

- Valid `lookup_customer` invocation returns `valid: true` and `binding: "match"`.
- Valid `draft_reply` invocation exposes human consent and regulatory context.
- Forbidden `refund_customer` invocation returns `POLICY_VIOLATION`.
- Tampered request body returns `binding: "mismatch"`.

## Raw Evidence Path

Use the assessment runner to capture raw logs:

```bash
scripts/assessment/run-live-assessment.sh
```

Raw logs are written under `.local/drs-assessment/live-*/logs/`.
Structured verifier request/response evidence is written under
`.local/drs-assessment/live-*/responses/`.

## Sanitized Report Destination

Summarize results in:

- `docs/audits/runtime-verification/results.md`
- `docs/audits/runtime-verification/claims.md`

## Cleanup

No secrets are committed. Remove local raw outputs when no longer needed:

```bash
rm -rf .local/drs-assessment/live-YYYYMMDDTHHMMSSZ
```
