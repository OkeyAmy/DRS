# Metadata Assessment Runbook

## Purpose

Validate that DRS metadata examples use canonical ids and that the assessment
does not convert asserted metadata into compliance claims.

## Commands

```bash
pnpm --filter drs-persona-walkthrough test
pnpm --filter drs-persona-walkthrough capture -- .local/drs-assessment/responses
```

## Expected Results

- `metadata.test.ts` accepts canonical ids such as `eu-ai-act-art12` and
  `soc2-security`.
- `metadata.test.ts` rejects display labels such as `EU AI Act` and `SOC 2`
  when used as raw metadata ids.
- Capture files include `metadataValidation.valid: true` for valid verifier
  scenarios.
- Capture files include an external-truth warning that DRS does not prove legal
  compliance or certification.

## Evidence Paths

- `examples/drs-persona-walkthrough/src/metadata.test.ts`
- `.local/drs-assessment/live-*/responses/*.json`
- `docs/audits/runtime-verification/metadata.md`
