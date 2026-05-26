# DRS Assessment Scripts

These scripts run against real DRS components in a controlled environment. They
do not mock verifier responses or middleware behavior.

Raw outputs go under `.local/drs-assessment/` and must not be committed.
Sanitized summaries belong under `docs/audits/runtime-verification/`.

## First command

```bash
scripts/assessment/run-live-assessment.sh
```

The runner captures real verifier request/response JSON files, admin revocation
checks, replay checks, metrics samples, persona test logs, and CLI walkthrough
output under `.local/drs-assessment/live-*/`.
