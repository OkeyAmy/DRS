# Export Evidence for EU AI Act

There is no dedicated `drs audit export` command in the current CLI. If you need
EU AI Act evidence today, assemble it from three artifacts:

1. the bundle JSON itself
2. the `drs verify` result
3. the `drs audit` output

## Current workflow

```bash
pnpm exec drs verify bundle.json > verify.txt
pnpm exec drs audit bundle.json > audit.txt
cp bundle.json eu-ai-act-bundle.json
```

## What you can include today

- the signed delegation chain (`bundle.json`)
- verifier output proving whether the chain is valid
- the audit trail showing issuer, audience, command, expiry, and tool server
- any external policy/consent records your application stored alongside the DRS flow

## What is not automated yet

The repo does not currently ship:

- `drs audit export`
- EU AI Act-specific JSON schemas
- batch export by date range or subject

Those remain documentation and tooling work for a future release.
