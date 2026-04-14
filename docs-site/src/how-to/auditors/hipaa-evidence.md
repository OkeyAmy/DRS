# HIPAA Audit Evidence

For healthcare deployments handling PHI, DRS can provide tamper-evident proof of
authorization and invocation activity. The current tooling is useful, but it is
not yet a dedicated HIPAA export pipeline.

## What DRS can show today

| HIPAA concern | Current DRS evidence |
|---|---|
| Record activity in PHI systems | signed invocation receipt |
| Verify authorization before access | signed delegation chain |
| Tamper evidence | Ed25519 signatures + `prev_dr_hash` chain |
| Independent verification | `did:key`-based signature checks |

## Current evidence workflow

```bash
pnpm exec drs verify bundle.json > verify.txt
pnpm exec drs audit bundle.json > audit.txt
```

Archive these outputs together with the original `bundle.json`.

## Storage caveat

The canonical storage model points regulated deployments toward Tier 3 / Tier 4
postures, but the current implementation does not enforce WORM semantics on the
filesystem backend. RFC 3161 timestamping is available when `TSA_URL` is set,
and TSA failures are best-effort.

See:

- [Storage Tiers](../operators/storage-tiers.md)
- `docs/storage-tiers.md`

## What is not implemented

The current repo does not ship:

- `drs audit retrieve`
- `drs audit export --format hipaa`
- a HIPAA-specific export schema

If you need HIPAA packaging today, build it from the raw bundle plus verifier
and audit outputs.
