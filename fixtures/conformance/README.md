# DRS Conformance Test Vectors

This directory contains the canonical test vectors for DRS 4.0.
All three implementations (Rust `drs-core`, Go `drs-verify`, TypeScript `drs-sdk`)
must produce identical results when run against these vectors.

## Directory Structure

```
conformance/
  jcs/vectors.json              RFC 8785 JCS canonicalization
  chain-hash/vectors.json       SHA-256 chain hash computation
  policy/pass.json              Policy attenuation — valid pairs
  policy/fail.json              Policy attenuation — invalid pairs
  temporal/vectors.json         Temporal validity checks
  revocation/vectors.json       Revocation status lookup
  receipts/
    root-delegation.json        Signed root DR with known test keys
    sub-delegation.json         Signed sub-delegation with chain linkage
    invocation.json             Signed invocation receipt
    full-chain-bundle.json      Complete valid bundle for end-to-end verification
```

## Key Material

All receipt fixtures use Ed25519 test keys embedded in the JSON files.
These keys are labeled `CONFORMANCE TEST KEY ONLY` and must never be
used outside of tests.

## Regenerating Fixtures

```bash
node fixtures/conformance/generate.mjs
```

The generator uses `@noble/ed25519` from `drs-sdk/node_modules`.
Ed25519 signing is deterministic — the same seed always produces the
same signature for the same message, so regeneration produces identical output.

## Adding New Vectors

1. Add the vector definition to `generate.mjs`.
2. Run the generator to update the JSON files.
3. Run the conformance test suite across all three languages.
4. When there is ambiguity about expected output, the Rust implementation decides.
