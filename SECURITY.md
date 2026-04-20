# Security Policy

DRS is security infrastructure. Please report vulnerabilities privately so
they can be fixed before public disclosure.

## Supported versions

Only the latest minor version line receives security fixes. DRS is at
`0.x` while the verification protocol stabilises; any new finding may be
patched in a new `0.x.y` release rather than backported.

| Version | Security fixes |
|---------|----------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x: (pre-release) |

## Reporting a vulnerability

**Do not file a public GitHub issue for security-relevant findings.**

Two acceptable channels:

1. **GitHub private security advisory** (preferred):
   https://github.com/OkeyAmy/DRS/security/advisories/new
2. **Email**: `amaobiokeoma@gmail.com` with subject prefix `[DRS security]`.

Please include:

- affected layer (`drs-core`, `drs-verify`, `drs-sdk`)
- affected version (commit hash if running from source, tag if from a
  published artifact)
- a reproduction (minimal bundle, payload, or test case) if available
- your assessment of severity and attack scenario

## Response targets

| Stage | Target time |
|-------|-------------|
| Acknowledgement | 72 hours |
| Initial triage + severity assessment | 7 days |
| Fix in a private branch | 14–30 days (depends on scope) |
| Coordinated disclosure + release | After fix is published |

These are best-effort targets. If a finding is actively exploited we
will shorten them. If a finding requires upstream coordination (e.g.,
`ed25519-dalek`, `serde-json-canonicalizer`) we will say so and work to
the upstream timeline.

## Scope

**In scope**:

- cryptographic verification correctness (Ed25519, SHA-256 chain, JCS canonicalisation)
- DID resolution correctness and SSRF controls
- replay protection (nonce store)
- revocation semantics (local admin + remote status list)
- RFC 3161 timestamp binding
- HTTP surface of `drs-verify` (rate limiting, admin token, headers)
- SDK signing path correctness
- supply-chain risks in the published artifacts (crates.io, npm, ghcr.io)

**Out of scope**:

- denial of service that requires already-exhausted rate limits or
  unbounded resource allocation already documented as a pilot-only
  limitation (see `docs/production-readiness-checklist.md`)
- social engineering of maintainers
- vulnerabilities in third-party dependencies already tracked by upstream
  CVE databases unless they affect DRS in a way that is not obvious from
  the dep's advisory text

## Safe harbour

Good-faith security research is welcome. You will not be pursued for
legal action as long as you:

- do not access data that is not yours
- do not disrupt production systems operated by third parties
- give us a reasonable window to fix before public disclosure
- do not demand payment in exchange for silence

## Known weaknesses

Treat these as confirmed gaps, not findings:

- **Process-local nonce store**: `drs-verify` keeps replay state in memory.
  A restart loses it, and multiple replicas do not share it. Single-
  instance deployments only until [#40 in the tracker](./docs/production-readiness-checklist.md) lands.
- **Process-local emergency revocation**: `POST /admin/revoke` does not
  survive restart. Durable revocation is via the remote W3C Bitstring
  Status List. Track [#39](./docs/production-readiness-checklist.md) for a
  disk-backed store.
- **Request-binding gap**: HTTP middleware verifies the bundle but does
  not by itself compare signed invocation arguments with the executed
  request body. Applications must add their own comparison today. Track
  [#42](./docs/production-readiness-checklist.md).

These are called out here so embedders can size their threat model
accurately while the fixes are in flight.

## GPG / signing

Releases are tagged by the maintainer. Image signing via `cosign` is in
the release-hardening plan; until that lands, verify release artifacts by
checking the commit hash against the tag on GitHub.
