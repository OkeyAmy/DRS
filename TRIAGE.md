# Security Triage

This triage records the high-risk findings reviewed during the DRS security repair pass.

| ID | Verdict | Action | Rationale |
|---|---|---|---|
| F-001 | TRUE_POSITIVE | Patched | `drs keygen` previously printed the raw private key to stdout; it now writes the key to a `0600` file, refuses overwrite, and prints only public metadata plus the file path. |
| F-005 | TRUE_POSITIVE | Go patched; Rust sibling remains tracked | Policy-restricted invocation fields were optional during Go evaluation, allowing omitted args to skip fail-closed checks. `VULN-FINDINGS.json` also records a Rust counterpart that still needs separate treatment. |
| F-006 | TRUE_POSITIVE | Patched | MCP Shape 2 verification posted only the bundle and did not bind official `tools/call.params.arguments` to the signed invocation args. |
| F-007 | TRUE_POSITIVE | Patched | In-process MCP/A2A binding read request bodies without a cap before JCS comparison. |
| F-008 | TRUE_POSITIVE | Patched | `SERVER_IDENTITY` default-off remains a supported single-server mode, but startup now emits an explicit warning when tool-server binding is disabled. |
| F-009 | TRUE_POSITIVE | Patched | A nil nonce checker no longer silently disables replay protection; middleware fails closed with `NONCE_REPLAY_PROTECTION_UNAVAILABLE`. |
| F-013 | NEEDS_DESIGN | Not patched; Go/Rust scope remains open | Invocation freshness and clock-skew semantics must be configurable and aligned with nonce TTL before enforcement. A hard-coded age bound could reject legitimate delayed/offline invocations. |

## F-013 design follow-up

Define an invocation freshness policy before changing verifier behavior:

- required `iat` semantics for invocation JWTs;
- maximum accepted future clock skew;
- maximum invocation age and its relationship to `NONCE_STORE_TTL_SECS`;
- compatibility mode for existing bundles that omit `iat`.

Once that policy is decided, add verifier tests for missing `iat`, future `iat`, expired freshness, and accepted boundary values.
