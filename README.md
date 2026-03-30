# Delegation Receipt Standard (DRS)

> **Research Project** — Infrastructure-grade accountability layer for agentic AI systems.

DRS is a [UCAN Profile](https://ucan.xyz) that issues cryptographically signed receipts at every step of an agentic delegation chain — so humans, auditors, and regulators can prove *who authorized what, to whom, and when*.

**Full documentation → [okeyamy.github.io/DRS](https://okeyamy.github.io/DRS/)**

---

## The Problem

When an AI agent sub-delegates work to other agents, standard OAuth 2.1 and JWT-based flows lose the chain of custody. An attacker can splice a forged delegation into the middle of the chain (CVE-2025-55241) and the tool server cannot detect it. DRS closes this gap with a tamper-evident receipt at every hop.

## Architecture

Three-layer language stack chosen for correctness and performance:

| Layer | Language | Responsibility |
|---|---|---|
| `drs-core` | Rust | Ed25519 crypto, CID computation, RFC 8785 JCS canonicalization, capability index |
| `drs-verify` | Go | Verification server, MCP/A2A middleware, LRU caches, revocation |
| `drs-sdk` | TypeScript | Developer SDK, issuance path, WASM bundle |

```
End User
  └─ issues Root DR (drs-sdk)
       └─ Developer sub-delegates (drs-sdk)
            └─ Agent Runtime invokes tool (drs-sdk)
                 └─ Tool Server verifies chain (drs-verify + drs-core)
                      └─ Auditor reconstructs chain (drs-verify CLI)
```

## Quick Start

```bash
# Install the SDK
pnpm add @drs/sdk

# Generate a keypair
npx drs keygen --out operator.key

# Issue a root delegation
import { issueRootDelegation } from '@drs/sdk'
const dr = await issueRootDelegation({
  issuerKey: operatorKey,
  subject:   'did:key:z6Mk...',
  policy:    [['==', '.tool', '"web_search"']],
  expiresIn: 3600,
})

# Start the verification server
docker run -p 8080:8080 \
  -e DRS_OPERATOR_DID=did:key:z6Mk... \
  ghcr.io/okeyamy/drs-verify:latest

# Verify a bundle
curl -X POST http://localhost:8080/verify \
  -H 'Content-Type: application/json' \
  -d @bundle.json
```

## Documentation

The docs cover four audiences:

| Audience | What you'll find |
|---|---|
| **Developers** | SDK install, MCP/A2A middleware, issuance guide |
| **Operators** | Deployment, key management, revocation, storage tiers |
| **Auditors** | Chain reconstruction, EU AI Act export, HIPAA evidence |
| **Contributors** | Architecture deep-dive, testing standards, false-positive history |

→ **[Read the docs](https://okeyamy.github.io/DRS/)**

## Repository Layout

```
drs-core/          Rust — crypto primitives and capability index
drs-verify/        Go  — verification server and middleware
drs-sdk/           TypeScript — developer SDK
docs/              Architecture documents and technical audit
docs-site/         mdBook source for the documentation site
.github/workflows/ CI: docs deploy to GitHub Pages on every push
```

## Security

- Ed25519 signatures via `ed25519-dalek` 2.x (RUSTSEC-2022-0093 patched)
- Constant-time multicodec prefix comparison (no timing oracle)
- RFC 8785 JCS canonicalization (no `JSON.stringify` key sort)
- Fail-closed capability checks — error = denied
- LRU-bounded DID resolver cache (10,000 entries max)
- Bitstring Status List revocation with `sync.Once` concurrency guard

## Status

This is a research project. APIs are not stable. Do not deploy to production without a full security audit.

Version history: v1 (scrapped — wrong threat model), v2 (scrapped — wrong UCAN version + O(n·m) capability check), v3 (current).

## License

MIT
