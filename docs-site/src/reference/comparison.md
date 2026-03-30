# DRS vs Alternatives

DRS is a narrow standard solving a specific problem. Understanding what it is and is not helps you decide where it belongs in your stack.

## Comparison table

| System | Core purpose | Independently verifiable? | Per-step receipts? | OAuth ecosystem? | Production adoption |
|---|---|---|---|---|---|
| **DRS** | Delegation chain receipts | ✓ Yes | ✓ Yes | ✓ Yes | Research / early |
| **OAuth 2.1** | User → service delegation | — | — (no receipts) | ✓ Yes | Universal |
| **RFC 8693** | Token exchange between agents | — | — (bearer tokens) | ✓ Yes | Growing |
| **UCAN** | Capability-based delegation | ✓ Yes | ✓ Yes | ✗ CBOR/IPLD | ~1 production user |
| **OpenTelemetry** | Distributed tracing | ✗ Operator-controlled | — (spans, not receipts) | Agnostic | Universal |
| **Langfuse / Arize** | LLM observability | ✗ Operator-controlled | — (logs/evals) | Agnostic | Growing |
| **Agentic JWT** | JWT profile for agent identity | Partial | — (identity, not chains) | ✓ Yes | Research |

## Why not UCAN?

UCAN is technically correct. The reason DRS uses OAuth 2.1 instead is ecosystem adoption:

- AT Protocol chose JWT + OAuth 2.1
- MCP (Model Context Protocol) chose JWT + OAuth 2.1
- The LLM agent ecosystem is converging on OAuth-based token exchange

UCAN's production deployment is approximately one system (Storacha/web3.storage). Building DRS on UCAN would have meant building for a standard that the target ecosystem does not use. You cannot get enterprises to adopt an accountability standard that requires them to also adopt CBOR/IPLD and a new DID infrastructure.

DRS solves the same cryptographic problem as UCAN (independently verifiable delegation chains) but uses the token format (JWT) and authorisation protocol (OAuth 2.1) that the ecosystem already uses.

## Why not OpenTelemetry?

OpenTelemetry traces are **observability data**. They tell you what happened from the operator's perspective, stored in operator-controlled infrastructure (Jaeger, Grafana, Datadog).

DRS receipts are **authorisation proofs**. They tell you what was permitted, signed by the authorising party, verifiable by anyone with the public key.

The critical difference: an attacker who compromises the operator can delete or falsify OTel traces. They cannot forge DRS receipts without the private key. For regulatory compliance ("prove what happened"), cryptographic proofs are required — logs are not sufficient.

Use OpenTelemetry for debugging and monitoring. Use DRS for compliance and audit.

## Why not server logs?

Server logs are:
- Operator-controlled — the operator can modify or delete them
- Not cryptographically bound to the authorising party
- Not independently verifiable — an auditor must trust the operator's infrastructure

DRS receipts are:
- Signed by the authorising party — the operator cannot forge them
- Verifiable by anyone — no trust in the operator's infrastructure required
- Tamper-evident — modification breaks the Ed25519 signature

For compliance purposes, "we have logs showing what happened" is weaker than "we have cryptographic proofs signed by the authorising parties." The EU AI Act, HIPAA, and AIUC-1 requirements are moving toward the latter.

## When to use each

| Your goal | Use |
|---|---|
| Track agent performance, latency, costs | OpenTelemetry + Langfuse/Arize |
| Authenticate users to your service | OAuth 2.1 |
| Exchange tokens between agents | RFC 8693 |
| Prove what an agent was authorised to do | DRS |
| Meet EU AI Act Article 12/13 requirements | DRS |
| Meet HIPAA §164.312(b) audit controls | DRS |
| Get AIUC-1 certification | DRS |
