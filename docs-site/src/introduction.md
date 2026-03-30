# Delegation Receipt Standard

<span class="research-badge">Research Project</span>

**DRS is a per-step delegation receipt standard built on top of OAuth 2.1 + RFC 8693 + MCP.**

Every time an AI agent acts on your behalf, DRS produces a cryptographically signed receipt that proves — to anyone, without contacting a central authority — exactly who authorised what, under which constraints, at what time.

## The problem DRS solves

Modern AI agents act through delegation chains. A human authorises an agent, which authorises a sub-agent, which calls a tool. OAuth 2.1 handles the first hop. RFC 8693 defines token exchange. But neither standard requires a receipt at every step — which means any link in the chain can be fabricated after the fact, and no tool server can independently verify the full provenance of a request.

This is the **chain splicing vulnerability** (CVE-2025-55241, demonstrated in Azure AD). The IETF OAuth Working Group named per-step signed receipts as mitigation #3. DRS is that mitigation, implemented as an open standard on top of the existing OAuth + MCP stack.

## What DRS is not

| DRS is | DRS is not |
|---|---|
| A receipt standard for delegation chains | A replacement for OAuth 2.1 |
| Built on JWTs, EdDSA, OAuth 2.1, MCP | A UCAN implementation |
| Independently verifiable audit evidence | An observability tool (Langfuse/Arize do that) |
| An open standard, not a platform | A blockchain product |
| The authorisation provenance layer | A replacement for OpenTelemetry |

## Who this is for

- **[Developers](./how-to/developers/install-sdk.md)** — building MCP servers or agent runtimes who need DRS integration
- **[Operators](./how-to/operators/deploy-drs-verify.md)** — deploying the verification server and configuring enterprise policies
- **[Auditors](./how-to/auditors/reconstruct-chain.md)** — reconstructing delegation chains for compliance evidence
- **[Contributors](./how-to/contributors/dev-setup.md)** — who want to understand the architecture and extend the codebase

## Repository structure

| Component | Language | Role |
|---|---|---|
| `drs-core` | Rust | Crypto primitives, JCS canonicalisation, chain verification, WASM build |
| `drs-verify` | Go | Verification HTTP server, MCP/A2A middleware, DID resolver, status list cache |
| `drs-sdk` | TypeScript | Developer SDK (issuance path), CLI tools, browser WASM wrapper |

> This is a research project. The architecture, data model, and algorithms are documented throughout this site. The implementation is the reference implementation of the DRS 4.0 specification.
>
> Start with [What is DRS?](./explanation/what-is-drs.md) for a conceptual overview, or jump straight to the [Quick Start](./quick-start.md).
