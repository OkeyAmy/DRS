# Delegation Receipt Standard

<span class="research-badge">Research Project</span>

**DRS is a JWT-based delegation receipt standard for MCP and OAuth-oriented agent ecosystems.**

Every time an AI agent acts on your behalf, DRS produces a cryptographically signed receipt that proves — to anyone, without contacting a central authority — exactly who authorised what, under which constraints, at what time.

## The problem DRS solves

Modern AI agents act through delegation chains. A human authorises an agent, which authorises a sub-agent, which calls a tool. Existing OAuth and token-exchange standards help frame that ecosystem, but the implemented DRS code here adds its own signed receipt chain so a tool server can independently verify provenance instead of trusting logs or bearer-token context alone.

This is the **chain splicing vulnerability** (CVE-2025-55241, demonstrated in Azure AD). DRS is designed as a receipt-layer response for that class of problem, implemented here as signed JWT receipts plus hash-chain verification.

## What DRS is not

| DRS is | DRS is not |
|---|---|
| A receipt standard for delegation chains | A replacement for OAuth 2.1 |
| Built on JWTs, JCS, Ed25519, MCP middleware, and DIDs | A UCAN implementation or OAuth server |
| Independently verifiable audit evidence | An observability tool (Langfuse/Arize do that) |
| An open standard, not a platform | A blockchain product |
| The authorisation provenance layer | A replacement for OpenTelemetry |

## Who this is for

- **[Builders](./how-to/builders/no-fork-required.md)** — building on
  top of DRS: a React Native app, MCP server, A2A agent, Node backend,
  or any product that should carry signed delegation receipts. **Start
  here if you're not sure.** You never need to fork the repo.
- **[Developers](./how-to/developers/install-sdk.md)** — using the SDK
  or Go middleware programmatically (lower-level patterns than the
  consumer guides).
- **[Operators](./how-to/operators/deploy-drs-verify.md)** — deploying
  the verification server and configuring enterprise policies.
- **[Auditors](./how-to/auditors/reconstruct-chain.md)** — reconstructing
  delegation chains for compliance evidence.
- **[Contributors](./how-to/contributors/dev-setup.md)** — understanding
  the architecture and proposing changes.

## The three layers (published separately)

Each layer is an independently-installable artifact. Consumers pull
from registries — **no fork required**.

| Component | Language | Install | Role |
|---|---|---|---|
| `drs-core` | Rust | `cargo add drs-core` (or bundled inside `@okeyamy/drs-sdk`) | Crypto primitives, JCS canonicalisation, chain verification, WASM build |
| `drs-verify` | Go | `docker pull ghcr.io/okeyamy/drs-verify` | Verification HTTP server, Go middleware, DID resolver, status list cache |
| `drs-sdk` | TypeScript | `pnpm add @okeyamy/drs-sdk` | Issuance path, CLI, React Native / Node / browser |

> This is a research project. The architecture, data model, and algorithms are documented throughout this site. The implementation is the reference implementation of the DRS 4.0 specification.
>
> Start with [What is DRS?](./explanation/what-is-drs.md) for a conceptual overview, or jump straight to the [Quick Start](./quick-start.md).
