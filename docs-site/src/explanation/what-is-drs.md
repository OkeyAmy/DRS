# What is DRS?

**DRS (Delegation Receipt Standard) is a per-step delegation receipt standard built on OAuth 2.1 + RFC 8693 + MCP.**

It produces a cryptographically signed receipt at every step of an agent delegation chain so that any party — the tool server, a regulator, an auditor — can independently verify the complete provenance of any agent action without contacting a central authority.

## The one-sentence definition

> DRS adds a tamper-evident, independently verifiable receipt to every hop of an OAuth delegation chain.

## What DRS adds to existing standards

```
OAuth 2.1         → handles the first delegation hop (user → agent)
RFC 8693          → defines token exchange between agents
RFC 8693 + DRS    → adds a signed receipt at EVERY hop
```

Without DRS, an audit trail exists only in server logs controlled by the operator. With DRS, the audit trail is in the receipts themselves — signed by the delegating party, verifiable by anyone with the public key.

## The chain splicing problem

RFC 8693 allows Agent A to exchange its token for a new token representing Agent B acting on behalf of the original user. The problem: nothing prevents an attacker from splicing an unrelated token into the chain — presenting credentials from scope A while actually invoking scope B.

CVE-2025-55241 (Azure AD, March 2025) demonstrated this in production. The IETF OAuth WG's suggested mitigation #3 is **per-step signed receipts**. DRS is that mitigation.

## How DRS works

1. **Delegation Receipt (DR):** A signed JWT issued by each delegator. Contains the command, policy constraints, temporal bounds, and a SHA-256 hash of the previous DR.
2. **Chain:** The linked sequence of DRs from the human root to the invoking agent. Each `prev_dr_hash` field links back, creating a tamper-evident chain.
3. **Invocation Receipt:** A signed JWT recording the actual tool call arguments, the full chain of DR hashes, and the tool server's DID.
4. **Bundle:** The invocation receipt plus all DRs, transmitted as a base64url-encoded JSON object in the `X-DRS-Bundle` HTTP header.

## What DRS is not

DRS is frequently confused with systems it is adjacent to but distinct from:

| System | What it does | How it differs from DRS |
|---|---|---|
| OAuth 2.1 | Delegates access | DRS extends it with per-step receipts |
| UCAN | Capability tokens (CBOR/IPLD) | DRS uses JWTs and OAuth — different ecosystem |
| OpenTelemetry | Distributed tracing | Observability vs. authorisation provenance |
| Langfuse / Arize | LLM observability | Logs vs. cryptographic proofs |
| Agentic JWT | JWT profile for agent identity | Identity vs. delegation chain receipts |
| Blockchain audit logs | Immutable event log | DRS receipts work without blockchain (on-chain is optional tier 4) |

For a detailed comparison, see [DRS vs Alternatives](../reference/comparison.md).
