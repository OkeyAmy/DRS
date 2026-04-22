# What is DRS?

**DRS (Delegation Receipt Standard) is a JWT-based, per-step delegation receipt standard for MCP and OAuth-oriented agent ecosystems.**

It produces a cryptographically signed receipt at every step of an agent delegation chain so that any party — the tool server, a regulator, an auditor — can independently verify the complete provenance of any agent action without contacting a central authority.

## The one-sentence definition

> DRS adds a tamper-evident, independently verifiable receipt to every hop of an agent delegation chain.

## What DRS adds around existing standards

```
OAuth / token exchange ecosystems → common surrounding auth context
DRS JWT receipts                  → signed proof for each delegation step
DRS verification                  → independent chain validation at the tool boundary
```

Without DRS, an audit trail exists only in server logs controlled by the operator. With DRS, the audit trail is in the receipts themselves — signed by the delegating party, verifiable by anyone with the public key.

## The chain splicing problem

RFC 8693 allows Agent A to exchange its token for a new token representing Agent B acting on behalf of the original user. The problem: nothing prevents an attacker from splicing an unrelated token into the chain — presenting credentials from scope A while actually invoking scope B.

CVE-2025-55241 (Azure AD, March 2025) demonstrated this in production. The IETF OAuth WG's suggested mitigation #3 is **per-step signed receipts**. DRS is that mitigation.

## How DRS works

1. **Delegation Receipt (DR):** A signed JWT issued by each delegator. Contains the command, policy constraints, temporal bounds, and a SHA-256 hash of the previous DR.
2. **Chain:** The linked sequence of DRs from the human root to the invoking agent. Each `prev_dr_hash` field links back, creating a tamper-evident chain.
3. **Invocation Receipt:** A signed JWT recording the actual tool call arguments, the full chain of DR hashes, and the tool server's DID.
4. **Bundle:** The invocation receipt plus all DRs. On HTTP-terminated routes it
   travels as a base64url-encoded JSON object in the `X-DRS-Bundle` header. On
   pure JSON-RPC MCP flows it can travel in `params._meta["X-DRS-Bundle"]` with
   the same base64url encoding.

## What DRS is not

DRS is frequently confused with systems it is adjacent to but distinct from:

| System | What it does | How it differs from DRS |
|---|---|---|
| OAuth 2.1 | Delegates access | DRS is designed to complement that ecosystem, but the implemented runtime here is JWT/JCS receipt verification |
| UCAN | Capability tokens (CBOR/IPLD) | DRS uses JWT receipts and DRS-specific fields, not UCAN envelopes |
| OpenTelemetry | Distributed tracing | Observability vs. authorisation provenance |
| Langfuse / Arize | LLM observability | Logs vs. cryptographic proofs |
| Agentic JWT | JWT profile for agent identity | Identity vs. delegation chain receipts |
| Blockchain audit logs | Immutable event log | DRS receipts work without blockchain (on-chain is optional Tier 5) |

For a detailed comparison, see [DRS vs Alternatives](../reference/comparison.md).
