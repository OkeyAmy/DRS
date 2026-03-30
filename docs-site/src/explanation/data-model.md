# Data Model

DRS defines three JWT types and one bundle format. All JWTs use the `{"alg":"EdDSA","typ":"JWT"}` header and are canonicalised with RFC 8785 JCS before signing.

## 1. Delegation Receipt (DR)

A signed JWT issued by each delegator. The root DR is issued by the human (or automated operator). Sub-DRs are issued by each agent in the chain.

### Root DR payload example

```json
{
  "aud": "did:key:z6MkAgent1...",
  "cmd": "/mcp/tools/call",
  "drs_consent": {
    "locale": "en-GB",
    "method": "explicit-ui-click",
    "policy_hash": "sha256:abc123...",
    "session_id": "sess:8f3a2b1c",
    "timestamp": "2026-03-28T10:30:00Z"
  },
  "drs_regulatory": {
    "frameworks": ["eu-ai-act-art13"],
    "retention_days": 730,
    "risk_level": "limited"
  },
  "drs_root_type": "human",
  "drs_type": "delegation-receipt",
  "drs_v": "4.0",
  "exp": 1745592000,
  "iat": 1743000000,
  "iss": "did:key:z6MkHuman...",
  "jti": "dr:8f3a2b1c-4d5e-4xxx-8b9c-0d1e2f3a4b5c",
  "nbf": 1743000000,
  "policy": {
    "allowed_tools": ["web_search", "write_file"],
    "max_calls": 100,
    "max_cost_usd": 50.00,
    "pii_access": false,
    "write_access": false
  },
  "prev_dr_hash": null,
  "sub": "did:key:z6MkHuman..."
}
```

> **Note:** Keys are sorted by Unicode code point in the JWT payload (RFC 8785 JCS). This is not cosmetic — it ensures identical bytes for identical data across all implementations.

### Sub-DR differences

Sub-DRs differ from root DRs in three ways:
1. `iss` changes to the delegating agent's DID (not the human)
2. `policy` must be a strict subset of the parent's policy (POLA)
3. `prev_dr_hash` contains `sha256:{hex of parent DR JWT bytes}` instead of null
4. `drs_consent` and `drs_root_type` are absent

### Field reference

See [JWT Fields Reference](../reference/jwt-fields.md) for the complete field table with types and constraints.

## 2. Invocation Receipt

Records the actual tool call. Issued by the agent making the call immediately before invoking the tool.

```json
{
  "args": {
    "estimated_cost_usd": 0.02,
    "query": "Monad TPS benchmarks",
    "tool": "web_search"
  },
  "cmd": "/mcp/tools/call",
  "dr_chain": ["sha256:abc123...", "sha256:def456..."],
  "drs_type": "invocation-receipt",
  "drs_v": "4.0",
  "iat": 1743000300,
  "iss": "did:key:z6MkAgent2...",
  "jti": "inv:7h5c4d3e-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "sub": "did:key:z6MkHuman...",
  "tool_server": "did:key:z6MkToolServer..."
}
```

The `dr_chain` array contains the `sha256:{hex}` hashes of every DR in the chain, in order from root (index 0) to most recent sub-DR.

## 3. DRS Bundle

The unit of transport. Transmitted as the `X-DRS-Bundle` HTTP header (base64url of the JSON):

```json
{
  "bundle_version": "4.0",
  "invocation": "<invocation-receipt-jwt>",
  "receipts": [
    "<root-dr-jwt>",
    "<sub-dr-jwt-1>",
    "<sub-dr-jwt-2>"
  ]
}
```

The `receipts` array is ordered from root (index 0) to most recent sub-delegation.

## Chain hash computation

```
prev_dr_hash = "sha256:" + lowercase_hex(SHA-256(UTF-8 bytes of previous DR JWT string))
```

The hash is computed over the **raw JWT string** (the `header.payload.signature` format), not just the payload.

```typescript
// TypeScript (drs-sdk)
function computeChainHash(jwt: string): string {
  const bytes = new TextEncoder().encode(jwt);
  const digest = sha256(bytes);
  return 'sha256:' + Array.from(digest)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
```

```rust
// Rust (drs-core)
pub fn compute_chain_hash(jwt: &str) -> String {
    let digest = sha2::Sha256::digest(jwt.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}
```

Both must produce identical output for the same JWT string. This is verified in the cross-implementation test suite.
