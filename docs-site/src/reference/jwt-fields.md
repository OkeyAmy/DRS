# JWT Fields Reference

All DRS JWTs use the header `{"alg":"EdDSA","typ":"JWT"}` with keys sorted by Unicode code point (RFC 8785 JCS). The signature covers `base64url(header).base64url(payload)`.

## Delegation Receipt payload

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `iss` | DID string | Yes | Valid `did:key` or `did:web` | Issuer — the party granting delegation |
| `sub` | DID string | Yes | Must match root DR's `sub` at every hop | Subject — the original resource owner; never changes through chain hops |
| `aud` | DID string | Yes | Valid DID | Audience — the party receiving the delegation |
| `drs_v` | string | Yes | Must be `"4.0"` | DRS specification version |
| `drs_type` | string | Yes | Must be `"delegation-receipt"` | JWT type discriminator |
| `cmd` | string | Yes | Non-empty | MCP command path, e.g. `/mcp/tools/call` |
| `policy` | object | Yes | See [Policy Schema](./policy-schema.md) | Capability constraints |
| `nbf` | integer | Yes | Unix seconds; ≥ parent's `nbf` in sub-DRs | Not-before — when the delegation becomes valid |
| `exp` | integer or null | Yes | Unix seconds; ≤ parent's `exp` in sub-DRs when both set | Expiry — null for standing delegations |
| `iat` | integer | Yes | Unix seconds | Issued-at time |
| `jti` | string | Yes | Format: `dr:` + UUID v4 | Unique identifier for revocation lookup |
| `prev_dr_hash` | string or null | Yes | Format: `sha256:{64 hex chars}` or null | Hash of previous DR's JWT bytes; null at chain root |
| `drs_consent` | object | When `drs_root_type` is `"human"` | See below | Human consent evidence |
| `drs_root_type` | string | Yes on root DR | `"human"` \| `"organisation"` \| `"automated-system"` | Trust anchor type; absent on sub-DRs |
| `drs_regulatory` | object | No | See below | Storage tier and retention requirements |
| `drs_status_list_index` | integer | No | Non-negative | Position in Bitstring Status List; absent if revocation not used |

## Invocation Receipt payload

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `iss` | DID string | Yes | Must match last DR's `aud` | Issuer — the agent making the call |
| `sub` | DID string | Yes | Must match root DR's `sub` | Subject — the original human |
| `drs_v` | string | Yes | Must be `"4.0"` | DRS spec version |
| `drs_type` | string | Yes | Must be `"invocation-receipt"` | Type discriminator |
| `cmd` | string | Yes | Must match all DR `cmd` fields | MCP command path |
| `args` | object | Yes | Evaluated against all DR policies | Actual invocation arguments |
| `dr_chain` | string[] | Yes | Length = number of DRs; each `sha256:{hex}` | Ordered hashes of every DR in the chain |
| `tool_server` | DID string | Yes | Valid DID | DID of the tool server |
| `iat` | integer | Yes | Unix seconds | Issued-at time |
| `jti` | string | Yes | Format: `inv:` + UUID v4 | Unique identifier |

## ConsentRecord object

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | Yes | `"explicit-ui-click"` \| `"explicit-ui-checkbox"` \| `"api-delegation"` \| `"operator-policy"` |
| `timestamp` | ISO 8601 string | Yes | When the user consented |
| `session_id` | string | Yes | Session identifier, prefixed `sess:` |
| `policy_hash` | string | Yes | `sha256:{hex}` of the human-readable policy text the user saw |
| `locale` | IETF language tag | Yes | Language of the consent UI (e.g. `en-GB`, `fr-FR`) |

## RegulatoryMetadata object

| Field | Type | Description |
|---|---|---|
| `frameworks` | string[] | Regulatory frameworks: `"eu-ai-act-art13"`, `"hipaa-164.312b"`, `"sox"`, `"finos-tier3"` |
| `risk_level` | string | `"unacceptable"` \| `"high"` \| `"limited"` \| `"minimal"` |
| `retention_days` | integer | Minimum retention in days (0 = forever) |

## DRS Bundle

```json
{
  "bundle_version": "4.0",
  "invocation": "<invocation-receipt-jwt>",
  "receipts": ["<root-dr-jwt>", "<sub-dr-jwt-1>"]
}
```

Transmitted as `X-DRS-Bundle: base64url({bundle_json})` HTTP header.
