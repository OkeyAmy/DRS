# API Endpoints

The drs-verify HTTP server exposes these endpoints.

## POST /verify

Verify a DRS bundle. This is the primary endpoint.

**Request:**
```
POST /verify
Content-Type: application/json
```

```json
{
  "bundle_version": "4.0",
  "invocation": "<invocation-receipt-jwt>",
  "receipts": ["<root-dr-jwt>", "<sub-dr-jwt>"]
}
```

Body is capped at `MAX_BODY_BYTES` (default 1 MiB).

**Response — valid chain (200):**
```json
{
  "valid": true,
  "context": {
    "root_principal": "did:key:z6MkHuman...",
    "chain_depth": 2,
    "leaf_policy": {
      "max_cost_usd": 0.10,
      "allowed_tools": ["web_search"]
    }
  }
}
```

**Response — invalid chain (200):**

> `/verify` always returns HTTP 200. Check the `valid` field to determine the outcome. HTTP 403 is only returned by the protocol gate (`pkg/gate` routes and `/v1/gate` decisions), not by `/verify` directly.

```json
{
  "valid": false,
  "error": {
    "code": "CHAIN_BREAK",
    "message": "receipt[1] prev_dr_hash mismatch: claimed \"sha256:def456...\", expected \"sha256:abc123...\".",
    "suggestion": "DR at index 0 may have been modified after DR at index 1 was issued, or the receipts are in the wrong order."
  }
}
```

> See [Error Codes](./error-codes.md) for the full list of `code` values by verification block.

**Response — malformed input (400):**
```json
{"error": "invalid character 'x' looking for beginning of value"}
```

### Request-body binding (required by default)

`POST /verify` takes a `body` field: the parsed request the tool server is
about to execute. drs-verify canonicalises it and `invocation.args` with
RFC 8785 (JCS). Numbers outside the I-JSON range (|n| > 2^53−1, in any
notation) are refused, because they can round to the same double; fractional
differences below double precision are not detected.

With `DRS_REQUIRE_BINDING=true` (the default):

| Situation | Response |
|---|---|
| body canonically equals `invocation.args` | `valid: true`, `binding: "match"`; jti committed |
| body differs | `valid: false`, `error.code: "BINDING_MISMATCH"`, `binding: "mismatch"`; jti **not** committed |
| body not valid JSON | `valid: false`, `error.code: "BINDING_MISMATCH"`, `binding: "invalid_body"` |
| `body` omitted | `valid: false`, `error.code: "BINDING_REQUIRED"` |

The jti is committed only after chain and binding pass, so a tampered request
cannot burn a legitimate invocation and an honest retry still succeeds.

With `DRS_REQUIRE_BINDING=false`, `/verify` reverts to chain-only verification:
an omitted body is not checked and a mismatch is reported in `binding` while
`valid` reflects the chain alone.

For MCP and A2A traffic prefer `POST /v1/gate`, which also knows which part of
a JSON-RPC message is the signed payload.

**Example request:**

```json
POST /verify
{
  "bundle_version": "4.0",
  "invocation": "<invocation-receipt-jwt>",
  "receipts": ["<root-dr-jwt>", "<sub-dr-jwt>"],
  "body": { "tool": "approve_payment", "transaction_id": "T1" }
}
```

**Example response with binding match:**

```json
{
  "valid": true,
  "context": { ... },
  "binding": "match"
}
```

## POST /v1/gate

Protocol-aware enforcement decision for out-of-process tool servers (Node,
Python, stdio). The caller forwards the request; drs-verify applies the MCP,
A2A or HTTP adapter (see [Protocol Gate](./protocol-gate.md)).

**Request:**

```json
{
  "protocol": "mcp",
  "method": "POST",
  "headers": { "x-drs-bundle": "eyJ…", "mcp-name": "web_search" },
  "body": { "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "web_search", "arguments": { "query": "weather" } } }
}
```

`protocol` is `mcp`, `a2a` or `http`. Only these headers are read:
`X-DRS-Bundle`, `Mcp-Method`, `Mcp-Name`, `Mcp-Protocol-Version`,
`A2A-Version`, `A2A-Extensions` — never send credentials.

**Response (always HTTP 200):**

```json
{ "allow": false, "gated": true, "status": 403,
  "response": { "jsonrpc": "2.0", "id": 1,
                "error": { "code": -32010, "message": "DRS: BINDING_MISMATCH",
                           "data": { "code": "BINDING_MISMATCH", "detail": "…", "suggestion": "…" } } } }
```

When `allow` is false, answer the client with `status` and `response`
verbatim. When `allow` is true and `gated` is true, `context` carries the
verified `VerificationContext`. `gated: false` means the message carries no
tool action (MCP handshake, discovery, list calls, stream GETs).

### What drs-verify does NOT do

drs-verify is a verification service only. It does not proxy, transform,
or execute MCP/A2A traffic. Tool servers own their own endpoints and call
`POST /v1/gate` (or `POST /verify` with `body`) on a local drs-verify instance
for each request, or import `github.com/OkeyAmy/DRS/drs-verify/pkg/gate` for
in-process Go integrations.

---

## GET /healthz

Liveness check.

```
GET /healthz
```

Response (200):
```json
{"status": "ok"}
```

Returns `503` only if the server cannot handle requests (e.g., during shutdown).

---

## GET /readyz

Readiness check. Returns 200 when the server is fully initialised and ready to handle verification requests; 503 when not ready.

```
GET /readyz
```

Response (200 — ready):
```json
{"status": "ready"}
```

Response (503 — not ready):
```json
{"status": "not_ready", "reason": "status_list_not_fetched"}
```

Use `/readyz` for Kubernetes readiness probes. Use `/healthz` for liveness probes.

> **Note:** If `STATUS_LIST_BASE_URL` is not configured, the status list cache is skipped and `/readyz` always returns 200 immediately.

---

## GET /metrics

Prometheus exposition endpoint.

```
GET /metrics
```

The endpoint is unauthenticated and exempt from the built-in rate limiter so
monitoring systems can scrape it reliably. In production, expose `/metrics`
only to your monitoring network through your reverse proxy, firewall, service
mesh, or Kubernetes NetworkPolicy.

---

## POST /admin/revoke

Mark a delegation receipt as locally revoked by its status list index. Takes effect immediately — does not wait for the remote Bitstring Status List to refresh.

`DRS_ADMIN_TOKEN` must be set as an environment variable. If not set, the endpoint responds 503.

```
POST /admin/revoke
Authorization: Bearer <DRS_ADMIN_TOKEN>
Content-Type: application/json
```

```json
{"status_list_index": 42}
```

Body is capped at 1 KiB.

**Response (200):**
```json
{"revoked": true, "status_list_index": 42}
```

**Response — admin not configured (503):**
```json
{"error": "admin endpoint not configured — set DRS_ADMIN_TOKEN"}
```

**Response — wrong or missing token (401):**
```json
{"error": "unauthorized"}
```

By default, local revocation is in-memory and affects only the current
`drs-verify` process. Set `REVOCATION_STORE_PATH` to enable the file-backed
local revocation store; successful `/admin/revoke` calls are appended and
fsynced so they survive process restart on that instance.

For multi-instance or cross-region durability, update the W3C Bitstring Status
List at your `STATUS_LIST_BASE_URL` endpoint. The file-backed local store is not
a distributed revocation backend.
