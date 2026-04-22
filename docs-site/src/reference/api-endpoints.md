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

> `/verify` always returns HTTP 200. Check the `valid` field to determine the outcome. HTTP 403 is only returned by the MCP/A2A middleware routes, not by `/verify` directly.

```json
{
  "valid": false,
  "error": {
    "code": "CHAIN_HASH_MISMATCH",
    "message": "prev_dr_hash mismatch at chain index 1",
    "suggestion": "Ensure receipts are in root-first order and were not modified after signing"
  }
}
```

**Response — malformed input (400):**
```json
{"error": "invalid character 'x' looking for beginning of value"}
```

### Optional: request-body binding check

`POST /verify` accepts an optional `body` field in the JSON request — the
parsed request body the tool server received from its client. When present,
drs-verify canonicalises both the body and `invocation.args` using
RFC 8785 (JCS) and reports the relationship in `result.binding`:

| `binding` value | Meaning |
|---|---|
| `"match"` | Body canonically equals `invocation.args`. The body is bound to what was signed. |
| `"mismatch"` | Chain verified but body diverges from args. Likely tampering between signing and execution. |
| `"invalid_body"` | Body was included but could not be parsed as JSON. |
| (field absent) | Body was not sent; no binding check ran. |

`result.valid` stays cryptographic truth (chain + policy + signature).
`binding` is a distinct signal; the tool server decides what to do with
`"mismatch"`. A common pattern:

```js
if (!result.valid) return reject(result.error);
if (result.binding === "mismatch") return reject({ code: "BINDING_MISMATCH" });
// proceed to execute the tool against the verified body
```

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

### What drs-verify does NOT do

drs-verify is a verification service only. It does not proxy, transform,
or execute MCP/A2A traffic. Tool servers own their own endpoints and call
`POST /verify` on a local drs-verify instance for each request. See
`examples/drs-expense-agent/src/tool-server.ts` for the canonical
tool-server pattern, or import `github.com/drs-protocol/drs-verify/pkg/middleware`
for in-process Go integrations.

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
