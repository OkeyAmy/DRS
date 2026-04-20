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

---

## POST /mcp/* and /a2a/* (verifier stubs, not proxies)

**drs-verify does not proxy, transform, or execute MCP/A2A traffic.**
It is a verification service: it validates a bundle, reports the outcome,
and — for requests that arrive on `/mcp/*` or `/a2a/*` — returns a JSON
stub confirming the bundle was accepted.

Production integrations embed the middleware package directly into the
caller's own HTTP server, so DRS enforcement sits in front of the caller's
actual MCP/A2A handlers. The `/mcp/*` and `/a2a/*` routes on the hosted
verifier are kept for demos and smoke tests only.

```go
import "github.com/drs-protocol/drs-verify/pkg/middleware"

mux := http.NewServeMux()
mux.Handle("/tools/call", middleware.MCPMiddleware(deps, nonceStore, myHandler))
```

**Request to the stub:** any MCP request with `X-DRS-Bundle` header:
```
POST /mcp/tools/call
X-DRS-Bundle: <base64url bundle>
Content-Type: application/json
```

**On valid bundle (200) — verifier stub response**:
```json
{
  "verified": true,
  "role": "verifier-stub",
  "detail": "DRS bundle accepted. This endpoint is a verifier stub — drs-verify does not proxy MCP/A2A traffic. Import github.com/drs-protocol/drs-verify/pkg/middleware to wire DRS into your own server."
}
```

**On invalid bundle (403):**
```json
{
  "valid": false,
  "error": {
    "code": "SIGNATURE_INVALID",
    "message": "Ed25519 signature verification failed for issuer did:key:z6Mk...",
    "suggestion": "Ensure the receipt chain was signed by the listed issuers."
  }
}
```

**On missing bundle (401):**
```json
{
  "error": "Missing X-DRS-Bundle header — DRS verification is required on this route."
}
```

**On malformed bundle (400):**

```json
{"error":"X-DRS-Bundle header is not valid base64url JSON"}
```

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

> The local revocation store is in-memory only. Revocations do not survive process restart. For durable revocation, update the W3C Bitstring Status List at your `STATUS_LIST_BASE_URL` endpoint.
