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

## POST /mcp/* (middleware)

When `DRS_UPSTREAM` is configured, drs-verify acts as a reverse proxy. All requests to `/mcp/*` are intercepted, the `X-DRS-Bundle` header is verified, and the request is proxied upstream if valid.

**Request:** Any MCP request with `X-DRS-Bundle` header:
```
POST /mcp/tools/call
X-DRS-Bundle: <base64url bundle>
Content-Type: application/json
```

**On valid bundle:** Proxied to `$DRS_UPSTREAM/mcp/tools/call`.

**On invalid bundle (403):**
```json
{
  "error": "SIGNATURE_INVALID",
  "block": "C",
  "message": "Ed25519 signature verification failed for issuer did:key:z6Mk..."
}
```

**On missing bundle (403, when `DRS_REQUIRE_BUNDLE=true`):**
```json
{
  "error": "BUNDLE_MISSING",
  "message": "X-DRS-Bundle header is required"
}
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

Readiness check. Returns `ok` when the server is fully initialised and ready to handle verification requests.

```
GET /readyz
```

Response (200):
```json
{
  "status": "ok",
  "cache_size": 42,
  "uptime_seconds": 3600
}
```

Use `/readyz` for Kubernetes readiness probes. Use `/healthz` for liveness probes.

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
