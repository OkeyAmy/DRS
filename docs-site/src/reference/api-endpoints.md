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

**Response — valid (200):**
```json
{
  "valid": true,
  "chain_depth": 2,
  "root_principal": "did:key:z6MkHuman...",
  "subject": "did:key:z6MkHuman...",
  "command": "/mcp/tools/call",
  "policy_result": "pass"
}
```

**Response — invalid (403):**
```json
{
  "valid": false,
  "error": "CHAIN_HASH_MISMATCH",
  "block": "B",
  "message": "prev_dr_hash mismatch at chain index 1: expected sha256:abc..., got sha256:def..."
}
```

**Response — malformed input (400):**
```json
{
  "error": "INVALID_INPUT",
  "message": "bundle_version must be \"4.0\""
}
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

Revoke a delegation receipt by JTI.

```
POST /admin/revoke
Authorization: Bearer <admin-token>
Content-Type: application/json
```

```json
{"jti": "dr:8f3a2b1c-4d5e-4xxx-8b9c-0d1e2f3a4b5c"}
```

Response (200):
```json
{"revoked": true, "jti": "dr:8f3a2b1c-..."}
```
