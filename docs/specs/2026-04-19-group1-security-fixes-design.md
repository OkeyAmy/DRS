# Group 1 Security Fixes — Design Spec

**Date:** 2026-04-19
**Scope:** `drs-verify` (Go only)
**Issues addressed:** GitHub #8, #9, #14, #15, #16, #17, #20 + 4 unlisted production gaps
**Group 2 (rate limiting, key management):** separate spec, separate plan

---

## 1. Background

A full audit of `drs-verify` against GitHub security issues and a direct read of the
source identified 11 fixes required before the service can be considered
production-ready. All fixes are confined to the Go layer. None require new
external dependencies.

Four of the 11 fixes were not captured in any GitHub issue:

- SSRF via `did:web` resolver
- No chain depth limit (unbounded CPU per request)
- JWT `alg` header never validated (algorithm confusion)
- No context/deadline propagation to I/O paths

---

## 2. File Change Map

| File | Fixes applied |
|---|---|
| `pkg/resolver/did.go` | SSRF protection, context propagation |
| `pkg/verify/chain.go` | Chain depth limit, JWT alg validation, RFC 3161 trusted path, silent store errors, context propagation |
| `pkg/store/filesystem.go` | Path traversal (#15) |
| `pkg/policy/evaluate.go` | NaN/Inf/negative cost bypass (#14) |
| `pkg/middleware/decode.go` | Export `CheckNonceReplay` (#20) |
| `pkg/middleware/mcp.go` | Update to `CheckNonceReplay` (exported name) |
| `pkg/middleware/a2a.go` | Update to `CheckNonceReplay` (exported name) |
| `pkg/revocation/status.go` | Partial reads (#8), context propagation |
| `pkg/revocation/admin_handler.go` | Constant-time token comparison (#16) |
| `pkg/types/types.go` | `StoreWarnings` field (#17) |
| `pkg/config/config.go` | `TSARootCertPEM` field (#9) |
| `cmd/server/main.go` | Wire nonce into /verify (#20), TSA root pool (#9), pass `r.Context()` |

---

## 3. Fix Specifications

### Fix 1 — SSRF in `did:web` resolver

**File:** `pkg/resolver/did.go`
**Severity:** HIGH (unlisted issue)

**Problem:** `resolveDidWeb` constructs an HTTPS URL from a user-supplied DID string
and fetches it with no restriction on target host. Attackers can probe internal
infrastructure via `did:web:169.254.169.254`, `did:web:localhost`, `did:web:10.0.0.1`, etc.

**Fix:**

Add `isPrivateHost(host string) (bool, error)` that:
1. Calls `net.LookupHost(host)` to resolve all IPs
2. Parses each result with `net.ParseIP`
3. Rejects the host if any IP falls in:
   - Loopback: `127.0.0.0/8`, `::1`
   - Link-local: `169.254.0.0/16`, `fe80::/10`
   - Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Unique local IPv6: `fc00::/7`
   - Unspecified: `0.0.0.0`, `::`
4. Returns `true` (is private) if any IP is in a blocked range

Call `isPrivateHost` inside `resolveDidWeb` after `didWebDocumentURL` returns and
before the HTTP fetch. On `true`, return error `"did:web host resolves to a
private or reserved address: SSRF protection"`.

The DNS resolution happens at check time (not URL-parse time), which also defeats
DNS rebinding attacks where the initial DNS response is benign but a subsequent one
is private.

**Blocked CIDRs** (defined as package-level `[]*net.IPNet` parsed with `net.ParseCIDR`
at package init):

```
127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12,
192.168.0.0/16, 0.0.0.0/8, 100.64.0.0/10,
::1/128, fe80::/10, fc00::/7, ::ffff:0:0/96
```

---

### Fix 2 — Chain depth limit

**File:** `pkg/verify/chain.go`
**Severity:** HIGH (unlisted issue)

**Problem:** Block A checks `len(bundle.Receipts) == 0` but has no upper bound.
A 500-receipt bundle triggers 500 DID resolutions, 500 Ed25519 verifications, and
500 `Store.Put` calls in a single request. Rate limiting (Group 2) caps concurrent
request count but not work per request. Both are required.

**Fix:**

```go
const maxChainDepth = 16
```

In Block A, after the empty check:

```go
if len(bundle.Receipts) > maxChainDepth {
    return types.Invalid("CHAIN_TOO_DEEP",
        fmt.Sprintf("bundle has %d receipts; maximum chain depth is %d.",
            len(bundle.Receipts), maxChainDepth),
        "Reduce the delegation chain depth.")
}
```

16 hops is more than any legitimate delegation chain requires. The constant is
defined at package level for clarity; it is not configurable at runtime because
allowing operators to raise it defeats the purpose.

---

### Fix 3 — JWT `alg` header validation

**File:** `pkg/verify/chain.go`
**Severity:** HIGH (unlisted issue)

**Problem:** `verifyJWTSignature` ignores the JWT header entirely. The `alg` field
is never read. DRS receipts must use `EdDSA`. A JWT claiming `alg:HS256` or
`alg:none` reaches the Ed25519 verifier and burns a DID resolution before failing.

**Fix:**

Add to `chain.go`:

```go
type jwtHeader struct {
    Alg string `json:"alg"`
}
```

Add `decodeJWTHeader(jwt string) (jwtHeader, error)` that base64url-decodes
`parts[0]` and unmarshals into `jwtHeader`.

At the top of `verifyJWTSignature`, before DID resolution:

```go
hdr, err := decodeJWTHeader(jwt)
if err != nil {
    return fmt.Errorf("JWT header decode failed: %w", err)
}
if hdr.Alg != "EdDSA" {
    return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
}
```

This rejection happens before `res.Resolve(issuerDID)` — no network call is made
for a JWT with a wrong algorithm.

---

### Fix 4 — Path traversal in filesystem store (#15)

**File:** `pkg/store/filesystem.go`
**Severity:** HIGH

**Problem:** `hashPath` passes user-supplied hash values through `filepath.Join`
without validation. A hash like `sha256:../../../../etc/passwd` produces a path
outside the store directory. `Put` writes attacker-controlled content to that path.
`Delete` removes it.

**Fix:**

Change `hashPath` signature to `(string, error)`.

Validation logic:

```go
var validHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (f *FilesystemStore) hashPath(hash string) (string, error) {
    name := strings.TrimPrefix(hash, "sha256:")
    if !validHashRe.MatchString(name) {
        return "", fmt.Errorf("store: invalid hash %q: must be 64 lowercase hex characters", hash)
    }
    prefix := name[:4]
    return filepath.Join(f.baseDir, prefix, name+".jwt"), nil
}
```

`Put`, `Get`, and `Delete` propagate the error. No path is constructed or used if
the hash is invalid.

The `regexp.MustCompile` call is at package init (compile-once). The regex
`^[0-9a-f]{64}$` exactly matches a SHA-256 hex digest — exactly 64 chars, no
path separators, no dots, no slashes.

---

### Fix 5 — NaN/Inf/negative cost bypass (#14)

**File:** `pkg/policy/evaluate.go`
**Severity:** HIGH

**Problem:** `toFloat64` accepts IEEE 754 special values. `NaN > X` is always
`false`, so `estimated_cost_usd: NaN` passes any cost limit. Negative values also
pass any positive limit.

**Fix:**

In `toFloat64`, after the type switch produces `f float64`:

```go
if math.IsNaN(f) || math.IsInf(f, 0) {
    return 0, false
}
```

In `Evaluate`, after successful `toFloat64` for `estimated_cost_usd`:

```go
if cost < 0 {
    return fmt.Errorf("estimated_cost_usd must be non-negative, got %v", cost)
}
```

Add `"math"` to the import block.

---

### Fix 6 — Missing nonce protection on `/verify` (#20)

**Files:** `pkg/middleware/decode.go`, `pkg/middleware/mcp.go`, `pkg/middleware/a2a.go`, `cmd/server/main.go`
**Severity:** HIGH

**Problem:** The MCP and A2A middleware check nonce replay via `checkNonceReplay`.
The `/verify` endpoint calls `verify.Chain` directly with no nonce check. Any
captured valid bundle can be replayed indefinitely against `/verify`.

**Fix:**

1. In `pkg/middleware/decode.go`: rename `checkNonceReplay` → `CheckNonceReplay`
   (exported). Function signature and body unchanged.

2. In `mcp.go` and `a2a.go`: update the two call sites from `checkNonceReplay` to
   `CheckNonceReplay` (same package — no import change, just the name).

3. In `cmd/server/main.go`, inside the `/verify` handler, after body decode and
   before `verify.Chain`:

```go
if middleware.CheckNonceReplay(w, req.Invocation, nonceStore) {
    return
}
```

`req.Invocation` is `types.ChainBundle.Invocation` — the invocation JWT string,
which is the field `CheckNonceReplay` already expects.

---

### Fix 7 — RFC 3161 timestamp trust chain (#9)

**Files:** `pkg/config/config.go`, `pkg/verify/chain.go`, `cmd/server/main.go`
**Severity:** HIGH

**Problem:** `chain.go:375` calls `anchor.VerifyTimestamp`, which verifies the TSA
signature against the certificate embedded in the token but does not validate that
certificate against a trust root. Any self-signed certificate can forge a timestamp
token that passes verification.

`anchor.VerifyTimestampTrusted` already implements the correct path (chain
validation + EKU check). It is just not called.

**Fix:**

`pkg/config/config.go`:
- Add `TSARootCertPEM string` field
- Load from `TSA_ROOT_CERT_PEM` env var (empty = use system roots)

`cmd/server/main.go`:
- After `config.Load()`, if `cfg.TSARootCertPEM != ""`:
  - Parse PEM into `*x509.CertPool` using `x509.NewCertPool()` + `AppendCertsFromPEM`
  - If the PEM parses but appends zero certificates: `log.Fatalf` (misconfiguration)
  - If parsing succeeds: assign to `deps.TSARootPool`
- If `cfg.TSARootCertPEM == ""`: `deps.TSARootPool = nil` (system roots)

`pkg/verify/chain.go`:
- Add `TSARootPool *x509.CertPool` to `Deps`
- Change line 375 from:
  ```go
  genTime, err := anchor.VerifyTimestamp([]byte(tokenStr), jwtHash[:])
  ```
  to:
  ```go
  genTime, err := anchor.VerifyTimestampTrusted([]byte(tokenStr), jwtHash[:], deps.TSARootPool)
  ```

---

### Fix 8 — Partial status list reads (#8)

**File:** `pkg/revocation/status.go`
**Severity:** HIGH

**Problem:** `refresh()` reads the HTTP response body with `io.ReadAll`. If the
connection drops mid-transfer, the truncated buffer is committed as the new bitstring.
Revoked entries beyond the truncation point silently appear non-revoked.

**Fix:**

In `refresh()`, replace the current `io.ReadAll(resp.Body)` call with:

```go
const maxStatusListBytes = 1 << 20 // 1 MiB

limited := io.LimitReader(resp.Body, int64(maxStatusListBytes)+1)
buf, err := io.ReadAll(limited)
if err != nil {
    return fmt.Errorf("reading status list body: %w", err)
}
if len(buf) > maxStatusListBytes {
    return fmt.Errorf("status list exceeds %d byte limit", maxStatusListBytes)
}
```

After the read, if `Content-Length` header is present and parseable:

```go
if clStr := resp.Header.Get("Content-Length"); clStr != "" {
    cl, err := strconv.ParseInt(clStr, 10, 64)
    if err == nil && cl >= 0 && int64(len(buf)) != cl {
        return fmt.Errorf("status list truncated: Content-Length %d, read %d bytes", cl, len(buf))
    }
}
```

The `cl >= 0` guard rejects malformed negative `Content-Length` values before
the length comparison, preventing a sign-confusion bypass.

On any error return, the previous `s.bitstring` snapshot is untouched (the write
to `s.bitstring` only happens on success, as it does now).

---

### Fix 9 — Constant-time admin token comparison (#16)

**File:** `pkg/revocation/admin_handler.go`
**Severity:** MEDIUM

**Problem:** `r.Header.Get("Authorization") != "Bearer "+token` uses Go string
equality which short-circuits on the first differing byte, leaking timing
information that enables byte-by-byte token enumeration.

**Fix:**

```go
import "crypto/subtle"

expected := "Bearer " + token
actual   := r.Header.Get("Authorization")
if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
    writeJSON(w, http.StatusUnauthorized, ...)
}
```

---

### Fix 10 — Silent store errors (#17)

**Files:** `pkg/types/types.go`, `pkg/verify/chain.go`
**Severity:** MEDIUM

**Problem:** `chain.go:347` discards `Store.Put` errors with `_ = err`. A full
disk, permission error, or network failure on a remote store creates a silent gap
in the audit trail.

**Fix:**

`pkg/types/types.go` — add to `VerificationResult`:

```go
StoreWarnings []string `json:"store_warnings,omitempty"`
```

`pkg/verify/chain.go` — replace `_ = err`:

```go
var storeWarnings []string
// ...
if err := deps.Store.Put(hash, jwt); err != nil {
    log.Printf("store: Put failed for hash %s: %v", hash, err)
    storeWarnings = append(storeWarnings,
        fmt.Sprintf("receipt %s could not be persisted: %v", hash, err))
}
// ...
result.StoreWarnings = storeWarnings
```

Chain is still valid. Callers receive transparency on audit gaps.

---

### Fix 11 — Context/deadline propagation

**Files:** `pkg/verify/chain.go`, `pkg/resolver/did.go`, `pkg/revocation/status.go`, `pkg/middleware/mcp.go`, `pkg/middleware/a2a.go`, `cmd/server/main.go`
**Severity:** MEDIUM (unlisted issue)

**Problem:** `verify.Chain` performs DID resolution (potential HTTP I/O) and
revocation checks (potential HTTP I/O) with no connection to the caller's
`context.Context`. Client disconnects do not cancel in-flight I/O. No
per-request timeout can be enforced at the application layer.

**Fix:**

1. `verify.Chain(bundle types.ChainBundle, deps Deps)` →
   `verify.Chain(ctx context.Context, bundle types.ChainBundle, deps Deps)`

2. `resolver.Resolver.Resolve(did string)` →
   `Resolve(ctx context.Context, did string)`
   — `resolveDidWeb` creates the HTTP request with `http.NewRequestWithContext(ctx, "GET", docURL, nil)`
   — `isPrivateHost` receives ctx for its `net.DefaultResolver.LookupHost(ctx, host)` call

3. `revocation.StatusCache.IsRevoked(statusListIndex uint64)` →
   `IsRevoked(ctx context.Context, statusListIndex uint64)`
   — `refresh()` gains a `ctx context.Context` parameter; when called from
   `IsRevoked` it uses the request context; when called from `WarmUp` or the
   TTL-triggered background path it uses `context.Background()` so a client
   disconnect does not abort a background cache refresh mid-write

4. All callers of `verify.Chain` pass `r.Context()`:
   - `/verify` handler in `main.go`
   - `mcpMiddleware` in `mcp.go`
   - `a2aMiddleware` in `a2a.go`

5. `Store.Put` calls are best-effort and not context-cancelled (store failures are
   non-fatal; cancelling a store write mid-flight could corrupt the file).

---

## 4. Testing Requirements

Each fix must have tests before the PR is opened. Test files follow the existing
`_test.go` convention.

| Fix | Test file | Required cases |
|---|---|---|
| SSRF | `pkg/resolver/did_test.go` | `did:web:localhost` rejected; `did:web:169.254.169.254` rejected; `did:web:10.0.0.1` rejected; valid public host allowed (mock DNS) |
| Chain depth | `pkg/verify/chain_test.go` | 17-receipt bundle → `CHAIN_TOO_DEEP`; 16-receipt bundle passes Block A |
| JWT alg | `pkg/verify/chain_test.go` | JWT with `alg:HS256` → `UNSUPPORTED_ALG`; `alg:none` → error; `alg:EdDSA` passes header check |
| Path traversal | `pkg/store/store_test.go` | `sha256:../../../../etc/passwd` → error; `sha256:` + 63 hex chars → error; valid 64-char hex accepted |
| NaN/Inf cost | `pkg/policy/evaluate_test.go` | NaN rejected; +Inf rejected; -Inf rejected; -1.0 rejected; 0.0 accepted; valid positive accepted |
| Nonce on /verify | `cmd/server/main_test.go` | replay via `/verify` returns 409; fresh invocation passes |
| RFC 3161 trust | `pkg/verify/chain_test.go` | self-signed cert → error; nil pool falls through to system roots |
| Partial reads | `pkg/revocation/status_test.go` | truncated body (Content-Length mismatch) preserves previous snapshot; over-limit body rejected |
| Constant-time | `pkg/revocation/admin_handler_test.go` | wrong token returns 401; correct token accepted |
| Store warnings | `pkg/verify/chain_test.go` | failing store → `store_warnings` populated; chain still valid |
| Context | `pkg/verify/chain_test.go` | cancelled context aborts verification and returns error |

---

## 5. What This Does Not Change

- No changes to `drs-core` (Rust) or `drs-sdk` (TypeScript)
- No changes to the DRS protocol wire format or JSON schema (except the additive
  `store_warnings` field, which is `omitempty`)
- `VerifyTimestamp` (untrusted) is not deleted — it may be useful in test contexts
  where no TSA infrastructure is available. Its name makes the risk explicit.
- Group 2 issues (#19 rate limiting, #11 key management) are out of scope for this plan

---

## 6. Issue Closure

On completion, the following GitHub issues can be closed:
`#8`, `#9`, `#14`, `#15`, `#16`, `#17`, `#20`

Three new issues should be opened for the unlisted gaps to document the fixes:
- SSRF protection in did:web resolver
- Chain depth limit
- JWT algorithm header validation
- Context propagation (can be bundled with one of the above)
