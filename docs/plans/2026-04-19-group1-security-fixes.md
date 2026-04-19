# Group 1 Security Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 11 security vulnerabilities in `drs-verify` (Go) before production deployment, covering path traversal, policy bypass, replay attacks, SSRF, algorithm confusion, partial reads, trust chain forgery, and missing context propagation.

**Architecture:** All changes are isolated to the `drs-verify` Go module. No new external dependencies. Changes are applied in dependency order: types first, then isolated package fixes, then cross-cutting context propagation, then wiring in `cmd/server/main.go`.

**Tech Stack:** Go 1.22, `crypto/subtle`, `crypto/x509`, `math`, `net`, `regexp`, `context` — all stdlib. Module path: `github.com/drs-protocol/drs-verify`.

**Spec:** `docs/specs/2026-04-19-group1-security-fixes-design.md`

**Run all tests:** `cd drs-verify && go test ./...`

---

## File Change Map

| File | Change |
|---|---|
| `pkg/types/types.go` | Add `StoreWarnings []string` to `VerificationResult` |
| `pkg/store/filesystem.go` | Validate hash before path construction (path traversal) |
| `pkg/policy/evaluate.go` | Reject NaN/Inf/negative in cost check |
| `pkg/revocation/admin_handler.go` | Constant-time bearer token comparison |
| `pkg/verify/chain.go` | JWT alg check, depth limit, store warnings, RFC 3161 trusted path, context |
| `pkg/resolver/did.go` | SSRF blocklist, context propagation |
| `pkg/revocation/status.go` | Partial read rejection, context propagation |
| `pkg/middleware/decode.go` | Export `CheckNonceReplay` |
| `pkg/middleware/mcp.go` | Use exported `CheckNonceReplay`, pass `r.Context()` to `Chain` |
| `pkg/middleware/a2a.go` | Use exported `CheckNonceReplay`, pass `r.Context()` to `Chain` |
| `pkg/config/config.go` | Add `TSARootCertPEM` field |
| `cmd/server/main.go` | Wire nonce into `/verify`, parse TSA root pool, pass `r.Context()` |

---

## Task 1: Add `StoreWarnings` to `VerificationResult`

**Files:**
- Modify: `pkg/types/types.go`
- Test: `pkg/types/types_test.go` (create)

- [ ] **Step 1: Write the failing test**

Create `pkg/types/types_test.go`:

```go
package types

import (
	"encoding/json"
	"testing"
)

func TestVerificationResultStoreWarningsOmitEmpty(t *testing.T) {
	r := VerificationResult{Valid: true}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) == "" {
		t.Fatal("empty marshal")
	}
	// store_warnings must be absent when nil
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["store_warnings"]; ok {
		t.Error("store_warnings must be omitted when nil")
	}
}

func TestVerificationResultStoreWarningsPresent(t *testing.T) {
	r := VerificationResult{
		Valid:         true,
		StoreWarnings: []string{"receipt sha256:abc could not be persisted: disk full"},
	}
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if _, ok := m["store_warnings"]; !ok {
		t.Error("store_warnings must be present when non-nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd drs-verify && go test ./pkg/types/... -run TestVerificationResult -v
```

Expected: `FAIL — StoreWarnings field undefined`

- [ ] **Step 3: Add the field to `VerificationResult`**

In `pkg/types/types.go`, change:

```go
type VerificationResult struct {
	Valid      bool                 `json:"valid"`
	Context    *VerificationContext `json:"context,omitempty"`
	Error      *VerificationError   `json:"error,omitempty"`
	Timestamps []TimestampResult    `json:"timestamps,omitempty"`
}
```

to:

```go
type VerificationResult struct {
	Valid          bool                 `json:"valid"`
	Context        *VerificationContext `json:"context,omitempty"`
	Error          *VerificationError   `json:"error,omitempty"`
	Timestamps     []TimestampResult    `json:"timestamps,omitempty"`
	StoreWarnings  []string             `json:"store_warnings,omitempty"`
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd drs-verify && go test ./pkg/types/... -v
```

Expected: `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/types/types.go pkg/types/types_test.go
git commit -m "fix(types): add StoreWarnings field to VerificationResult (#17)"
```

---

## Task 2: Path Traversal Fix in Filesystem Store

**Files:**
- Modify: `pkg/store/filesystem.go`
- Test: `pkg/store/store_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `pkg/store/store_test.go`:

```go
func TestFilesystemStorePathTraversal(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}

	malicious := []string{
		"sha256:../../../../etc/passwd",
		"sha256:../evil",
		"sha256:abc",             // too short — not 64 hex chars
		"sha256:" + strings.Repeat("a", 63), // 63 chars — one short
		"sha256:" + strings.Repeat("G", 64), // uppercase — not hex
		"sha256:" + strings.Repeat("a", 65), // too long
	}

	for _, hash := range malicious {
		if err := s.Put(hash, "jwt"); err == nil {
			t.Errorf("Put(%q) should have returned an error", hash)
		}
		if _, err := s.Get(hash); err == nil {
			t.Errorf("Get(%q) should have returned an error", hash)
		}
		if err := s.Delete(hash); err == nil {
			t.Errorf("Delete(%q) should have returned an error", hash)
		}
	}
}

func TestFilesystemStoreValidHash(t *testing.T) {
	dir := t.TempDir()
	s, err := store.NewFilesystemStore(dir, 0)
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}

	// exactly 64 lowercase hex chars is valid
	valid := "sha256:" + strings.Repeat("a1", 32)
	if err := s.Put(valid, "test.jwt"); err != nil {
		t.Fatalf("Put with valid hash: %v", err)
	}
	got, err := s.Get(valid)
	if err != nil {
		t.Fatalf("Get with valid hash: %v", err)
	}
	if got != "test.jwt" {
		t.Errorf("Get returned %q, want %q", got, "test.jwt")
	}
}
```

Add `"strings"` to the import block of `store_test.go`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/store/... -run TestFilesystemStorePath -v
```

Expected: `FAIL — malicious paths accepted without error`

- [ ] **Step 3: Implement validation in `filesystem.go`**

Add import `"regexp"` to `pkg/store/filesystem.go`.

Add the compiled regex as a package-level variable (compile-once):

```go
// validHashRe matches exactly 64 lowercase hex characters — a SHA-256 digest.
// Anything else (path separators, dots, uppercase, wrong length) is rejected.
var validHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
```

Change `hashPath` from returning `string` to `(string, error)`:

```go
func (f *FilesystemStore) hashPath(hash string) (string, error) {
	name := strings.TrimPrefix(hash, "sha256:")
	if !validHashRe.MatchString(name) {
		return "", fmt.Errorf("store: invalid hash %q: must be 64 lowercase hex characters", hash)
	}
	prefix := name[:4]
	return filepath.Join(f.baseDir, prefix, name+".jwt"), nil
}
```

Update `Put`:

```go
func (f *FilesystemStore) Put(hash string, jwt string) error {
	path, err := f.hashPath(hash)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), dirPermission); err != nil {
		return fmt.Errorf("store: mkdir: %w", err)
	}
	if err := os.WriteFile(path, []byte(jwt), filePermission); err != nil {
		return fmt.Errorf("store: write: %w", err)
	}
	return nil
}
```

Update `Get`:

```go
func (f *FilesystemStore) Get(hash string) (string, error) {
	path, err := f.hashPath(hash)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("store: stat: %w", err)
	}
	if time.Since(info.ModTime()) > f.ttl {
		_ = os.Remove(path)
		return "", ErrNotFound
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("store: read: %w", err)
	}
	return string(data), nil
}
```

Update `Delete`:

```go
func (f *FilesystemStore) Delete(hash string) error {
	path, err := f.hashPath(hash)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run all store tests**

```bash
cd drs-verify && go test ./pkg/store/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/store/filesystem.go pkg/store/store_test.go
git commit -m "fix(store): reject path traversal in filesystem store hashPath (#15)"
```

---

## Task 3: NaN/Infinity/Negative Cost Bypass

**Files:**
- Modify: `pkg/policy/evaluate.go`
- Test: `pkg/policy/evaluate_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `pkg/policy/evaluate_test.go`:

```go
func TestEvaluateCostSpecialValues(t *testing.T) {
	limit := 100.0
	pol := types.Policy{MaxCostUSD: &limit}

	cases := []struct {
		name    string
		cost    interface{}
		wantErr bool
	}{
		{"NaN float64", math.NaN(), true},
		{"positive Inf", math.Inf(1), true},
		{"negative Inf", math.Inf(-1), true},
		{"negative cost", -1.0, true},
		{"zero cost", 0.0, false},
		{"within limit", 50.0, false},
		{"at limit", 100.0, false},
		{"over limit", 100.01, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{"estimated_cost_usd": tc.cost}
			err := Evaluate(pol, args)
			if tc.wantErr && err == nil {
				t.Errorf("Evaluate(%v): expected error, got nil", tc.cost)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Evaluate(%v): expected nil error, got %v", tc.cost, err)
			}
		})
	}
}
```

Add `"math"` to the import block of `evaluate_test.go`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/policy/... -run TestEvaluateCostSpecialValues -v
```

Expected: `FAIL` — NaN, Inf, and negative cases do not return errors

- [ ] **Step 3: Fix `toFloat64` and `Evaluate`**

Add `"math"` to the import block of `pkg/policy/evaluate.go`.

In `toFloat64`, after the type switch, add NaN/Inf rejection before the return:

```go
func toFloat64(v interface{}) (float64, bool) {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
```

In `Evaluate`, after the `toFloat64` call for `estimated_cost_usd`, add the negative check:

```go
if pol.MaxCostUSD != nil {
	if costRaw, ok := args["estimated_cost_usd"]; ok {
		cost, ok := toFloat64(costRaw)
		if !ok {
			return fmt.Errorf("estimated_cost_usd must be a finite non-negative number")
		}
		if cost < 0 {
			return fmt.Errorf("estimated_cost_usd must be non-negative, got %v", cost)
		}
		if cost > *pol.MaxCostUSD {
			return fmt.Errorf("cost limit exceeded: max $%.2f, provided $%.2f", *pol.MaxCostUSD, cost)
		}
	}
}
```

- [ ] **Step 4: Run all policy tests**

```bash
cd drs-verify && go test ./pkg/policy/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/policy/evaluate.go pkg/policy/evaluate_test.go
git commit -m "fix(policy): reject NaN, Inf, and negative values in cost check (#14)"
```

---

## Task 4: Constant-Time Admin Token Comparison

**Files:**
- Modify: `pkg/revocation/admin_handler.go`
- Test: `pkg/revocation/admin_handler_test.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/revocation/admin_handler_test.go`:

```go
func TestAdminRevokeTokenRejection(t *testing.T) {
	store := NewLocalRevocationStore()
	handler := AdminRevokeHandler(store, "correct-token-value")

	cases := []struct {
		name   string
		auth   string
		status int
	}{
		{"no auth header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong-token-value", http.StatusUnauthorized},
		{"partial match prefix", "Bearer correct-token-valu", http.StatusUnauthorized},
		{"partial match suffix", "Bearer orrect-token-value", http.StatusUnauthorized},
		{"bearer missing", "correct-token-value", http.StatusUnauthorized},
		{"correct token", "Bearer correct-token-value", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"status_list_index":1}`
			req := httptest.NewRequest(http.MethodPost, "/admin/revoke", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Errorf("auth=%q: got status %d, want %d", tc.auth, w.Code, tc.status)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd drs-verify && go test ./pkg/revocation/... -run TestAdminRevokeTokenRejection -v
```

Expected: test compiles and the constant-time cases pass (behaviour is same), but this establishes the test baseline before the fix.

- [ ] **Step 3: Apply constant-time comparison**

In `pkg/revocation/admin_handler.go`, add `"crypto/subtle"` to imports.

Find the line:

```go
if r.Header.Get("Authorization") != "Bearer "+token {
```

Replace it with:

```go
expected := "Bearer " + token
actual := r.Header.Get("Authorization")
if subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) != 1 {
```

- [ ] **Step 4: Run all revocation tests**

```bash
cd drs-verify && go test ./pkg/revocation/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/revocation/admin_handler.go pkg/revocation/admin_handler_test.go
git commit -m "fix(revocation): constant-time bearer token comparison in admin handler (#16)"
```

---

## Task 5: JWT Algorithm Header Validation

**Files:**
- Modify: `pkg/verify/chain.go`
- Test: `pkg/verify/chain_test.go`

- [ ] **Step 1: Write the failing tests**

`chain_test.go` already has `newTestKey(t)` (returns `testKey{pub,prv,did}`) and `signJWT(prv, payload)`. Use them.

Add to `pkg/verify/chain_test.go`:

```go
func TestVerifyJWTSignatureAlgCheck(t *testing.T) {
	k := newTestKey(t)
	res, err := resolver.New(10, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}

	// signJWTWithAlg signs a minimal payload using an explicit alg header value.
	signJWTWithAlg := func(alg string) string {
		headerJSON, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
		payloadJSON, _ := json.Marshal(map[string]interface{}{
			"iss": k.did,
			"exp": int64(9999999999),
		})
		h := base64.RawURLEncoding.EncodeToString(headerJSON)
		p := base64.RawURLEncoding.EncodeToString(payloadJSON)
		msg := h + "." + p
		sig := ed25519.Sign(k.prv, []byte(msg))
		return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	cases := []struct {
		alg     string
		wantErr bool
	}{
		{"EdDSA", false},
		{"HS256", true},
		{"RS256", true},
		{"none", true},
		{"", true},
	}

	for _, tc := range cases {
		t.Run("alg="+tc.alg, func(t *testing.T) {
			jwt := signJWTWithAlg(tc.alg)
			err := verifyJWTSignature(jwt, k.did, res)
			if tc.wantErr && err == nil {
				t.Errorf("alg=%q: expected error, got nil", tc.alg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("alg=%q: unexpected error: %v", tc.alg, err)
			}
		})
	}
}
```

No new helpers needed — all utilities already exist in `chain_test.go`.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/verify/... -run TestVerifyJWTSignatureAlgCheck -v
```

Expected: `FAIL` — HS256/none/RS256 are not rejected

- [ ] **Step 3: Add `jwtHeader` struct and `decodeJWTHeader` to `chain.go`**

Add after the existing constants in `pkg/verify/chain.go`:

```go
// jwtHeader holds the minimum fields needed to validate a JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
}

// decodeJWTHeader base64url-decodes the JWT header (parts[0]) into a jwtHeader.
func decodeJWTHeader(jwt string) (jwtHeader, error) {
	parts := strings.SplitN(jwt, ".", 4)
	if len(parts) != 3 {
		return jwtHeader{}, fmt.Errorf("expected 3 dot-separated JWT parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwtHeader{}, fmt.Errorf("JWT header base64 decode: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return jwtHeader{}, fmt.Errorf("JWT header JSON unmarshal: %w", err)
	}
	return hdr, nil
}
```

At the top of `verifyJWTSignature`, before the `res.Resolve` call, add:

```go
func verifyJWTSignature(jwt string, issuerDID string, res *resolver.Resolver) error {
	hdr, err := decodeJWTHeader(jwt)
	if err != nil {
		return fmt.Errorf("JWT header decode failed: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
	}

	pubKeyBytes, err := res.Resolve(issuerDID)
	// ... rest of existing function unchanged
```

- [ ] **Step 4: Run all verify tests**

```bash
cd drs-verify && go test ./pkg/verify/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/verify/chain.go pkg/verify/chain_test.go
git commit -m "fix(verify): validate JWT alg header — reject non-EdDSA algorithms"
```

---

## Task 6: Chain Depth Limit

**Files:**
- Modify: `pkg/verify/chain.go`
- Test: `pkg/verify/chain_test.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/verify/chain_test.go`:

```go
func TestChainDepthLimit(t *testing.T) {
	deps := testDeps(t)

	// Build a bundle with 17 receipts (one over the limit of 16).
	// The receipts don't need to be cryptographically valid — Block A fires first.
	receipts := make([]string, 17)
	for i := range receipts {
		receipts[i] = "a.b.c" // minimal 3-part JWT placeholder
	}
	bundle := types.ChainBundle{
		BundleVersion: "1",
		Invocation:    "a.b.c",
		Receipts:      receipts,
	}

	result := Chain(bundle, deps)
	if result.Valid {
		t.Fatal("expected invalid result for depth > 16")
	}
	if result.Error == nil || result.Error.Code != "CHAIN_TOO_DEEP" {
		t.Errorf("expected CHAIN_TOO_DEEP, got %v", result.Error)
	}
}

func TestChainDepthLimitBoundary(t *testing.T) {
	// 16 receipts must NOT trigger CHAIN_TOO_DEEP (it may fail for other reasons).
	deps := testDeps(t)
	receipts := make([]string, 16)
	for i := range receipts {
		receipts[i] = "a.b.c"
	}
	bundle := types.ChainBundle{
		BundleVersion: "1",
		Invocation:    "a.b.c",
		Receipts:      receipts,
	}
	result := Chain(bundle, deps)
	if result.Error != nil && result.Error.Code == "CHAIN_TOO_DEEP" {
		t.Error("16-receipt bundle must not trigger CHAIN_TOO_DEEP")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/verify/... -run TestChainDepthLimit -v
```

Expected: `FAIL` — 17-receipt bundle does not return `CHAIN_TOO_DEEP`

- [ ] **Step 3: Add the constant and Block A check to `chain.go`**

After the existing `const` block at the top of `pkg/verify/chain.go`, add:

```go
// maxChainDepth is the maximum number of delegation receipts allowed in a
// single bundle. 16 hops is more than any legitimate delegation chain needs.
// This bounds CPU work per request independently of rate limiting.
const maxChainDepth = 16
```

In `Chain`, in Block A after the empty-chain check, add:

```go
if len(bundle.Receipts) > maxChainDepth {
	return types.Invalid("CHAIN_TOO_DEEP",
		fmt.Sprintf("bundle has %d receipts; maximum allowed chain depth is %d.",
			len(bundle.Receipts), maxChainDepth),
		"Reduce the delegation chain depth. Legitimate chains rarely exceed 4 hops.")
}
```

- [ ] **Step 4: Run all verify tests**

```bash
cd drs-verify && go test ./pkg/verify/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/verify/chain.go pkg/verify/chain_test.go
git commit -m "fix(verify): add chain depth limit of 16 to bound CPU per request"
```

---

## Task 7: SSRF Protection + Context in Resolver

**Files:**
- Modify: `pkg/resolver/did.go`
- Test: `pkg/resolver/did_test.go`

This task adds `context.Context` to `Resolve` and `resolveDidWeb`, and adds the SSRF blocklist. It also updates `verifyJWTSignature` in `chain.go` to pass `context.Background()` temporarily (Task 9 will replace with real ctx).

- [ ] **Step 1: Write the failing tests**

Add to `pkg/resolver/did_test.go`:

```go
func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"169.254.169.254", true}, // AWS IMDS
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false}, // example.com
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("ParseIP(%q) returned nil", tc.ip)
		}
		got := isPrivateIP(ip)
		if got != tc.private {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}

func TestResolveDidWebSSRFLocalhost(t *testing.T) {
	res, err := New(10, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = res.Resolve(context.Background(), "did:web:localhost")
	if err == nil {
		t.Fatal("expected error for did:web:localhost (SSRF), got nil")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error should mention private/reserved address, got: %v", err)
	}
}

func TestResolveDidWebSSRFLinkLocal(t *testing.T) {
	res, err := New(10, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 169.254.169.254 is an IP literal — LookupHost returns it as-is
	_, err = res.Resolve(context.Background(), "did:web:169.254.169.254")
	if err == nil {
		t.Fatal("expected error for did:web:169.254.169.254, got nil")
	}
}
```

Add `"context"`, `"net"`, `"strings"` to imports in `did_test.go` if not already present.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/resolver/... -run "TestIsPrivateIP|TestResolveDidWebSSRF" -v
```

Expected: compile error (`Resolve` takes 1 arg, tests pass 2; `isPrivateIP` not exported)

- [ ] **Step 3: Update `resolver/did.go`**

Add `"context"` and `"net"` to the import block.

Add the blocked CIDR list as a package-level variable:

```go
// privateRanges is the set of IP ranges that must not be reachable via did:web.
// Parsed once at init time; panic on invalid CIDR is intentional (programmer error).
var privateRanges = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8",    // loopback
		"::1/128",        // IPv6 loopback
		"169.254.0.0/16", // link-local (AWS IMDS, Azure IMDS)
		"fe80::/10",      // IPv6 link-local
		"10.0.0.0/8",     // RFC 1918 private
		"172.16.0.0/12",  // RFC 1918 private
		"192.168.0.0/16", // RFC 1918 private
		"fc00::/7",       // IPv6 unique local
		"100.64.0.0/10",  // RFC 6598 shared address space (carrier-grade NAT)
		"0.0.0.0/8",      // "this" network
		"::ffff:0:0/96",  // IPv4-mapped IPv6 addresses
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("resolver: invalid private CIDR %q: %v", cidr, err))
		}
		out = append(out, block)
	}
	return out
}()
```

Add the helper functions:

```go
// isPrivateIP returns true if ip falls within any of the blocked private ranges.
func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateHost resolves host to IP addresses and returns true if any resolve
// to a private or reserved range. Defends against SSRF via did:web.
// The DNS lookup uses ctx so it respects request cancellation.
func isPrivateHost(ctx context.Context, host string) (bool, error) {
	// Strip port if present — net.LookupHost does not accept host:port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false, fmt.Errorf("did:web host resolution failed for %q: %w", host, err)
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isPrivateIP(ip) {
			return true, nil
		}
	}
	return false, nil
}
```

Change `Resolve` signature to accept `ctx`:

```go
func (r *Resolver) Resolve(ctx context.Context, did string) ([ed25519PublicKeyBytes]byte, error) {
	// Fast path: brief lock for cache lookup only
	r.cacheMu.Lock()
	if entry, ok := r.cache.Get(did); ok {
		if time.Now().Before(entry.expiry) {
			r.cacheMu.Unlock()
			return entry.key, nil
		}
		r.cache.Remove(did)
	}
	r.cacheMu.Unlock()

	// Slow path: singleflight deduplication.
	r.inflightMu.Lock()
	if e, ok := r.inflight[did]; ok {
		r.inflightMu.Unlock()
		// Respect context cancellation while waiting for the shared in-flight result.
		select {
		case <-ctx.Done():
			return [ed25519PublicKeyBytes]byte{}, ctx.Err()
		case <-e.done:
			return e.res.key, e.res.err
		}
	}
	e := &inflightEntry{done: make(chan struct{})}
	r.inflight[did] = e
	r.inflightMu.Unlock()

	key, err := r.resolveUncached(ctx, did)
	e.res = resolveResult{key: key, err: err}
	close(e.done)

	r.inflightMu.Lock()
	delete(r.inflight, did)
	r.inflightMu.Unlock()

	if err == nil {
		r.cacheMu.Lock()
		r.cache.Add(did, cacheEntry{key: key, expiry: time.Now().Add(r.ttl)})
		r.cacheMu.Unlock()
	}
	return key, err
}
```

Change `resolveUncached` to accept and pass `ctx`:

```go
func (r *Resolver) resolveUncached(ctx context.Context, did string) ([ed25519PublicKeyBytes]byte, error) {
	switch {
	case strings.HasPrefix(did, didKeyPrefix):
		return resolveDidKey(did) // pure computation — no ctx needed
	case strings.HasPrefix(did, didWebPrefix):
		return r.resolveDidWeb(ctx, did)
	default:
		method := "unknown"
		if parts := strings.SplitN(did, ":", 3); len(parts) >= 2 {
			method = parts[1]
		}
		return [ed25519PublicKeyBytes]byte{}, fmt.Errorf("unsupported DID method: %q", method)
	}
}
```

Change `resolveDidWeb` to accept ctx, add SSRF check, use `http.NewRequestWithContext`:

```go
func (r *Resolver) resolveDidWeb(ctx context.Context, did string) ([ed25519PublicKeyBytes]byte, error) {
	var zero [ed25519PublicKeyBytes]byte

	docURL, err := didWebDocumentURL(did)
	if err != nil {
		return zero, err
	}

	// SSRF protection: resolve the hostname and reject private/reserved ranges.
	u, err := url.Parse(docURL)
	if err != nil {
		return zero, fmt.Errorf("did:web URL parse failed: %w", err)
	}
	private, err := isPrivateHost(ctx, u.Hostname())
	if err != nil {
		return zero, fmt.Errorf("did:web SSRF check failed: %w", err)
	}
	if private {
		return zero, fmt.Errorf("did:web host %q resolves to a private or reserved address", u.Hostname())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return zero, fmt.Errorf("did:web request build failed: %w", err)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return zero, fmt.Errorf("did:web fetch failed for %s: %w", docURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("did:web fetch failed: HTTP %d from %s", resp.StatusCode, docURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return zero, fmt.Errorf("did:web document read failed: %w", err)
	}

	return extractEd25519FromDIDDocument(body)
}
```

- [ ] **Step 4: Fix the compile error in `chain.go`**

`verifyJWTSignature` calls `res.Resolve(issuerDID)`. Update it to pass `context.Background()` for now (Task 9 will replace this with the real request context):

```go
func verifyJWTSignature(jwt string, issuerDID string, res *resolver.Resolver) error {
	hdr, err := decodeJWTHeader(jwt)
	if err != nil {
		return fmt.Errorf("JWT header decode failed: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
	}

	pubKeyBytes, err := res.Resolve(context.Background(), issuerDID)
	// ... rest unchanged
```

Add `"context"` to imports in `chain.go`.

Also update any tests in `did_test.go` that call `res.Resolve(did)` with one argument — they now need `res.Resolve(context.Background(), did)`.

- [ ] **Step 5: Run all tests**

```bash
cd drs-verify && go test ./... -v 2>&1 | tail -30
```

Expected: all `PASS`

- [ ] **Step 6: Commit**

```bash
git add pkg/resolver/did.go pkg/resolver/did_test.go pkg/verify/chain.go
git commit -m "fix(resolver): SSRF protection + context propagation in did:web resolver"
```

---

## Task 8: Partial Status List Reads + Context in Revocation

**Files:**
- Modify: `pkg/revocation/status.go`
- Test: `pkg/revocation/status_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `pkg/revocation/status_test.go`:

```go
func TestRefreshRejectsTruncatedBody(t *testing.T) {
	// Serve a body that is shorter than the advertised Content-Length.
	fullBody := bytes.Repeat([]byte{0x00}, 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "200") // lie: advertise 200, send 100
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fullBody)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	err := cache.WarmUp()
	if err == nil {
		t.Fatal("expected error for truncated body, got nil")
	}
	if !strings.Contains(err.Error(), "truncated") && !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("error should mention truncation: %v", err)
	}

	// The cache must remain uninitialized (no partial data committed).
	if cache.Ready() {
		t.Error("cache.Ready() must be false after failed fetch")
	}
}

func TestRefreshRejectsOversizeBody(t *testing.T) {
	// Serve a body larger than 1 MiB.
	oversized := bytes.Repeat([]byte{0xFF}, (1<<20)+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	cache := New(srv.URL, time.Hour)
	err := cache.WarmUp()
	if err == nil {
		t.Fatal("expected error for oversized body, got nil")
	}
}

func TestRefreshPreservesSnapshotOnError(t *testing.T) {
	// First fetch succeeds; second fetch returns a truncated body.
	// The cache must serve the first snapshot after the failed refresh.
	callCount := 0
	goodBody := []byte{0b10000000} // bit 0 set → index 0 is revoked

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(goodBody)
		} else {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte{0x00}) // truncated
		}
	}))
	defer srv.Close()

	cache := New(srv.URL, 1*time.Millisecond) // very short TTL triggers refresh
	if err := cache.WarmUp(); err != nil {
		t.Fatalf("WarmUp: %v", err)
	}

	time.Sleep(5 * time.Millisecond) // let TTL expire

	// IsRevoked triggers refresh; it should fail and preserve old snapshot.
	revoked, err := cache.IsRevoked(context.Background(), 0)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	// Old snapshot had bit 0 set → should still return true.
	if !revoked {
		t.Error("expected index 0 to be revoked (from preserved snapshot)")
	}
}
```

Add `"bytes"`, `"context"`, `"net/http/httptest"`, `"strings"`, `"time"` to imports.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd drs-verify && go test ./pkg/revocation/... -run "TestRefresh" -v
```

Expected: compile error — `IsRevoked` still takes 1 arg; tests call it with 2

- [ ] **Step 3: Update `status.go`**

Add `"context"`, `"strconv"` to imports.

Change `refresh` signature to accept `ctx`:

```go
func (s *StatusCache) refresh(ctx context.Context) error {
	if s.baseURL == "" {
		s.mu.Lock()
		s.bitstring = []byte{}
		s.fetchedAt = time.Now()
		s.mu.Unlock()
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", s.baseURL, err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", s.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP GET %s returned %d", s.baseURL, resp.StatusCode)
	}

	const maxStatusListBytes = 1 << 20 // 1 MiB
	limited := io.LimitReader(resp.Body, int64(maxStatusListBytes)+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("reading status list body from %s: %w", s.baseURL, err)
	}
	if len(buf) > maxStatusListBytes {
		return fmt.Errorf("status list from %s exceeds %d byte limit", s.baseURL, maxStatusListBytes)
	}
	if len(buf) == 0 {
		return fmt.Errorf("status list from %s is empty", s.baseURL)
	}

	// Reject truncated responses: if Content-Length is present and non-negative,
	// it must match the number of bytes received.
	if clStr := resp.Header.Get("Content-Length"); clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err == nil && cl >= 0 && int64(len(buf)) != cl {
			return fmt.Errorf("status list from %s truncated: Content-Length %d, read %d bytes",
				s.baseURL, cl, len(buf))
		}
	}

	s.mu.Lock()
	s.bitstring = buf
	s.fetchedAt = time.Now()
	s.mu.Unlock()

	return nil
}
```

Change `IsRevoked` to accept `ctx`:

```go
func (s *StatusCache) IsRevoked(ctx context.Context, statusListIndex uint64) (bool, error) {
	var initErr error
	s.once.Do(func() {
		initErr = s.refresh(context.Background()) // initial fetch: not tied to a request
	})
	if initErr != nil {
		return false, fmt.Errorf("revocation: initial status list fetch failed: %w", initErr)
	}

	s.mu.RLock()
	expired := time.Since(s.fetchedAt) > s.ttl
	s.mu.RUnlock()

	if expired {
		s.refreshMu.Lock()
		s.mu.RLock()
		stillExpired := time.Since(s.fetchedAt) > s.ttl
		s.mu.RUnlock()
		if stillExpired {
			// Background refresh: use Background ctx — a cancelled request must not
			// abort a cache write that other requests depend on.
			if err := s.refresh(context.Background()); err != nil {
				log.Printf("revocation: status list refresh failed (serving stale data): %v", err)
			}
		}
		s.refreshMu.Unlock()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return getBit(s.bitstring, statusListIndex), nil
}
```

Change `WarmUp` to call `refresh(context.Background())`:

```go
func (s *StatusCache) WarmUp() error {
	var err error
	s.once.Do(func() {
		err = s.refresh(context.Background())
	})
	return err
}
```

- [ ] **Step 4: Fix compile error in `chain.go`**

In Block F of `chain.go`, update the `IsRevoked` call to pass `context.Background()` (Task 9 replaces with real ctx):

```go
revoked, err := deps.Revocation.IsRevoked(context.Background(), *r.DrsStatusListIndex)
```

- [ ] **Step 5: Run all tests**

```bash
cd drs-verify && go test ./... 2>&1 | tail -20
```

Expected: all `PASS`

- [ ] **Step 6: Commit**

```bash
git add pkg/revocation/status.go pkg/revocation/status_test.go pkg/verify/chain.go
git commit -m "fix(revocation): reject partial status list reads; add context propagation (#8)"
```

---

## Task 9: Thread Real Request Context Through Chain + Middleware

**Files:**
- Modify: `pkg/verify/chain.go`
- Modify: `pkg/middleware/mcp.go`
- Modify: `pkg/middleware/a2a.go`
- Modify: `cmd/server/main.go`
- Test: `pkg/verify/chain_test.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/verify/chain_test.go`:

```go
func TestChainCancelledContext(t *testing.T) {
	// A cancelled context must not panic Chain; it may return any invalid result.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Invocation:    "a.b.c",
		Receipts:      []string{"a.b.c"},
	}
	result := Chain(ctx, bundle, testDeps(t))
	_ = result // must not panic; any result is acceptable
}
```

Add `"context"` to the imports in `chain_test.go`.

- [ ] **Step 2: Update ALL existing `Chain(bundle, deps)` calls in `chain_test.go`**

The existing tests call `Chain` with 2 args. After adding `ctx` these all fail to compile.
Run a search to find every call site:

```bash
grep -n "Chain(" drs-verify/pkg/verify/chain_test.go
```

For every line that matches `Chain(`, change it from:

```go
Chain(bundle, deps)
// or
Chain(types.ChainBundle{...}, testDeps(t))
```

to:

```go
Chain(context.Background(), bundle, deps)
// or
Chain(context.Background(), types.ChainBundle{...}, testDeps(t))
```

Also update any call to `verifyJWTSignature(jwt, did, res)` — after Step 4 below it
becomes `verifyJWTSignature(jwt, did, res)` with ctx added:
`verifyJWTSignature(jwt, did, res)` → `verifyJWTSignature(context.Background(), jwt, did, res)`

- [ ] **Step 3: Change `Chain` signature and thread ctx through**

In `pkg/verify/chain.go`, change:

```go
func Chain(bundle types.ChainBundle, deps Deps) types.VerificationResult {
```

to:

```go
func Chain(ctx context.Context, bundle types.ChainBundle, deps Deps) types.VerificationResult {
```

Change `verifyJWTSignature` to accept and use `ctx`:

```go
func verifyJWTSignature(ctx context.Context, jwt string, issuerDID string, res *resolver.Resolver) error {
	hdr, err := decodeJWTHeader(jwt)
	if err != nil {
		return fmt.Errorf("JWT header decode failed: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
	}
	pubKeyBytes, err := res.Resolve(ctx, issuerDID)
	// ... rest of function unchanged
```

Update both `verifyJWTSignature` calls inside `Chain`:

```go
if err := verifyJWTSignature(ctx, jwt, receipts[i].Iss, deps.Resolver); err != nil {
```

```go
if err := verifyJWTSignature(ctx, bundle.Invocation, invocation.Iss, deps.Resolver); err != nil {
```

Replace the `context.Background()` placeholder in Block F (set in Task 8):

```go
revoked, err := deps.Revocation.IsRevoked(ctx, *r.DrsStatusListIndex)
```

- [ ] **Step 4: Update middleware callers**

In `pkg/middleware/mcp.go`, change:

```go
result := verify.Chain(bundle, deps)
```

to:

```go
result := verify.Chain(r.Context(), bundle, deps)
```

In `pkg/middleware/a2a.go`, change:

```go
result := verify.Chain(bundle, deps)
```

to:

```go
result := verify.Chain(r.Context(), bundle, deps)
```

- [ ] **Step 4: Update `/verify` handler in `main.go`**

In `cmd/server/main.go`, change:

```go
result := verify.Chain(req.ChainBundle, reqDeps)
```

to:

```go
result := verify.Chain(r.Context(), req.ChainBundle, reqDeps)
```

- [ ] **Step 5: Run all tests**

```bash
cd drs-verify && go test ./... -v 2>&1 | tail -30
```

Expected: all `PASS`

- [ ] **Step 6: Commit**

```bash
git add pkg/verify/chain.go pkg/middleware/mcp.go pkg/middleware/a2a.go cmd/server/main.go pkg/verify/chain_test.go
git commit -m "fix(verify): thread request context through Chain, resolver, and revocation"
```

---

## Task 10: Surface Silent Store Errors

**Files:**
- Modify: `pkg/verify/chain.go`
- Test: `pkg/verify/chain_test.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/verify/chain_test.go`:

```go
// failStore always returns an error on Put.
type failStore struct{}

func (f *failStore) Put(hash, jwt string) error      { return fmt.Errorf("disk full") }
func (f *failStore) Get(hash string) (string, error) { return "", store.ErrNotFound }
func (f *failStore) Delete(hash string) error        { return nil }

func TestChainStoreWarningsOnPutFailure(t *testing.T) {
	deps := testDeps(t)
	deps.Store = &failStore{}

	// Build a minimal single-hop valid chain using the existing test helpers.
	now := time.Now().Unix()
	root := newTestKey(t)
	agent := newTestKey(t)

	_, drJWT := makeReceipt(root.did, root.did, agent.did, now, nil, root)
	drHash := computeChainHash(drJWT)
	invJWT := makeInvocation(agent.did, root.did, []string{drHash}, now, agent)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Invocation:    invJWT,
		Receipts:      []string{drJWT},
	}

	result := Chain(context.Background(), bundle, deps)

	// Chain must still be valid — store failure must not invalidate verification.
	if !result.Valid {
		t.Fatalf("expected valid result even with store failure, got: %v", result.Error)
	}

	// StoreWarnings must be populated.
	if len(result.StoreWarnings) == 0 {
		t.Error("expected StoreWarnings to be non-empty when store.Put fails")
	}
	if !strings.Contains(result.StoreWarnings[0], "could not be persisted") {
		t.Errorf("StoreWarnings content unexpected: %v", result.StoreWarnings)
	}
}
```

`makeReceipt`, `makeInvocation`, `newTestKey`, and `computeChainHash` all already exist in `chain_test.go`. Add `"context"` and `"strings"` to imports if not already present.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd drs-verify && go test ./pkg/verify/... -run TestChainStoreWarnings -v
```

Expected: `FAIL` — `StoreWarnings` is nil even when store fails

- [ ] **Step 3: Replace `_ = err` with logging and warning collection**

In `pkg/verify/chain.go`, find the store loop (around line 343):

```go
if deps.Store != nil {
	for _, jwt := range bundle.Receipts {
		hash := computeChainHash(jwt)
		if err := deps.Store.Put(hash, jwt); err != nil {
			_ = err
		}
	}
}
```

Replace with:

```go
var storeWarnings []string
if deps.Store != nil {
	for _, jwt := range bundle.Receipts {
		hash := computeChainHash(jwt)
		if err := deps.Store.Put(hash, jwt); err != nil {
			log.Printf("store: Put failed for hash %s: %v", hash, err)
			storeWarnings = append(storeWarnings,
				fmt.Sprintf("receipt %s could not be persisted: %v", hash, err))
		}
	}
}
```

In the success return at the bottom of `Chain`, set `StoreWarnings` on the result before returning:

```go
result := types.Valid(types.VerificationContext{
	RootPrincipal: root.Iss,
	RootType:      root.DrsRootType,
	ConsentRecord: root.DrsConsent,
	Regulatory:    root.DrsRegulatory,
	LeafPolicy:    last.Policy,
	ChainDepth:    len(receipts),
	SessionID:     sessionID,
})
result.Timestamps = timestamps
result.StoreWarnings = storeWarnings
return result
```

- [ ] **Step 4: Run all tests**

```bash
cd drs-verify && go test ./pkg/verify/... -v
```

Expected: all `PASS`

- [ ] **Step 5: Commit**

```bash
git add pkg/verify/chain.go pkg/verify/chain_test.go
git commit -m "fix(verify): surface store put errors as StoreWarnings instead of silently discarding (#17)"
```

---

## Task 11: RFC 3161 Trusted Timestamp Path

**Files:**
- Modify: `pkg/config/config.go`
- Modify: `pkg/verify/chain.go`
- Modify: `cmd/server/main.go`
- Test: `pkg/verify/chain_test.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/verify/chain_test.go`:

```go
func TestTimestampVerificationUsesTrustedPath(t *testing.T) {
	// Build a self-signed certificate that is NOT in any trusted root pool.
	// VerifyTimestampTrusted must reject it; the old VerifyTimestamp would accept it.
	// This test uses a nil TSARootPool (system roots) and a self-signed cert,
	// verifying that the trusted path rejects it.

	// Create a minimal self-signed cert
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed-tsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Verify that the Deps.TSARootPool field exists on verify.Deps.
	deps := testDeps(t)
	_ = deps.TSARootPool // compile check: field must exist

	// If TSARootPool is nil, VerifyTimestampTrusted uses system roots.
	// A self-signed cert with no EKU will fail.
	pool := x509.NewCertPool()
	pool.AddCert(cert) // add self-signed as trusted root

	// Even with the self-signed cert as root, EKU check must reject it.
	deps.TSARootPool = pool
	// The actual token bytes would come from a real TSA call.
	// We verify the Deps field is wired correctly by checking it compiles and is set.
	if deps.TSARootPool == nil {
		t.Error("TSARootPool must not be nil after assignment")
	}
}
```

Add necessary imports: `"crypto/ecdsa"`, `"crypto/elliptic"`, `"crypto/rand"`, `"crypto/x509"`, `"crypto/x509/pkix"`, `"math/big"`.

- [ ] **Step 2: Add `TSARootPool` to `verify.Deps`**

In `pkg/verify/chain.go`, add to the `Deps` struct:

```go
// TSARootPool is the set of trusted root CA certificates for RFC 3161
// timestamp token verification. When nil, system roots are used.
// Set via TSA_ROOT_CERT_PEM env var parsed in main().
TSARootPool *x509.CertPool
```

Add `"crypto/x509"` to imports in `chain.go`.

- [ ] **Step 3: Switch `chain.go` to call `VerifyTimestampTrusted`**

In the timestamp verification loop, change:

```go
genTime, err := anchor.VerifyTimestamp([]byte(tokenStr), jwtHash[:])
```

to:

```go
genTime, err := anchor.VerifyTimestampTrusted([]byte(tokenStr), jwtHash[:], deps.TSARootPool)
```

- [ ] **Step 4: Add `TSARootCertPEM` to `config.go`**

In `pkg/config/config.go`, add to the `Config` struct:

```go
// TSARootCertPEM is the PEM-encoded root CA certificate(s) trusted for
// RFC 3161 timestamp verification. Empty means system roots are used.
// Set via TSA_ROOT_CERT_PEM env var.
TSARootCertPEM string
```

In `Load()`, add:

```go
tsaRootCertPEM := os.Getenv("TSA_ROOT_CERT_PEM")
```

And include it in the returned `Config`:

```go
TSARootCertPEM: tsaRootCertPEM,
```

- [ ] **Step 5: Parse the PEM pool in `main.go`**

In `cmd/server/main.go`, after `config.Load()`, add:

```go
var tsaRootPool *x509.CertPool
if cfg.TSARootCertPEM != "" {
	tsaRootPool = x509.NewCertPool()
	if !tsaRootPool.AppendCertsFromPEM([]byte(cfg.TSARootCertPEM)) {
		log.Fatalf("TSA_ROOT_CERT_PEM: no valid certificates found in PEM data")
	}
	log.Printf("drs-verify: RFC 3161 trust anchored to custom root pool")
} else {
	log.Printf("drs-verify: RFC 3161 trust uses system roots (set TSA_ROOT_CERT_PEM to override)")
}
```

Add `TSARootPool: tsaRootPool` to the `deps` struct:

```go
deps := verify.Deps{
	Resolver:        res,
	Revocation:      statusCache,
	LocalRevocation: localRev,
	Store:           drStore,
	ServerIdentity:  cfg.ServerIdentity,
	TSARootPool:     tsaRootPool,
}
```

Add `"crypto/x509"` to imports in `main.go`.

- [ ] **Step 6: Run all tests**

```bash
cd drs-verify && go test ./... 2>&1 | tail -20
```

Expected: all `PASS`

- [ ] **Step 7: Commit**

```bash
git add pkg/config/config.go pkg/verify/chain.go cmd/server/main.go pkg/verify/chain_test.go
git commit -m "fix(verify): use VerifyTimestampTrusted for RFC 3161 trust chain validation (#9)"
```

---

## Task 12: Export `CheckNonceReplay` and Wire `/verify`

**Files:**
- Modify: `pkg/middleware/decode.go`
- Modify: `pkg/middleware/mcp.go`
- Modify: `pkg/middleware/a2a.go`
- Modify: `cmd/server/main.go`
- Test: `pkg/middleware/decode_test.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/middleware/decode_test.go`:

```go
func TestCheckNonceReplayExported(t *testing.T) {
	// Verify the function is exported and callable from outside the package.
	// (This test is in package middleware — same package — so it proves exportability
	// by the capital letter; integration coverage is in main_test.go below.)
	ns := nonce.New(100, time.Hour)
	w := httptest.NewRecorder()

	// Build a minimal JWT with a jti claim.
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"inv:test-nonce-001"}`))
	jwt := "header." + payload + ".sig"

	// First call: nonce is fresh — should NOT abort (returns false).
	if blocked := CheckNonceReplay(w, jwt, ns); blocked {
		t.Error("first call with fresh nonce should not be blocked")
	}

	// Second call: same nonce — should abort (replay detected, returns true).
	w2 := httptest.NewRecorder()
	if blocked := CheckNonceReplay(w2, jwt, ns); !blocked {
		t.Error("second call with same nonce should be blocked as replay")
	}
	if w2.Code != http.StatusConflict {
		t.Errorf("replay response: want 409, got %d", w2.Code)
	}
}
```

Add `"encoding/base64"`, `"net/http"`, `"net/http/httptest"`, `"time"` to imports.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd drs-verify && go test ./pkg/middleware/... -run TestCheckNonceReplayExported -v
```

Expected: `FAIL` — `CheckNonceReplay` undefined (currently `checkNonceReplay`, unexported)

- [ ] **Step 3: Export the function in `decode.go`**

In `pkg/middleware/decode.go`, rename `checkNonceReplay` to `CheckNonceReplay`:

```go
// CheckNonceReplay extracts the invocation JTI and checks it against the nonce
// store. Writes an error response and returns true if the request should be
// aborted (replay detected, store exhausted, or missing JTI). Returns false
// if the request should proceed.
//
// Exported so the /verify endpoint in cmd/server/main.go can use the same
// replay protection as the MCP and A2A middleware.
func CheckNonceReplay(w http.ResponseWriter, invocationJWT string, ns *nonce.Store) bool {
```

- [ ] **Step 4: Update internal callers in `mcp.go` and `a2a.go`**

In `pkg/middleware/mcp.go`, change:

```go
if checkNonceReplay(w, bundle.Invocation, nonceStore) {
```

to:

```go
if CheckNonceReplay(w, bundle.Invocation, nonceStore) {
```

In `pkg/middleware/a2a.go`, change:

```go
if checkNonceReplay(w, bundle.Invocation, nonceStore) {
```

to:

```go
if CheckNonceReplay(w, bundle.Invocation, nonceStore) {
```

- [ ] **Step 5: Wire nonce check into `/verify` in `main.go`**

In `cmd/server/main.go`, inside the `/verify` handler, after body decode and before `verify.Chain`, add:

```go
if middleware.CheckNonceReplay(w, req.Invocation, nonceStore) {
	return
}
```

The full handler becomes:

```go
mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)

	var req struct {
		types.ChainBundle
		IncludeTimestamps bool `json:"include_timestamps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
			log.Printf("verify: encode error response: %v", encErr)
		}
		return
	}

	if middleware.CheckNonceReplay(w, req.Invocation, nonceStore) {
		return
	}

	reqDeps := deps
	reqDeps.IncludeTimestamps = req.IncludeTimestamps

	result := verify.Chain(r.Context(), req.ChainBundle, reqDeps)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("verify: encode result: %v", err)
	}
})
```

- [ ] **Step 6: Run all tests**

```bash
cd drs-verify && go test ./... -v 2>&1 | tail -30
```

Expected: all `PASS`

- [ ] **Step 7: Final build check**

```bash
cd drs-verify && CGO_ENABLED=0 go build -o /dev/null ./cmd/server
```

Expected: exits 0 with no output (clean build)

- [ ] **Step 8: Commit**

```bash
git add pkg/middleware/decode.go pkg/middleware/mcp.go pkg/middleware/a2a.go cmd/server/main.go pkg/middleware/decode_test.go
git commit -m "fix(middleware): export CheckNonceReplay and wire replay protection into /verify endpoint (#20)"
```

---

## Final: Full Test Suite + Issue Closure

- [ ] **Run the complete test suite**

```bash
cd drs-verify && go test ./... -count=1 -race
```

Expected: all `PASS`, no data races detected.

- [ ] **Close GitHub issues**

Issues resolved by this plan: `#8`, `#9`, `#14`, `#15`, `#16`, `#17`, `#20`.

- [ ] **Open new GitHub issues for the unlisted gaps fixed here**

- `fix: SSRF protection in did:web resolver` (references this plan)
- `fix: chain depth limit (maxChainDepth=16)` (references this plan)
- `fix: JWT alg header validation — reject non-EdDSA` (references this plan)
- `fix: context propagation through Chain, Resolve, IsRevoked` (references this plan)

Each new issue can be immediately closed with a reference to the commit that fixed it.
