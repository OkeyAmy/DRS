package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/nonce"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

func testDeps(t *testing.T) verify.Deps {
	t.Helper()
	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	return verify.Deps{Resolver: res}
}

func encodeBundle(t *testing.T, bundle types.ChainBundle) string {
	t.Helper()
	b, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("json.Marshal bundle: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestMCPMiddlewareRejects401WhenNoBundleHeader(t *testing.T) {
	handler := MCPMiddleware(testDeps(t), nil, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when X-DRS-Bundle is missing")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when X-DRS-Bundle is missing, got %d", rr.Code)
	}
}

func TestOptionalMCPMiddlewarePassesThroughWhenNoBundleHeader(t *testing.T) {
	called := false
	handler := OptionalMCPMiddleware(testDeps(t), nil, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler should be called when using OptionalMCPMiddleware with no bundle")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMCPMiddlewareReturnsBadRequestForInvalidBase64(t *testing.T) {
	handler := MCPMiddleware(testDeps(t), nil, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for invalid bundle")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	req.Header.Set("X-DRS-Bundle", "not-valid-base64url!!!")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid base64url, got %d", rr.Code)
	}
}

func TestMCPMiddlewareReturnsForbiddenForInvalidBundle(t *testing.T) {
	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      nil,
		Invocation:    "x",
	}

	handler := MCPMiddleware(testDeps(t), nil, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for invalid bundle")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	req.Header.Set("X-DRS-Bundle", encodeBundle(t, bundle))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid bundle, got %d", rr.Code)
	}

	var result types.VerificationResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if result.Valid {
		t.Error("response should indicate invalid")
	}
	if result.Error == nil || result.Error.Code == "" {
		t.Error("response should include error code")
	}
}

func TestGetVerificationContextReturnsNilWhenAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := GetVerificationContext(req.Context())
	if ctx != nil {
		t.Error("expected nil when middleware was not applied")
	}
}

func TestMCPMiddleware401ResponseIsJSON(t *testing.T) {
	handler := MCPMiddleware(testDeps(t), nil, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] == "" {
		t.Error("response should include an error message")
	}
}

func fakeJWTWithJTI(t *testing.T, jti string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload, _ := json.Marshal(map[string]string{"jti": jti})
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadB64 + "." + sig
}

func TestMCPMiddlewareInvalidSigDoesNotPreConsumeNonce(t *testing.T) {
	// Regression: committing the nonce before signature verification lets an
	// attacker with a known JTI pre-consume legitimate nonces via invalid-sig
	// requests. After the fix, two invalid-sig requests sharing a JTI both
	// return 403 (verify failed) and the JTI is never committed to the store.
	ns := nonce.New(100, time.Hour)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{fakeJWTWithJTI(t, "dr:r1")},
		Invocation:    fakeJWTWithJTI(t, "inv:replay-test"),
	}

	handler := MCPMiddleware(testDeps(t), ns, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	req1.Header.Set("X-DRS-Bundle", encodeBundle(t, bundle))
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusForbidden {
		t.Errorf("first request (invalid sig): expected 403, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	req2.Header.Set("X-DRS-Bundle", encodeBundle(t, bundle))
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusForbidden {
		t.Errorf("second request (invalid sig): expected 403, got %d (nonce was pre-consumed on invalid sig)", rr2.Code)
	}

	// The JTI must NOT have been recorded in the nonce store — a legitimate
	// future request with this JTI must still be acceptable.
	if err := ns.Check("inv:replay-test"); err != nil {
		t.Errorf("legitimate JTI was wrongly consumed by invalid-sig request: %v", err)
	}
}

func TestMCPMiddlewareNilNonceStoreSkipsCheck(t *testing.T) {
	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      nil,
		Invocation:    "x",
	}

	handler := MCPMiddleware(testDeps(t), nil, BindingModeOff, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for invalid bundle")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp/tools/call", nil)
	req.Header.Set("X-DRS-Bundle", encodeBundle(t, bundle))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}
