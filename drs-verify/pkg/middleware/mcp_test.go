package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	handler := MCPMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := OptionalMCPMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := MCPMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	handler := MCPMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	handler := MCPMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
