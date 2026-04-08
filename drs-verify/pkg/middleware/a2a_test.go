package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/drs-protocol/drs-verify/pkg/types"
)

func TestA2AMiddlewareRejects401WhenNoBundleHeader(t *testing.T) {
	handler := A2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when X-DRS-Bundle is missing")
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when X-DRS-Bundle is missing, got %d", rr.Code)
	}
}

func TestOptionalA2AMiddlewarePassesThroughWhenNoBundleHeader(t *testing.T) {
	called := false
	handler := OptionalA2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler should be called when using OptionalA2AMiddleware with no bundle")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestA2AMiddlewareReturnsBadRequestForInvalidBase64(t *testing.T) {
	handler := A2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
	req.Header.Set("X-DRS-Bundle", "not-valid-base64url!!!")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestA2AMiddlewareReturnsForbiddenForInvalidBundle(t *testing.T) {
	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      nil,
		Invocation:    "x",
	}

	handler := A2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for an invalid bundle")
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
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
		t.Error("response body should indicate invalid")
	}
	if result.Error == nil || result.Error.Code == "" {
		t.Error("response body should include an error code")
	}
}

func TestA2AMiddleware401ResponseIsJSON(t *testing.T) {
	handler := A2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
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

func TestOptionalA2AMiddlewareReturnsNilContextWhenNoBundleHeader(t *testing.T) {
	handler := OptionalA2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ctx := GetVerificationContext(r.Context()); ctx != nil {
			t.Errorf("expected nil verification context when no bundle is present, got %+v", ctx)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}
