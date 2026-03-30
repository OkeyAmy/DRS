package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestA2AMiddlewarePassesThroughWhenNoBundleHeader(t *testing.T) {
	called := false
	handler := A2AMiddleware(testDeps(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/a2a/task", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler should be called when no X-DRS-Bundle header is present")
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
