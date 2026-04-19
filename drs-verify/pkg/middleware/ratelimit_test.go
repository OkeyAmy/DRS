package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterAllowsNormalTraffic(t *testing.T) {
	rl := NewRateLimiter(100, 1000)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.RemoteAddr = "1.2.3.4:5000"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRateLimiterRejectsExcessiveRequests(t *testing.T) {
	// 1 req/sec per IP, burst of 1 — second request must be rejected
	rl := NewRateLimiter(1, 1000)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/verify", nil)
	req.RemoteAddr = "1.2.3.4:5000"

	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req)

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)

	if w1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w1.Code)
	}
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}
	if w2.Header().Get("Retry-After") == "" {
		t.Error("429 response must include Retry-After header")
	}
}

func TestRateLimiterHealthBypass(t *testing.T) {
	// /healthz and /readyz must bypass rate limiting
	rl := NewRateLimiter(1, 1)
	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "1.2.3.4:5000"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("healthz request %d: expected 200, got %d", i, w.Code)
		}
	}
}
