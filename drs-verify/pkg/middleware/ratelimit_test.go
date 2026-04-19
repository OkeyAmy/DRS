package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterAllowsNormalTraffic(t *testing.T) {
	rl := NewRateLimiter(100, 1000, false)
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
	rl := NewRateLimiter(1, 1000, false)
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
	rl := NewRateLimiter(1, 1, false)
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

func TestClientIPTrustProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		trustProxy bool
		wantIP     string
	}{
		{
			name:       "no XFF, trustProxy false",
			remoteAddr: "1.2.3.4:5000",
			wantIP:     "1.2.3.4",
		},
		{
			name:       "XFF present, trustProxy false — must use RemoteAddr",
			remoteAddr: "1.2.3.4:5000",
			xff:        "9.9.9.9",
			trustProxy: false,
			wantIP:     "1.2.3.4",
		},
		{
			name:       "XFF present, trustProxy true — use rightmost",
			remoteAddr: "10.0.0.1:5000",
			xff:        "9.9.9.9, 5.5.5.5",
			trustProxy: true,
			wantIP:     "5.5.5.5",
		},
		{
			name:       "XFF single value, trustProxy true",
			remoteAddr: "10.0.0.1:5000",
			xff:        "9.9.9.9",
			trustProxy: true,
			wantIP:     "9.9.9.9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/verify", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := clientIP(req, tt.trustProxy)
			if got != tt.wantIP {
				t.Errorf("clientIP = %q, want %q", got, tt.wantIP)
			}
		})
	}
}
