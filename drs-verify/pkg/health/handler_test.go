package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLivenessReturns200Always(t *testing.T) {
	mux := Handler(nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestReadinessReturns200WhenNilCache(t *testing.T) {
	// nil cache means revocation is disabled — service is always ready
	mux := Handler(nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when cache is nil, got %d", rr.Code)
	}
}
