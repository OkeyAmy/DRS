package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/revocation"
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

func TestReadinessReturns503WhenCacheNotYetPopulated(t *testing.T) {
	// A newly created StatusCache has never fetched the status list.
	// Ready() returns false → /readyz must return 503 to gate traffic.
	// Use an unreachable URL so no accidental fetch occurs during the test.
	cache := revocation.New("http://127.0.0.1:0/status", time.Hour)
	mux := Handler(cache)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when status cache has not been populated, got %d", rr.Code)
	}
}
