package resolver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func resolutions(method, result string) float64 {
	return testutil.ToFloat64(metrics.DIDResolutions.WithLabelValues(method, result))
}

// A real did:key (the conformance fixture issuer key is not needed: any
// well-formed Ed25519 did:key resolves locally).
const sampleDidKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

func TestResolveCountsMissThenHitForDidKey(t *testing.T) {
	r, err := New(10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	miss, hit := resolutions("key", "miss_success"), resolutions("key", "hit")
	if _, err := r.Resolve(context.Background(), sampleDidKey); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := r.Resolve(context.Background(), sampleDidKey); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// blindfold: contract — metrics.DIDResolutions doc: first lookup is a miss, the second is served from cache.
	if resolutions("key", "miss_success")-miss != 1 || resolutions("key", "hit")-hit != 1 {
		t.Fatalf("want one miss_success and one hit, got miss=%v hit=%v",
			resolutions("key", "miss_success")-miss, resolutions("key", "hit")-hit)
	}
}

func TestResolveCountsErrorsAndOpenCircuit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	did := "did:web:" + strings.ReplaceAll(strings.TrimPrefix(srv.URL, "http://"), ":", "%3A")

	r, err := NewWithCircuitBreaker(10, time.Hour, 2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.allowPrivateHosts = true
	errs, open := resolutions("web", "miss_error"), resolutions("web", "circuit_open")
	for i := 0; i < 3; i++ {
		_, _ = r.Resolve(context.Background(), did)
	}
	_, err = r.Resolve(context.Background(), did)
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("an open circuit must be reported as ErrCircuitOpen, got %v", err)
	}
	// blindfold: contract — threshold 2: two real failures, then every further call short-circuits.
	if got := resolutions("web", "miss_error") - errs; got != 2 {
		t.Errorf("miss_error: want 2, got %v", got)
	}
	if got := resolutions("web", "circuit_open") - open; got != 2 {
		t.Errorf("circuit_open: want 2, got %v", got)
	}
}
