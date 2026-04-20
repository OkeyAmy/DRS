package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesPrometheusExposition(t *testing.T) {
	// Touch each metric so at least one series is exposed per vec.
	Verifications.WithLabelValues("valid").Inc()
	DIDResolutions.WithLabelValues("key", "hit").Inc()
	RevocationLookups.WithLabelValues("remote_statuslist", "false").Inc()
	NonceChecks.WithLabelValues("accepted").Inc()
	RequestDuration.WithLabelValues("/verify").Observe(0.01)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from /metrics, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// Each metric should surface under its namespaced name.
	expected := []string{
		"drs_verify_verifications_total",
		"drs_resolver_resolutions_total",
		"drs_revocation_lookups_total",
		"drs_nonce_checks_total",
		"drs_http_request_duration_seconds",
	}
	for _, m := range expected {
		if !strings.Contains(body, m) {
			t.Errorf("metric %q missing from /metrics output", m)
		}
	}
}

func TestHandlerIsStateless(t *testing.T) {
	// Calling Handler() twice must not register duplicate collectors or panic.
	h1 := Handler()
	h2 := Handler()
	if h1 == nil || h2 == nil {
		t.Fatal("Handler() returned nil")
	}
}
