// Package metrics exposes Prometheus metrics for the drs-verify server.
//
// Metrics are registered once in a package-level init via promauto so the
// default registry picks them up automatically. Handler returns the
// promhttp.Handler so cmd/server wires /metrics without importing promhttp
// directly.
//
// Metric names follow the Prometheus convention: namespace_subsystem_name_unit.
// The namespace is "drs" so all series can be filtered as drs_*.
package metrics

import (
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Verifications counts verify.Chain outcomes.
//
// result labels:
//   - valid   — chain verified, invocation signature ok
//   - invalid — one or more receipts failed verification (signature, expiry, policy)
//   - error   — a dependency failed (resolver, revocation, store)
var Verifications = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "verify",
	Name:      "verifications_total",
	Help:      "Total verification attempts by outcome.",
}, []string{"result"})

// DIDResolutions counts DID resolver calls.
//
// method: key | web
// result: hit (cache) | miss_success | miss_error | circuit_open
var DIDResolutions = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "resolver",
	Name:      "resolutions_total",
	Help:      "DID resolution attempts by method and result.",
}, []string{"method", "result"})

// RevocationLookups counts revocation-status queries.
//
// source: remote_statuslist | local_admin
// revoked: true | false
var RevocationLookups = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "revocation",
	Name:      "lookups_total",
	Help:      "Revocation status lookups by source and outcome.",
}, []string{"source", "revoked"})

// NonceChecks counts nonce-replay check outcomes.
//
// result: accepted | replay | exhausted | missing_jti | decode_error
var NonceChecks = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "nonce",
	Name:      "checks_total",
	Help:      "Nonce replay check outcomes.",
}, []string{"result"})

// BindingChecks counts request-body binding outcomes.
//
// Emitted from two surfaces:
//
//  1. The /verify HTTP handler (cmd/server). Labels: match | mismatch |
//     invalid_body. empty_match does not fire here — the JSON envelope
//     forces at least some bytes under "body", so purely-empty bodies
//     are indistinguishable from "no body field" (which skips the check
//     entirely and does not increment the counter).
//
//  2. pkg/middleware.checkRequestBinding, used by Go in-process tool-server
//     integrations. Labels: match | mismatch | empty_match | invalid_body |
//     (plus the off / mismatch_lenient / mismatch_enforced labels when an
//     integrator wires the middleware with those modes — those modes live
//     in the library, not on the drs-verify binary's env surface).
//
// Label semantics:
//   - match              — body JCS-equals invocation.args
//   - mismatch           — body and args both valid JSON but canonical forms differ
//   - empty_match        — body and args both literally empty (middleware path only)
//   - invalid_body       — body is not parseable as JSON, or invocation args decode failed
//   - off                — check disabled via middleware bindingMode (middleware only)
//   - mismatch_lenient   — middleware lenient mode observed a mismatch and passed through
//   - mismatch_enforced  — middleware enforced mode rejected a mismatch (403)
var BindingChecks = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "binding",
	Name:      "checks_total",
	Help:      "Request-body binding check outcomes.",
}, []string{"result"})

// RequestDuration times HTTP handlers.
//
// endpoint: /verify | /mcp | /a2a | /admin/revoke
var RequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: "drs",
	Subsystem: "http",
	Name:      "request_duration_seconds",
	Help:      "HTTP request duration in seconds by endpoint.",
	Buckets:   prometheus.DefBuckets,
}, []string{"endpoint"})

// Handler returns an http.Handler that serves Prometheus exposition on /metrics.
// Stateless — safe to call once at startup.
func Handler() http.Handler {
	return promhttp.Handler()
}

// StartServer starts a minimal HTTP server on addr that serves only /metrics.
// Returns the started *http.Server so the caller can call Shutdown during
// graceful drain. Returns nil, nil when addr is empty (metrics disabled).
// Returns nil, err if the listener cannot bind.
func StartServer(addr string) (*http.Server, error) {
	if addr == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler())
	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	go srv.Serve(ln) //nolint:errcheck — ErrServerClosed is the normal exit
	return srv, nil
}
