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
	"net/http"

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
