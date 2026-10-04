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
//  2. pkg/gate.Decide, used by the Go gate middleware and POST /v1/gate
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

// StoreWriteQueueDropped counts receipt writes dropped because the async
// write queue was full. A non-zero value means evidence is being lost and
// the backend cannot keep pace with ingress.
var StoreWriteQueueDropped = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "store",
	Name:      "write_queue_dropped_total",
	Help:      "Receipt writes dropped because the async queue was full (evidence gap).",
})

// StoreFlushErrors counts receipt writes that exhausted all retries against
// the durable backend. The receipt is not lost yet: it stays in memory and is
// redriven until the backend recovers (see the drs_store_failed_pending gauge). It is lost only
// if the process exits first or the failed-write buffer overflows
// (StoreWriteQueueDropped).
var StoreFlushErrors = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "store",
	Name:      "flush_errors_total",
	Help:      "Receipt writes that exhausted retries against the durable backend (they are redriven until the backend recovers).",
})

// RegisterStoreGauges exposes two live gauges about receipts that are not yet
// durable. Call once at startup.
//
//   - drs_store_pending_writes: queued, in flight, retrying or failed. Alert when
//     it stays high — the durable backend is not keeping up.
//   - drs_store_failed_pending: the subset whose retries are exhausted and that
//     are waiting for the backend to recover. Alert when it stays above zero.
func RegisterStoreGauges(pending, failed func() int) {
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "drs",
		Subsystem: "store",
		Name:      "pending_writes",
		Help:      "Receipts not yet durable: queued, being flushed, retrying, or failed and awaiting redrive.",
	}, func() float64 { return float64(pending()) })
	promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "drs",
		Subsystem: "store",
		Name:      "failed_pending",
		Help:      "Receipts whose durable write exhausted its retries and await redrive. Non-zero means evidence is not yet durable.",
	}, func() float64 { return float64(failed()) })
}

// StoreWritesTotal counts store write attempts by outcome.
//
// result labels:
//   - flushed — write succeeded and was committed to the backend
//   - dropped — write was shed at the queue boundary (correlates with StoreWriteQueueDropped)
//   - error   — write reached the backend but the backend returned an error
var StoreWritesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "drs",
	Subsystem: "store",
	Name:      "writes_total",
	Help:      "Receipt store write outcomes.",
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
