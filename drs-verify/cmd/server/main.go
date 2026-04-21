// Binary drs-verify is the DRS verification HTTP server.
//
// It wires together configuration, caches, middleware, and health endpoints,
// then starts listening. All business logic lives in pkg/; this file contains
// only wiring — no business logic.
//
// Build: CGO_ENABLED=0 go build -o drs-verify ./cmd/server
// Run:   LISTEN_ADDR=:8080 STATUS_LIST_BASE_URL=https://... ./drs-verify
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
	"github.com/drs-protocol/drs-verify/pkg/config"
	"github.com/drs-protocol/drs-verify/pkg/health"
	"github.com/drs-protocol/drs-verify/pkg/metrics"
	"github.com/drs-protocol/drs-verify/pkg/middleware"
	"github.com/drs-protocol/drs-verify/pkg/nonce"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

// shutdownTimeout is how long the server waits for in-flight requests to drain
// after receiving SIGTERM / SIGINT. Long enough for /verify requests under
// typical network conditions (resolver + HTTP response) to complete, short
// enough that orchestrators' kill-after-grace-period stays in play.
const shutdownTimeout = 30 * time.Second

func main() {
	// Pre-init: use a default text handler until configuration is loaded.
	// This ensures any config-load failure is logged through slog, not fmt/log.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	// Parse log level
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Init structured logger
	opts := &slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))

	res, err := resolver.NewWithCircuitBreaker(
		cfg.DidCacheSize,
		time.Duration(cfg.DidCacheTTLSecs)*time.Second,
		cfg.CircuitBreakerThreshold,
		time.Duration(cfg.CircuitBreakerCooldownSecs)*time.Second,
	)
	if err != nil {
		slog.Error("resolver init failed", "error", err)
		os.Exit(1)
	}

	var statusCache *revocation.StatusCache
	if cfg.StatusListBaseURL != "" {
		statusCache = revocation.New(cfg.StatusListBaseURL,
			time.Duration(cfg.StatusListCacheTTLSecs)*time.Second)
		if err := statusCache.WarmUp(); err != nil {
			slog.Warn("status list warm-up failed", "error", err)
		} else {
			slog.Info("status list warm-up successful")
		}
	}

	// Local revocation store: in-memory by default, file-backed when
	// REVOCATION_STORE_PATH is set. The file-backed store persists every
	// /admin/revoke call with fsync so emergency revokes survive restart.
	var localRev revocation.LocalStore
	if cfg.RevocationStorePath != "" {
		fsRev, err := revocation.OpenFileBackedRevocationStore(cfg.RevocationStorePath)
		if err != nil {
			slog.Error("revocation store init failed", "path", cfg.RevocationStorePath, "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := fsRev.Close(); err != nil {
				slog.Warn("revocation store close failed", "error", err)
			}
		}()
		localRev = fsRev
		slog.Info("local revocation: file-backed", "path", cfg.RevocationStorePath)
	} else {
		localRev = revocation.NewLocalRevocationStore()
		slog.Info("local revocation: in-memory (set REVOCATION_STORE_PATH to persist)")
	}

	var drStore store.Store
	if cfg.StoreDir != "" {
		fsStore, err := store.NewFilesystemStore(cfg.StoreDir, 0)
		if err != nil {
			slog.Error("store init failed", "error", err)
			os.Exit(1)
		}
		if cfg.TSAURL != "" {
			drStore = anchor.NewTier3Store(fsStore, anchor.NewTSAClient(cfg.TSAURL))
			slog.Info("store initialized", "tier", 3, "tsa_url", cfg.TSAURL)
		} else {
			drStore = fsStore
			slog.Info("store initialized", "tier", 1)
		}
	} else {
		s, err := store.NewMemoryStore(0)
		if err != nil {
			slog.Error("store init failed", "error", err)
			os.Exit(1)
		}
		drStore = s
		slog.Info("store initialized", "tier", 0)
	}

	var tsaRootPool *x509.CertPool
	if cfg.TSARootCertPEM != "" {
		tsaRootPool = x509.NewCertPool()
		if !tsaRootPool.AppendCertsFromPEM([]byte(cfg.TSARootCertPEM)) {
			slog.Error("TSA_ROOT_CERT_PEM: no valid certificates found in PEM data")
			os.Exit(1)
		}
		slog.Info("RFC 3161 trust anchored to custom root pool")
	} else {
		slog.Info("RFC 3161 trust uses system roots")
	}

	deps := verify.Deps{
		Resolver:        res,
		Revocation:      statusCache,
		LocalRevocation: localRev,
		Store:           drStore,
		ServerIdentity:  cfg.ServerIdentity,
		TSARootPool:     tsaRootPool,
	}

	// Nonce store: in-memory by default. When NONCE_STORE_BACKEND=redis,
	// Check uses Redis SETNX for atomic claim-if-new across replicas and
	// across restart. Closed in the shutdown deferred cleanup path so
	// Redis connections drain.
	var nonceStore nonce.Checker
	switch cfg.NonceStoreBackend {
	case "redis":
		rs, err := nonce.NewRedisStore(context.Background(), nonce.RedisConfig{
			URL: cfg.RedisURL,
			TTL: time.Duration(cfg.NonceStoreTTLSecs) * time.Second,
		})
		if err != nil {
			slog.Error("nonce store init failed", "backend", "redis", "error", err)
			os.Exit(1)
		}
		defer func() {
			if err := rs.Close(); err != nil {
				slog.Warn("nonce store close failed", "error", err)
			}
		}()
		nonceStore = rs
		slog.Info("nonce replay protection enabled",
			"backend", "redis",
			"ttl_secs", cfg.NonceStoreTTLSecs)
	default:
		nonceStore = nonce.New(cfg.NonceStoreMaxEntries, time.Duration(cfg.NonceStoreTTLSecs)*time.Second)
		slog.Info("nonce replay protection enabled",
			"backend", "memory",
			"max_entries", cfg.NonceStoreMaxEntries,
			"ttl_secs", cfg.NonceStoreTTLSecs)
	}

	rateLimiter := middleware.NewRateLimiter(cfg.RateLimitPerIP, cfg.RateLimitGlobal, cfg.TrustProxy)
	slog.Info("rate limiting enabled",
		"per_ip_rps", cfg.RateLimitPerIP,
		"global_rps", cfg.RateLimitGlobal,
		"trust_proxy", cfg.TrustProxy)

	mux := http.NewServeMux()

	// Health endpoints (no auth required)
	healthMux := health.Handler(statusCache)
	mux.Handle("/healthz", healthMux)
	mux.Handle("/readyz", healthMux)

	// Verification endpoint — accepts a ChainBundle JSON body and returns VerificationResult.
	// Used directly by the SDK and tests; MCP/A2A routes use header-based extraction instead.
	//
	// Optional field: "include_timestamps" (bool) — when true, retrieves and verifies
	// the RFC 3161 timestamp token stored alongside each receipt and includes results
	// in VerificationResult.Timestamps.
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			metrics.RequestDuration.WithLabelValues("/verify").Observe(time.Since(start).Seconds())
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes)

		var req struct {
			types.ChainBundle
			IncludeTimestamps bool `json:"include_timestamps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			metrics.Verifications.WithLabelValues("error").Inc()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
				slog.Warn("encode error response failed", "error", encErr)
			}
			return
		}

		reqDeps := deps
		reqDeps.IncludeTimestamps = req.IncludeTimestamps

		// Verify first, commit nonce only on a valid chain. Committing the
		// nonce from an unsigned payload would let an attacker with a known
		// JTI pre-consume legitimate nonces by submitting an invalid signature.
		result := verify.Chain(r.Context(), req.ChainBundle, reqDeps)
		if result.Valid {
			metrics.Verifications.WithLabelValues("valid").Inc()
			if middleware.CheckNonceReplay(w, req.Invocation, nonceStore) {
				return
			}
		} else {
			metrics.Verifications.WithLabelValues("invalid").Inc()
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Warn("encode verify result failed", "error", err)
		}
	})

	// Admin revocation endpoint — marks a local status list index as revoked immediately.
	// Requires DRS_ADMIN_TOKEN to be set; responds 503 otherwise.
	mux.Handle("/admin/revoke", revocation.AdminRevokeHandler(localRev, cfg.AdminToken))

	// /mcp/* and /a2a/* are verifier stubs — NOT transparent proxies.
	// Behind MCPMiddleware / A2AMiddleware, they return a JSON body that says
	// "your bundle was accepted; wire the middleware into your own server to
	// enforce DRS on real MCP/A2A routes". Kept for demos and smoke tests.
	//
	// Product boundary: drs-verify is a verification service. It does not
	// proxy, transform, or execute MCP/A2A requests. Real integrations
	// consume the middleware package directly. See docs/drs-source-of-truth.md.
	verifierStub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"verified": true,
			"role":     "verifier-stub",
			"detail": "DRS bundle accepted. This endpoint is a verifier stub — drs-verify does not proxy MCP/A2A " +
				"traffic. Import github.com/drs-protocol/drs-verify/pkg/middleware to wire DRS into your own server.",
		})
	})
	mux.Handle("/mcp/", middleware.MCPMiddleware(deps, nonceStore, verifierStub))
	mux.Handle("/a2a/", middleware.A2AMiddleware(deps, nonceStore, verifierStub))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           rateLimiter.Middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Run ListenAndServe in a goroutine so main can listen for shutdown signals.
	// ErrServerClosed means a graceful shutdown happened — not an error.
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()
	slog.Info("drs-verify listening", "addr", cfg.ListenAddr)

	metricsSrv, err := metrics.StartServer(cfg.MetricsAddr)
	if err != nil {
		slog.Error("metrics server failed to start", "addr", cfg.MetricsAddr, "error", err)
		os.Exit(1)
	}
	if metricsSrv != nil {
		slog.Info("metrics server listening", "addr", metricsSrv.Addr)
	} else {
		slog.Warn("metrics endpoint disabled — set METRICS_ADDR to enable (e.g. METRICS_ADDR=127.0.0.1:9090)")
	}

	// Block on SIGTERM / SIGINT or a startup failure from ListenAndServe.
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		if err != nil {
			slog.Error("server exited unexpectedly", "error", err)
			os.Exit(1)
		}
		return
	case <-signalCtx.Done():
		slog.Info("shutdown signal received, draining in-flight requests",
			"timeout", shutdownTimeout)
	}

	// Graceful drain. srv.Shutdown blocks until idle or the deadline fires.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	if metricsSrv != nil {
		if err = metricsSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("metrics server shutdown failed", "error", err)
		}
	}
	// Drain the background goroutine's final error (should be nil after Shutdown).
	if err := <-serverErr; err != nil {
		slog.Error("post-shutdown server error", "error", err)
		os.Exit(1)
	}
	slog.Info("drs-verify shut down cleanly")
}
