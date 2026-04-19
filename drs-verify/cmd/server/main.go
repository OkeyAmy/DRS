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
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
	"github.com/drs-protocol/drs-verify/pkg/config"
	"github.com/drs-protocol/drs-verify/pkg/health"
	"github.com/drs-protocol/drs-verify/pkg/middleware"
	"github.com/drs-protocol/drs-verify/pkg/nonce"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

func main() {
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

	res, err := resolver.New(cfg.DidCacheSize, time.Duration(cfg.DidCacheTTLSecs)*time.Second)
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

	localRev := revocation.NewLocalRevocationStore()

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

	nonceStore := nonce.New(cfg.NonceStoreMaxEntries, time.Duration(cfg.NonceStoreTTLSecs)*time.Second)
	slog.Info("nonce replay protection enabled",
		"max_entries", cfg.NonceStoreMaxEntries,
		"ttl_secs", cfg.NonceStoreTTLSecs)

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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
				slog.Warn("encode error response failed", "error", encErr)
			}
			return
		}

		// Nonce replay check — before expensive chain verification.
		if middleware.CheckNonceReplay(w, req.Invocation, nonceStore) {
			return
		}

		reqDeps := deps
		reqDeps.IncludeTimestamps = req.IncludeTimestamps

		result := verify.Chain(r.Context(), req.ChainBundle, reqDeps)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			slog.Warn("encode verify result failed", "error", err)
		}
	})

	// Admin revocation endpoint — marks a local status list index as revoked immediately.
	// Requires DRS_ADMIN_TOKEN to be set; responds 503 otherwise.
	mux.Handle("/admin/revoke", revocation.AdminRevokeHandler(localRev, cfg.AdminToken))

	// MCP tool-call route group
	mux.Handle("/mcp/", middleware.MCPMiddleware(deps, nonceStore,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	// A2A task route group
	mux.Handle("/a2a/", middleware.A2AMiddleware(deps, nonceStore,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("drs-verify listening", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server exited", "error", err)
		os.Exit(1)
	}
}
