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
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
	"github.com/drs-protocol/drs-verify/pkg/config"
	"github.com/drs-protocol/drs-verify/pkg/health"
	"github.com/drs-protocol/drs-verify/pkg/middleware"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	res, err := resolver.New(cfg.DidCacheSize, time.Duration(cfg.DidCacheTTLSecs)*time.Second)
	if err != nil {
		log.Fatalf("resolver: %v", err)
	}

	var statusCache *revocation.StatusCache
	if cfg.StatusListBaseURL != "" {
		statusCache = revocation.New(cfg.StatusListBaseURL,
			time.Duration(cfg.StatusListCacheTTLSecs)*time.Second)
		if err := statusCache.WarmUp(); err != nil {
			log.Printf("drs-verify: status list warm-up failed (will retry on first request): %v", err)
		} else {
			log.Printf("drs-verify: status list warm-up successful")
		}
	}

	localRev := revocation.NewLocalRevocationStore()

	var drStore store.Store
	if cfg.StoreDir != "" {
		fsStore, err := store.NewFilesystemStore(cfg.StoreDir, 0)
		if err != nil {
			log.Fatalf("store: %v", err)
		}
		if cfg.TSAURL != "" {
			drStore = anchor.NewTier3Store(fsStore, anchor.NewTSAClient(cfg.TSAURL))
			log.Printf("drs-verify: Tier 3 store enabled (TSA: %s)", cfg.TSAURL)
		} else {
			drStore = fsStore
			log.Printf("drs-verify: Tier 1 filesystem store (no TSA configured)")
		}
	} else {
		s, err := store.NewMemoryStore(0)
		if err != nil {
			log.Fatalf("store: %v", err)
		}
		drStore = s
		log.Printf("drs-verify: Tier 0 memory store (no STORE_DIR configured)")
	}

	deps := verify.Deps{
		Resolver:        res,
		Revocation:      statusCache,
		LocalRevocation: localRev,
		Store:           drStore,
		ServerIdentity:  cfg.ServerIdentity,
	}

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
				log.Printf("verify: encode error response: %v", encErr)
			}
			return
		}

		reqDeps := deps
		reqDeps.IncludeTimestamps = req.IncludeTimestamps

		result := verify.Chain(req.ChainBundle, reqDeps)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Printf("verify: encode result: %v", err)
		}
	})

	// Admin revocation endpoint — marks a local status list index as revoked immediately.
	// Requires DRS_ADMIN_TOKEN to be set; responds 503 otherwise.
	mux.Handle("/admin/revoke", revocation.AdminRevokeHandler(localRev, cfg.AdminToken))

	// MCP tool-call route group
	mux.Handle("/mcp/", middleware.MCPMiddleware(deps, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	// A2A task route group
	mux.Handle("/a2a/", middleware.A2AMiddleware(deps,
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
	log.Printf("drs-verify listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}
