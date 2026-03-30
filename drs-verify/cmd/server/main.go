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
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/config"
	"github.com/drs-protocol/drs-verify/pkg/health"
	"github.com/drs-protocol/drs-verify/pkg/middleware"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
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
	}

	deps := verify.Deps{
		Resolver:   res,
		Revocation: statusCache,
	}

	mux := http.NewServeMux()

	// Health endpoints (no auth required)
	healthMux := health.Handler(statusCache)
	mux.Handle("/healthz", healthMux)
	mux.Handle("/readyz", healthMux)

	// Verification endpoint — accepts a raw ChainBundle and returns VerificationResult
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// The MCP middleware is applied on the /mcp/* routes; direct /verify
		// calls are used by the SDK and tests.
		middleware.MCPMiddleware(deps, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := middleware.GetVerificationContext(r.Context())
			if ctx == nil {
				http.Error(w, `{"error":"no DRS-Chain-Bundle header"}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"valid":true,"chain_depth":%d}`, ctx.ChainDepth)
		})).ServeHTTP(w, r)
	})

	// MCP tool-call route group
	mux.Handle("/mcp/", middleware.MCPMiddleware(deps,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	// A2A task route group
	mux.Handle("/a2a/", middleware.A2AMiddleware(deps,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

	log.Printf("drs-verify listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}
