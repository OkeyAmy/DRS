package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/drs-protocol/drs-verify/pkg/verify"
)

// A2AMiddleware extracts the X-DRS-Bundle header from A2A agent-to-agent calls,
// verifies it, and attaches the VerificationContext to the request context.
// The header name and behaviour are identical to MCPMiddleware; this adapter
// exists as a named entrypoint so A2A route groups can be configured separately.
func A2AMiddleware(deps verify.Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundleHeader := r.Header.Get("X-DRS-Bundle")
		if bundleHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		bundle, err := decodeBundle(bundleHeader)
		if err != nil {
			http.Error(w, `{"error":"X-DRS-Bundle header is not valid base64url JSON"}`, http.StatusBadRequest)
			return
		}

		result := verify.Chain(bundle, deps)
		if !result.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(result)
			return
		}

		// Reuse the context key from mcp.go — both middlewares share the same context slot
		ctx := withVerificationContext(r.Context(), result.Context)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
