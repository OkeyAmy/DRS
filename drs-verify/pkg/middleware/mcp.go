// Package middleware provides HTTP middleware adapters for MCP and A2A protocols.
// Each adapter extracts the DRS chain bundle from the X-DRS-Bundle header,
// calls the verifier, and attaches the VerificationContext to the request context.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const verificationContextKey contextKey = "drs_verification_context"

// MCPMiddleware extracts the X-DRS-Bundle header, verifies it, and attaches
// the VerificationContext to the request context.
// Requests with no X-DRS-Bundle header pass through unmodified (optional enforcement).
// Requests with an invalid bundle receive 403 Forbidden.
func MCPMiddleware(deps verify.Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundleHeader := r.Header.Get("X-DRS-Bundle")
		if bundleHeader == "" {
			// No DRS bundle — pass through; enforcement is the caller's responsibility
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

		ctx := context.WithValue(r.Context(), verificationContextKey, result.Context)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetVerificationContext retrieves the VerificationContext attached by MCPMiddleware.
// Returns nil if the middleware was not applied or the bundle was absent.
func GetVerificationContext(ctx context.Context) *types.VerificationContext {
	v, _ := ctx.Value(verificationContextKey).(*types.VerificationContext)
	return v
}

// withVerificationContext is shared by both MCP and A2A middleware.
func withVerificationContext(ctx context.Context, vc *types.VerificationContext) context.Context {
	return context.WithValue(ctx, verificationContextKey, vc)
}

// decodeBundle decodes a base64url-encoded JSON bundle from the X-DRS-Bundle header.
func decodeBundle(encoded string) (types.ChainBundle, error) {
	jsonBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return types.ChainBundle{}, err
	}
	var bundle types.ChainBundle
	if err := json.Unmarshal(jsonBytes, &bundle); err != nil {
		return types.ChainBundle{}, err
	}
	return bundle, nil
}
