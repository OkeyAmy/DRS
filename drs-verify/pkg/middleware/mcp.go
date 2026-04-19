// Package middleware provides HTTP middleware adapters for MCP and A2A protocols.
// Each adapter extracts the DRS chain bundle from the X-DRS-Bundle header,
// calls the verifier, and attaches the VerificationContext to the request context.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/drs-protocol/drs-verify/pkg/nonce"
	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const verificationContextKey contextKey = "drs_verification_context"

// MCPMiddleware extracts the X-DRS-Bundle header, verifies it, and attaches
// the VerificationContext to the request context.
// Requests with no X-DRS-Bundle header receive 401 Unauthorized (fail-closed).
// Requests with an invalid bundle receive 403 Forbidden.
// For optional enforcement, use OptionalMCPMiddleware instead.
func MCPMiddleware(deps verify.Deps, nonceStore *nonce.Store, next http.Handler) http.Handler {
	return mcpMiddleware(deps, nonceStore, next, false)
}

// OptionalMCPMiddleware behaves like MCPMiddleware but passes through requests
// that do not include the X-DRS-Bundle header. Use this only when downstream
// handlers perform their own authorization or when DRS verification is advisory.
func OptionalMCPMiddleware(deps verify.Deps, nonceStore *nonce.Store, next http.Handler) http.Handler {
	return mcpMiddleware(deps, nonceStore, next, true)
}

func mcpMiddleware(deps verify.Deps, nonceStore *nonce.Store, next http.Handler, allowMissing bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundleHeader := r.Header.Get("X-DRS-Bundle")
		if bundleHeader == "" {
			if allowMissing {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "Missing X-DRS-Bundle header — DRS verification is required on this route.",
			})
			return
		}

		bundle, err := decodeBundle(bundleHeader)
		if err != nil {
			http.Error(w, `{"error":"X-DRS-Bundle header is not valid base64url JSON"}`, http.StatusBadRequest)
			return
		}

		// Nonce replay check — before expensive chain verification.
		if checkNonceReplay(w, bundle.Invocation, nonceStore) {
			return
		}

		result := verify.Chain(r.Context(), bundle, deps)
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
