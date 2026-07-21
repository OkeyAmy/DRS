// Package middleware provides HTTP middleware adapters for MCP and A2A protocols.
// Each adapter extracts the DRS chain bundle from the X-DRS-Bundle header,
// calls the verifier, and attaches the VerificationContext to the request context.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/nonce"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
	"github.com/OkeyAmy/DRS/drs-verify/pkg/verify"
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

const verificationContextKey contextKey = "drs_verification_context"

// maxBundleHeaderBytes is the maximum allowed length of the raw (base64url-encoded)
// X-DRS-Bundle header value. It corresponds to a decoded payload ceiling of 65,535
// bytes (ceil(65535 × 4/3) = 87,381). A legitimate DRS chain bundle — which carries
// a handful of compact JWTs — is well under this limit. Any value that exceeds it
// is either malformed or an attempt to force a large heap allocation in
// base64.RawURLEncoding.DecodeString before any structural check is applied.
const maxBundleHeaderBytes = 87_381

// errBundleTooLarge is returned by decodeBundle when the encoded header exceeds
// maxBundleHeaderBytes.
var errBundleTooLarge = errors.New("X-DRS-Bundle header exceeds maximum allowed size")

// MCPMiddleware extracts the X-DRS-Bundle header, verifies it, and attaches
// the VerificationContext to the request context.
// Requests with no X-DRS-Bundle header receive 401 Unauthorized (fail-closed).
// Requests with an invalid bundle receive 403 Forbidden.
// bindingMode controls the body↔invocation.args binding check: "off" | "lenient" | "enforced".
// For optional enforcement of the header itself, use OptionalMCPMiddleware.
func MCPMiddleware(deps verify.Deps, nonceStore nonce.Checker, bindingMode string, next http.Handler) http.Handler {
	return mcpMiddleware(deps, nonceStore, bindingMode, next, false)
}

// OptionalMCPMiddleware behaves like MCPMiddleware but passes through requests
// that do not include the X-DRS-Bundle header. Use this only when downstream
// handlers perform their own authorization or when DRS verification is advisory.
func OptionalMCPMiddleware(deps verify.Deps, nonceStore nonce.Checker, bindingMode string, next http.Handler) http.Handler {
	return mcpMiddleware(deps, nonceStore, bindingMode, next, true)
}

func mcpMiddleware(deps verify.Deps, nonceStore nonce.Checker, bindingMode string, next http.Handler, allowMissing bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject ambiguous multi-valued headers: if a proxy and a client each
		// supply X-DRS-Bundle, Header.Get would silently verify only the first
		// while a downstream hop might act on a different value.
		if len(r.Header.Values("X-DRS-Bundle")) > 1 {
			http.Error(w, `{"error":"multiple X-DRS-Bundle headers are not allowed"}`, http.StatusBadRequest)
			return
		}
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

		// Verify first, commit nonce only on a valid signature/chain. Committing
		// the nonce from an unsigned payload would let an attacker with a known
		// JTI pre-consume legitimate nonces by submitting an invalid signature.
		result := verify.Chain(r.Context(), bundle, deps)
		if !result.Valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(result)
			return
		}
		if CheckNonceReplay(w, bundle.Invocation, nonceStore) {
			return
		}
		if checkRequestBinding(w, r, bundle.Invocation, bindingMode) {
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
	if len(encoded) > maxBundleHeaderBytes {
		return types.ChainBundle{}, errBundleTooLarge
	}
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
