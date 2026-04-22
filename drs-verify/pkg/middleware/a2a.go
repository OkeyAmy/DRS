package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/drs-protocol/drs-verify/pkg/nonce"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

// A2AMiddleware extracts the X-DRS-Bundle header from A2A agent-to-agent calls,
// verifies it, and attaches the VerificationContext to the request context.
// Requests with no X-DRS-Bundle header receive 401 Unauthorized (fail-closed).
// bindingMode controls the body↔invocation.args binding check: "off" | "lenient" | "enforced".
// For optional enforcement of the header itself, use OptionalA2AMiddleware.
func A2AMiddleware(deps verify.Deps, nonceStore nonce.Checker, bindingMode string, next http.Handler) http.Handler {
	return a2aMiddleware(deps, nonceStore, bindingMode, next, false)
}

// OptionalA2AMiddleware behaves like A2AMiddleware but passes through requests
// that do not include the X-DRS-Bundle header.
func OptionalA2AMiddleware(deps verify.Deps, nonceStore nonce.Checker, bindingMode string, next http.Handler) http.Handler {
	return a2aMiddleware(deps, nonceStore, bindingMode, next, true)
}

func a2aMiddleware(deps verify.Deps, nonceStore nonce.Checker, bindingMode string, next http.Handler, allowMissing bool) http.Handler {
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

		ctx := withVerificationContext(r.Context(), result.Context)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
