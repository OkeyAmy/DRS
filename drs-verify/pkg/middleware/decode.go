package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/drs-protocol/drs-verify/pkg/metrics"
	"github.com/drs-protocol/drs-verify/pkg/nonce"
)

// jtiPayload is a minimal struct for extracting only the jti field from a JWT
// payload without decoding the entire receipt.
type jtiPayload struct {
	Jti string `json:"jti"`
}

// argsPayload extracts only the args field from an invocation JWT payload.
type argsPayload struct {
	Args interface{} `json:"args"`
}

// decodeInvocationJTI extracts the jti field from an invocation JWT without
// fully decoding the receipt. Splits on ".", base64url-decodes the payload
// segment, and unmarshals only the jti field.
func decodeInvocationJTI(jwt string) (string, error) {
	parts := strings.SplitN(jwt, ".", 4)
	if len(parts) != 3 {
		return "", fmt.Errorf("expected 3 dot-separated parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	var p jtiPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return "", fmt.Errorf("JSON unmarshal: %w", err)
	}
	return p.Jti, nil
}

// decodeInvocationArgs extracts the args field from an invocation JWT payload
// without decoding the entire receipt. Returns nil if the field is absent.
// The caller is expected to have passed chain verification before relying on
// this value.
func decodeInvocationArgs(jwt string) (interface{}, error) {
	parts := strings.SplitN(jwt, ".", 4)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 dot-separated parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	var p argsPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("JSON unmarshal: %w", err)
	}
	return p.Args, nil
}

// CheckNonceReplay extracts the invocation JTI and commits it to the nonce
// store. Writes an error response and returns true if the request should be
// aborted (replay detected, store exhausted, or missing JTI). Returns false
// if the request should proceed.
//
// Call this AFTER verify.Chain has successfully validated the signature and
// chain. Committing the JTI before signature verification would let an
// attacker with a known (but not signed-for) JTI pre-consume legitimate
// nonces by sending invalid-signature requests. The rate limiter, not the
// nonce store, is the layer that defends against CPU exhaustion.
func CheckNonceReplay(w http.ResponseWriter, invocationJWT string, ns nonce.Checker) bool {
	if ns == nil {
		return false
	}

	jti, err := decodeInvocationJTI(invocationJWT)
	if err != nil {
		metrics.NonceChecks.WithLabelValues("decode_error").Inc()
		http.Error(w, `{"error":"cannot decode invocation JTI"}`, http.StatusBadRequest)
		return true
	}
	if jti == "" {
		metrics.NonceChecks.WithLabelValues("missing_jti").Inc()
		http.Error(w, `{"error":"invocation must include a jti for replay protection"}`, http.StatusBadRequest)
		return true
	}

	if err := ns.Check(jti); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, nonce.ErrReplayDetected) {
			metrics.NonceChecks.WithLabelValues("replay").Inc()
			slog.Warn("nonce replay detected", "jti", jti)
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":      "REPLAY_DETECTED",
				"detail":     err.Error(),
				"suggestion": "Generate a new invocation with a unique jti.",
			})
		} else {
			metrics.NonceChecks.WithLabelValues("exhausted").Inc()
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":      "NONCE_STORE_EXHAUSTED",
				"detail":     err.Error(),
				"suggestion": "Retry after a short delay — the nonce store is temporarily at capacity.",
			})
		}
		return true
	}

	metrics.NonceChecks.WithLabelValues("accepted").Inc()
	return false
}
