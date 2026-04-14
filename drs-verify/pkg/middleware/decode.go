package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/drs-protocol/drs-verify/pkg/nonce"
)

// jtiPayload is a minimal struct for extracting only the jti field from a JWT
// payload without decoding the entire receipt.
type jtiPayload struct {
	Jti string `json:"jti"`
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

// checkNonceReplay extracts the invocation JTI and checks it against the nonce
// store. Writes an error response and returns true if the request should be
// aborted (replay detected, store exhausted, or missing JTI). Returns false
// if the request should proceed.
//
// Note: the nonce is consumed before verify.Chain runs. If verification
// subsequently fails, the JTI cannot be reused — the client must generate a
// new invocation. This is a deliberate trade-off: rejecting replays before
// expensive cryptographic verification prevents CPU exhaustion attacks.
func checkNonceReplay(w http.ResponseWriter, invocationJWT string, ns *nonce.Store) bool {
	if ns == nil {
		return false
	}

	jti, err := decodeInvocationJTI(invocationJWT)
	if err != nil {
		http.Error(w, `{"error":"cannot decode invocation JTI"}`, http.StatusBadRequest)
		return true
	}
	if jti == "" {
		http.Error(w, `{"error":"invocation must include a jti for replay protection"}`, http.StatusBadRequest)
		return true
	}

	if err := ns.Check(jti); err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, nonce.ErrReplayDetected) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":      "REPLAY_DETECTED",
				"detail":     err.Error(),
				"suggestion": "Generate a new invocation with a unique jti.",
			})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":      "NONCE_STORE_EXHAUSTED",
				"detail":     err.Error(),
				"suggestion": "Retry after a short delay — the nonce store is temporarily at capacity.",
			})
		}
		return true
	}

	return false
}
