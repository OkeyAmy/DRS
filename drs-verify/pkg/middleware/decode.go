package middleware

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
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
