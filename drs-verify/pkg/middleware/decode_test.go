package middleware

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDecodeInvocationJTI_Valid(t *testing.T) {
	payload := map[string]interface{}{
		"jti":      "inv:test-123",
		"drs_type": "invocation-receipt",
		"iss":      "did:key:z6Mk...",
	}
	jwt := fakeJWT(t, payload)

	jti, err := decodeInvocationJTI(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jti != "inv:test-123" {
		t.Errorf("expected jti 'inv:test-123', got %q", jti)
	}
}

func TestDecodeInvocationJTI_MalformedJWT(t *testing.T) {
	_, err := decodeInvocationJTI("not.a.valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
}

func TestDecodeInvocationJTI_MissingJTI(t *testing.T) {
	payload := map[string]interface{}{
		"drs_type": "invocation-receipt",
	}
	jwt := fakeJWT(t, payload)

	jti, err := decodeInvocationJTI(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if jti != "" {
		t.Errorf("expected empty jti for payload without jti, got %q", jti)
	}
}

// fakeJWT builds a three-segment JWT string with the given payload.
// The header and signature are valid base64url but not cryptographically meaningful.
func fakeJWT(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal payload: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadB64 + "." + sig
}
