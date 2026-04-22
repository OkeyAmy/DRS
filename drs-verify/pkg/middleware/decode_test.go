package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/nonce"
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

func TestCheckNonceReplayExported(t *testing.T) {
	// Verify the function is exported and callable from outside the package.
	// (This test is in package middleware — same package — so it proves exportability
	// by the capital letter; integration coverage is in main_test.go below.)
	ns := nonce.New(100, time.Hour)

	// Build a minimal JWT with a jti claim.
	payload := map[string]interface{}{
		"jti":      "inv:test-nonce-001",
		"drs_type": "invocation-receipt",
	}
	jwt := fakeJWT(t, payload)

	// First call: nonce is fresh — should NOT abort (returns false).
	w := httptest.NewRecorder()
	if blocked := CheckNonceReplay(w, jwt, ns); blocked {
		t.Error("first call with fresh nonce should not be blocked")
	}

	// Second call: same nonce — should abort (replay detected, returns true).
	w2 := httptest.NewRecorder()
	if blocked := CheckNonceReplay(w2, jwt, ns); !blocked {
		t.Error("second call with same nonce should be blocked as replay")
	}
	if w2.Code != http.StatusConflict {
		t.Errorf("replay response: want 409, got %d", w2.Code)
	}
}

func TestDecodeInvocationArgs(t *testing.T) {
	payload := map[string]interface{}{
		"jti":  "inv:1",
		"args": map[string]interface{}{"to": "amara@example.com", "count": 3},
	}
	jwt := fakeJWT(t, payload)

	args, err := decodeInvocationArgs(jwt)
	if err != nil {
		t.Fatalf("decodeInvocationArgs: %v", err)
	}
	argsMap, ok := args.(map[string]interface{})
	if !ok {
		t.Fatalf("args type = %T, want map[string]interface{}", args)
	}
	if argsMap["to"] != "amara@example.com" {
		t.Errorf("args.to = %v, want amara@example.com", argsMap["to"])
	}
}

func TestDecodeInvocationArgsMalformed(t *testing.T) {
	if _, err := decodeInvocationArgs("not-a-jwt"); err == nil {
		t.Error("malformed JWT should fail")
	}
	if _, err := decodeInvocationArgs("bad!!.payload!!.sig"); err == nil {
		t.Error("non-base64 payload should fail")
	}
}

func TestDecodeInvocationArgsAbsent(t *testing.T) {
	payload := map[string]interface{}{"jti": "inv:1"}
	jwt := fakeJWT(t, payload)

	args, err := decodeInvocationArgs(jwt)
	if err != nil {
		t.Fatalf("decodeInvocationArgs: %v", err)
	}
	if args != nil {
		t.Errorf("args should be nil when absent, got %v", args)
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
