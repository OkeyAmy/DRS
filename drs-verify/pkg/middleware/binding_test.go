package middleware

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bindingJWT builds an invocation-like JWT where the payload's args field is
// set to argsJSON verbatim (a raw JSON fragment). Controlling the raw bytes lets
// tests verify that JCS canonicalisation — not accidental alphabetic ordering
// from json.Marshal — is what makes mismatched key orders equivalent.
func bindingJWT(argsJSON string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"inv:1","args":` + argsJSON + `}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payload + "." + sig
}

func TestCheckRequestBindingOffPassesMismatch(t *testing.T) {
	jwt := bindingJWT(`{"to":"amara"}`)
	body := []byte(`{"to":"attacker"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	if abort := checkRequestBinding(w, r, jwt, BindingModeOff); abort {
		t.Error("off mode must never abort")
	}
	got, _ := io.ReadAll(r.Body)
	if !bytes.Equal(got, body) {
		t.Errorf("body not restored: got %q, want %q", got, body)
	}
}

func TestCheckRequestBindingLenientMismatchPasses(t *testing.T) {
	jwt := bindingJWT(`{"to":"amara"}`)
	body := []byte(`{"to":"attacker"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	if abort := checkRequestBinding(w, r, jwt, BindingModeLenient); abort {
		t.Error("lenient mode must not abort on mismatch")
	}
	got, _ := io.ReadAll(r.Body)
	if !bytes.Equal(got, body) {
		t.Error("body not restored")
	}
}

func TestCheckRequestBindingEnforcedMismatchReturns403(t *testing.T) {
	jwt := bindingJWT(`{"to":"amara"}`)
	body := []byte(`{"to":"attacker"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	if abort := checkRequestBinding(w, r, jwt, BindingModeEnforced); !abort {
		t.Fatal("enforced mode must abort on mismatch")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "BINDING_MISMATCH") {
		t.Errorf("response body must include BINDING_MISMATCH: %s", w.Body.String())
	}
}

func TestCheckRequestBindingEnforcedMatchPasses(t *testing.T) {
	jwt := bindingJWT(`{"to":"amara"}`)
	body := []byte(`{"to":"amara"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	if abort := checkRequestBinding(w, r, jwt, BindingModeEnforced); abort {
		t.Error("matching body must not abort in enforced mode")
	}
}

func TestCheckRequestBindingEnforcedEmptyMatchPasses(t *testing.T) {
	jwt := bindingJWT(`{}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	if abort := checkRequestBinding(w, r, jwt, BindingModeEnforced); abort {
		t.Error("empty body + empty args must not abort in enforced mode")
	}
}

func TestCheckRequestBindingReorderedKeysMatches(t *testing.T) {
	// Args encoded as {"b":2,"a":1}; body has {"a":1,"b":2}.
	// Proves JCS canonicalisation, not accidental lexicographic ordering, is
	// what makes these equivalent — by controlling exact JWT payload bytes.
	jwt := bindingJWT(`{"b":2,"a":1}`)
	body := []byte(`{"a":1,"b":2}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	if abort := checkRequestBinding(w, r, jwt, BindingModeEnforced); abort {
		t.Errorf("reordered keys must match after JCS: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCheckRequestBindingBodyRestoredAfterMismatch(t *testing.T) {
	// Body must still be readable by downstream handlers even after a
	// lenient-mode mismatch — otherwise the handler sees an empty body.
	jwt := bindingJWT(`{"to":"amara"}`)
	body := []byte(`{"to":"attacker"}`)
	r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	w := httptest.NewRecorder()
	_ = checkRequestBinding(w, r, jwt, BindingModeLenient)
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("body read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body not restored: got %q, want %q", got, body)
	}
}
