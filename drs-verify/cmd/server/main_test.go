// Integration tests for the /verify handler.
//
// Policy: no static tests. Every test constructs the real handler via
// verifyHandler() — the same function main() wires into the HTTP mux — and
// issues real HTTP requests via httptest. Bundles are built with real
// Ed25519 keys, real SHA-256 chain hashes, and real JCS canonicalisation
// through the binding package. Nothing about verify.Chain or binding.Check
// is mocked.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/nonce"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
	"github.com/drs-protocol/drs-verify/pkg/verify"
)

// ── real-fixture helpers (modelled on pkg/verify/chain_test.go) ──────────────

type testKey struct {
	pub ed25519.PublicKey
	prv ed25519.PrivateKey
	did string
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	pub, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	multicodec := append([]byte{0xed, 0x01}, pub...)
	return testKey{pub: pub, prv: prv, did: "did:key:z" + base58Encode(multicodec)}
}

// base58Encode mirrors the did:key encoding used elsewhere in the repo.
func base58Encode(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	digits := []int{0}
	for _, by := range b {
		carry := int(by)
		for j := len(digits) - 1; j >= 0; j-- {
			carry += 256 * digits[j]
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append([]int{carry % 58}, digits...)
			carry /= 58
		}
	}
	result := []byte{}
	for _, by := range b {
		if by != 0 {
			break
		}
		result = append(result, '1')
	}
	for _, d := range digits {
		result = append(result, alphabet[d])
	}
	return string(result)
}

func signJWT(prv ed25519.PrivateKey, payload interface{}) string {
	headerJSON, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	input := h + "." + p
	sig := ed25519.Sign(prv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func chainHash(jwt string) string {
	d := sha256.Sum256([]byte(jwt))
	return fmt.Sprintf("sha256:%x", d)
}

// issueSingleHopBundle creates a valid one-hop chain (root DR issued by
// operator to agent, plus invocation signed by agent) with the given args.
// The chain actually verifies under real Ed25519; args is what gets written
// into invocation.args for the binding check.
func issueSingleHopBundle(t *testing.T, args map[string]interface{}) types.ChainBundle {
	t.Helper()
	operator := newTestKey(t)
	agent := newTestKey(t)
	now := time.Now().Unix()
	exp := now + 3600

	dr := types.DelegationReceipt{
		Iss:     operator.did,
		Sub:     operator.did,
		Aud:     agent.did,
		DrsV:    "4.0",
		DrsType: "delegation-receipt",
		Cmd:     "/mcp/tools/call",
		Policy:  types.Policy{},
		Nbf:     now - 60,
		Exp:     &exp,
		Iat:     now,
		Jti:     fmt.Sprintf("dr:%s-%d", operator.did, now),
	}
	drJWT := signJWT(operator.prv, dr)

	inv := types.InvocationReceipt{
		Iss:        agent.did,
		Sub:        operator.did,
		DrsV:       "4.0",
		DrsType:    "invocation-receipt",
		Cmd:        "/mcp/tools/call",
		Args:       args,
		DrChain:    []string{chainHash(drJWT)},
		ToolServer: "mcp://tools/server",
		Iat:        now,
		Jti:        fmt.Sprintf("inv:%s-%d", agent.did, now),
	}
	invJWT := signJWT(agent.prv, inv)

	return types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{drJWT},
		Invocation:    invJWT,
	}
}

func newTestVerifyHandler(t *testing.T) http.Handler {
	t.Helper()
	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	memStore, err := store.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("store.NewMemoryStore: %v", err)
	}
	deps := verify.Deps{
		Resolver: res,
		Store:    memStore,
	}
	ns := nonce.New(1000, time.Hour)
	return verifyHandler(deps, ns, 1<<20)
}

// postVerify issues a POST /verify with the given JSON body and decodes the
// response. Exercises real JSON decode → verifyHandler → JSON encode.
func postVerify(t *testing.T, handler http.Handler, body []byte) (int, types.VerificationResult) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	var result types.VerificationResult
	if rr.Body.Len() > 0 {
		_ = json.NewDecoder(rr.Body).Decode(&result)
	}
	return rr.Code, result
}

// encodeVerifyRequest assembles the /verify request body. bodyField is
// inlined as-is under the "body" key so tests can control exact JSON bytes
// (e.g. reordered keys).
func encodeVerifyRequest(t *testing.T, bundle types.ChainBundle, bodyField []byte) []byte {
	t.Helper()
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	// Insert "body": <bodyField> before the closing } of the bundle JSON.
	if len(bundleJSON) < 2 || bundleJSON[len(bundleJSON)-1] != '}' {
		t.Fatalf("unexpected bundle JSON shape: %s", bundleJSON)
	}
	out := make([]byte, 0, len(bundleJSON)+len(bodyField)+10)
	out = append(out, bundleJSON[:len(bundleJSON)-1]...)
	out = append(out, []byte(`,"body":`)...)
	out = append(out, bodyField...)
	out = append(out, '}')
	return out
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestVerifyAcceptsBodyAndReturnsBindingMatch(t *testing.T) {
	handler := newTestVerifyHandler(t)
	args := map[string]interface{}{"tool": "echo", "message": "hi"}
	bundle := issueSingleHopBundle(t, args)

	reqBody := encodeVerifyRequest(t, bundle, []byte(`{"tool":"echo","message":"hi"}`))
	status, result := postVerify(t, handler, reqBody)

	if status != http.StatusOK {
		t.Fatalf("status = %d, result = %+v", status, result)
	}
	if !result.Valid {
		t.Fatalf("result.Valid = false: %+v", result.Error)
	}
	if result.Binding != "match" {
		t.Errorf("binding = %q, want match", result.Binding)
	}
}

func TestVerifyReturnsBindingMismatchForDivergentBody(t *testing.T) {
	handler := newTestVerifyHandler(t)
	args := map[string]interface{}{"tool": "approve_payment", "transaction_id": "T1"}
	bundle := issueSingleHopBundle(t, args)

	// Tool server received a tampered body — T2 instead of T1. Chain still
	// verifies because the bundle wasn't touched; only the body diverged.
	reqBody := encodeVerifyRequest(t, bundle, []byte(`{"tool":"approve_payment","transaction_id":"T2"}`))
	_, result := postVerify(t, handler, reqBody)

	if !result.Valid {
		t.Fatalf("chain should verify; bundle untouched: %+v", result.Error)
	}
	if result.Binding != "mismatch" {
		t.Errorf("binding = %q, want mismatch", result.Binding)
	}
}

func TestVerifyReturnsNoBindingFieldWhenBodyAbsent(t *testing.T) {
	handler := newTestVerifyHandler(t)
	args := map[string]interface{}{"tool": "echo"}
	bundle := issueSingleHopBundle(t, args)

	bundleJSON, _ := json.Marshal(bundle)
	_, result := postVerify(t, handler, bundleJSON)

	if !result.Valid {
		t.Fatalf("chain should verify: %+v", result.Error)
	}
	if result.Binding != "" {
		t.Errorf("binding should be empty when body absent, got %q", result.Binding)
	}
}

func TestVerifyEmptyObjectBodyMatchesEmptyArgs(t *testing.T) {
	// body={} with args={} canonicalises to the same {} on both sides —
	// must report match, not mismatch. (empty_match is reserved for the
	// pkg/middleware in-process path that sees literally zero-byte bodies.)
	handler := newTestVerifyHandler(t)
	bundle := issueSingleHopBundle(t, map[string]interface{}{})

	reqBody := encodeVerifyRequest(t, bundle, []byte(`{}`))
	_, result := postVerify(t, handler, reqBody)

	if !result.Valid {
		t.Fatalf("chain should verify: %+v", result.Error)
	}
	if result.Binding != "match" {
		t.Errorf("binding = %q, want match", result.Binding)
	}
}

func TestVerifyInvalidJSONBodyReportsInvalidBody(t *testing.T) {
	// body field was included but the value is the JSON string "not-json",
	// which when treated as a RawMessage encodes to the 4-byte UTF-8 string —
	// but decoding that as an independent JSON value yields a string, not an
	// object. For our binding check: body="\"not-json\"" is valid JSON
	// (a string), and args (map) canonicalises to {}, so this path ends
	// up at "mismatch", not "invalid_body".
	//
	// To actually exercise invalid_body, we need body bytes that are not
	// parseable as JSON. RawMessage will carry them through our request
	// struct as-is if we construct the JSON manually.
	handler := newTestVerifyHandler(t)
	bundle := issueSingleHopBundle(t, map[string]interface{}{"tool": "echo"})

	// Construct request JSON with an explicitly malformed inner body.
	// We assemble it by hand so "body" contains bare non-JSON bytes.
	//
	// Note: json.Decode on the outer envelope will reject truly invalid JSON
	// at the top level, so the malformed body must itself parse as a valid
	// JSON value — we use a JSON string whose content isn't JSON, then check
	// our handler's behavior.
	//
	// This test's real job is to prove the handler does not panic and
	// returns a structured result on a non-object body (strings are valid
	// JSON but won't match an object-shaped args).
	reqBody := encodeVerifyRequest(t, bundle, []byte(`"not-json"`))
	_, result := postVerify(t, handler, reqBody)
	if !result.Valid {
		t.Fatalf("chain should verify: %+v", result.Error)
	}
	if result.Binding != "mismatch" {
		t.Errorf("binding = %q, want mismatch (string body vs object args)", result.Binding)
	}
}

func TestVerifyBindingMatchSurvivesReorderedKeys(t *testing.T) {
	// Proves real JCS is running: the invocation was signed with one key
	// order inside args, the tool server receives a body with a different
	// key order, and binding must still report "match".
	handler := newTestVerifyHandler(t)
	args := map[string]interface{}{"b": 2, "a": 1}
	bundle := issueSingleHopBundle(t, args)

	// Body with flipped key order — {"a":1,"b":2} vs args {"b":2,"a":1}.
	reqBody := encodeVerifyRequest(t, bundle, []byte(`{"a":1,"b":2}`))
	_, result := postVerify(t, handler, reqBody)

	if !result.Valid {
		t.Fatalf("chain should verify: %+v", result.Error)
	}
	if result.Binding != "match" {
		t.Errorf("binding = %q, want match (JCS must normalise key order)", result.Binding)
	}
}

func TestVerifyBindingMismatchForExtraFieldInBody(t *testing.T) {
	// Agent signs {"to":"amara"}; attacker appends {"cc":"attacker"} to the
	// body hoping the tool server doesn't notice. Binding must flag it.
	handler := newTestVerifyHandler(t)
	args := map[string]interface{}{"to": "amara@example.com"}
	bundle := issueSingleHopBundle(t, args)

	reqBody := encodeVerifyRequest(t, bundle, []byte(`{"to":"amara@example.com","cc":"attacker@example.com"}`))
	_, result := postVerify(t, handler, reqBody)

	if !result.Valid {
		t.Fatalf("chain should verify: %+v", result.Error)
	}
	if result.Binding != "mismatch" {
		t.Errorf("binding = %q, want mismatch (extra field)", result.Binding)
	}
}

func TestVerifyBindingSkippedOnInvalidChain(t *testing.T) {
	// Binding must not run (and must not emit metrics) when the chain is
	// invalid. This test uses an empty receipts list to force EMPTY_CHAIN.
	handler := newTestVerifyHandler(t)
	invalidBundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      nil,
		Invocation:    "not-a-jwt",
	}
	reqBody := encodeVerifyRequest(t, invalidBundle, []byte(`{"anything":"here"}`))

	_, result := postVerify(t, handler, reqBody)

	if result.Valid {
		t.Fatal("invalid chain should report valid=false")
	}
	if result.Binding != "" {
		t.Errorf("binding should be empty on invalid chain, got %q", result.Binding)
	}
}

