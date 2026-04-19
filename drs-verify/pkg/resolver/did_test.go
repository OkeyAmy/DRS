package resolver

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ed25519TestKey is a known 32-byte public key used across tests.
var ed25519TestKey = [32]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// encodeDIDKey mirrors the Rust encode_did_key — used to build test DIDs.
func encodeDIDKey(pub [32]byte) string {
	multicodec := append([]byte{multicodecEd25519Hi, multicodecEd25519Lo}, pub[:]...)
	return didKeyPrefix + base58Encode(multicodec)
}

// base58Encode encodes bytes using the Bitcoin alphabet.
func base58Encode(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	n := new([64]byte)
	_ = n

	// Convert bytes to a large integer, then encode in base58
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

	// Add leading '1' for each leading zero byte
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

// ── did:key resolution ────────────────────────────────────────────────────────

func TestRoundTripEncodeAndResolve(t *testing.T) {
	did := encodeDIDKey(ed25519TestKey)
	resolved, err := resolveDidKey(did)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != ed25519TestKey {
		t.Errorf("round-trip failed: got %x, want %x", resolved, ed25519TestKey)
	}
}

func TestUnsupportedDidMethodReturnsError(t *testing.T) {
	// resolveDidKey only handles did:key — must reject did:web
	_, err := resolveDidKey("did:web:example.com")
	if err == nil {
		t.Fatal("expected error for unsupported DID method, got nil")
	}
}

func TestWrongMulticodecPrefixReturnsError(t *testing.T) {
	// Use sha2-256 multicodec (0x12 0x00) instead of ed25519
	raw := append([]byte{0x12, 0x00}, make([]byte, 32)...)
	did := didKeyPrefix + base58Encode(raw)
	_, err := resolveDidKey(did)
	if err == nil {
		t.Fatal("expected error for wrong multicodec prefix, got nil")
	}
}

func TestTruncatedKeyReturnsError(t *testing.T) {
	// Only 5 bytes — far too short
	raw := []byte{0xed, 0x01, 0x00, 0x01, 0x02}
	did := didKeyPrefix + base58Encode(raw)
	_, err := resolveDidKey(did)
	if err == nil {
		t.Fatal("expected error for truncated key, got nil")
	}
}

// ── LRU cache behaviour ───────────────────────────────────────────────────────

func TestCacheHitReturnsSameKey(t *testing.T) {
	r, err := New(100, time.Hour)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}
	did := encodeDIDKey(ed25519TestKey)

	k1, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	k2, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("second resolve (cache hit) failed: %v", err)
	}
	if k1 != k2 {
		t.Error("cache hit returned different key than initial resolution")
	}
}

func TestExpiredCacheEntryIsEvicted(t *testing.T) {
	// TTL of 1 nanosecond — entry is always expired
	r, err := New(100, time.Nanosecond)
	if err != nil {
		t.Fatalf("failed to create resolver: %v", err)
	}
	did := encodeDIDKey(ed25519TestKey)

	// First call populates cache
	_, err = r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	time.Sleep(time.Millisecond) // ensure TTL expires

	// Second call must re-resolve without error
	_, err = r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatalf("resolve after TTL expiry failed: %v", err)
	}
}

// ── did:web URL construction ──────────────────────────────────────────────────

func TestDidWebDocumentURL_RootDomain(t *testing.T) {
	got, err := didWebDocumentURL("did:web:example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://example.com/.well-known/did.json"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDidWebDocumentURL_WithPath(t *testing.T) {
	got, err := didWebDocumentURL("did:web:example.com:users:alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://example.com/users/alice/did.json"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDidWebDocumentURL_PercentEncodedPort(t *testing.T) {
	// did:web spec: port is encoded as a percent-escaped colon in the domain segment
	got, err := didWebDocumentURL("did:web:example.com%3A8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://example.com:8443/.well-known/did.json"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDidWebDocumentURL_MissingDomainReturnsError(t *testing.T) {
	_, err := didWebDocumentURL("did:web:")
	if err == nil {
		t.Fatal("expected error for missing domain, got nil")
	}
}

// ── did:web DID document parsing ─────────────────────────────────────────────

func TestExtractEd25519_PublicKeyMultibase(t *testing.T) {
	// Build a DID document with Ed25519VerificationKey2020 + publicKeyMultibase
	multicodec := append([]byte{multicodecEd25519Hi, multicodecEd25519Lo}, ed25519TestKey[:]...)
	encoded := "z" + base58Encode(multicodec)

	doc := []byte(`{
		"verificationMethod": [{
			"type": "Ed25519VerificationKey2020",
			"publicKeyMultibase": "` + encoded + `"
		}]
	}`)

	got, err := extractEd25519FromDIDDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ed25519TestKey {
		t.Errorf("got %x, want %x", got, ed25519TestKey)
	}
}

func TestExtractEd25519_PublicKeyJwk(t *testing.T) {
	// Build a DID document with JsonWebKey2020 + publicKeyJwk (OKP/Ed25519)
	xEncoded := base64.RawURLEncoding.EncodeToString(ed25519TestKey[:])
	doc := []byte(`{
		"verificationMethod": [{
			"type": "JsonWebKey2020",
			"publicKeyJwk": {
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "` + xEncoded + `"
			}
		}]
	}`)

	got, err := extractEd25519FromDIDDocument(doc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ed25519TestKey {
		t.Errorf("got %x, want %x", got, ed25519TestKey)
	}
}

func TestExtractEd25519_NoMatchingMethodReturnsError(t *testing.T) {
	doc := []byte(`{"verificationMethod": []}`)
	_, err := extractEd25519FromDIDDocument(doc)
	if err == nil {
		t.Fatal("expected error when no Ed25519 method found, got nil")
	}
}

func TestExtractEd25519_WrongMulticodecInMultibaseReturnsError(t *testing.T) {
	// publicKeyMultibase with wrong multicodec prefix (sha2-256 instead of ed25519)
	wrongPrefix := append([]byte{0x12, 0x00}, make([]byte, 32)...)
	encoded := "z" + base58Encode(wrongPrefix)
	doc := []byte(`{
		"verificationMethod": [{
			"type": "Ed25519VerificationKey2020",
			"publicKeyMultibase": "` + encoded + `"
		}]
	}`)
	_, err := extractEd25519FromDIDDocument(doc)
	if err == nil {
		t.Fatal("expected error for wrong multicodec prefix in publicKeyMultibase, got nil")
	}
}

// TestResolveDispatch_UnsupportedMethodReturnsError confirms that Resolve
// rejects DID methods other than did:key and did:web.
func TestResolveDispatch_UnsupportedMethodReturnsError(t *testing.T) {
	r, err := New(10, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = r.Resolve(context.Background(), "did:ethr:0xABCD")
	if err == nil {
		t.Fatal("expected error for unsupported DID method, got nil")
	}
}

// ── Concurrency tests ────────────────────────────────────────────────────────

func TestConcurrentDidKeyResolutionsDoNotBlock(t *testing.T) {
	r, err := New(100, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const goroutines = 50
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			did := encodeDIDKey(ed25519TestKey)
			_, resolveErr := r.Resolve(context.Background(), did)
			errs <- resolveErr
		}()
	}

	for i := 0; i < goroutines; i++ {
		if e := <-errs; e != nil {
			t.Errorf("concurrent did:key resolve failed: %v", e)
		}
	}
}

func TestSingleflightDeduplicatesConcurrentMisses(t *testing.T) {
	r, err := New(100, time.Nanosecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	did := encodeDIDKey(ed25519TestKey)

	const goroutines = 20
	type result struct {
		key [ed25519PublicKeyBytes]byte
		err error
	}
	ch := make(chan result, goroutines)

	time.Sleep(time.Millisecond)

	for i := 0; i < goroutines; i++ {
		go func() {
			key, resolveErr := r.Resolve(context.Background(), did)
			ch <- result{key: key, err: resolveErr}
		}()
	}

	for i := 0; i < goroutines; i++ {
		res := <-ch
		if res.err != nil {
			t.Errorf("concurrent resolve failed: %v", res.err)
		} else if res.key != ed25519TestKey {
			t.Errorf("unexpected key: got %x, want %x", res.key, ed25519TestKey)
		}
	}
}

// ── SSRF protection ───────────────────────────────────────────────────────────

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"169.254.169.254", true}, // AWS IMDS
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false}, // example.com
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("ParseIP(%q) returned nil", tc.ip)
		}
		got := isPrivateIP(ip)
		if got != tc.private {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}

func TestResolveDidWebSSRFLocalhost(t *testing.T) {
	res, err := New(10, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = res.Resolve(context.Background(), "did:web:localhost")
	if err == nil {
		t.Fatal("expected error for did:web:localhost (SSRF), got nil")
	}
	if !strings.Contains(err.Error(), "private") && !strings.Contains(err.Error(), "reserved") {
		t.Errorf("error should mention private/reserved address, got: %v", err)
	}
}

func TestResolveDidWebSSRFLinkLocal(t *testing.T) {
	res, err := New(10, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// 169.254.169.254 is an IP literal — LookupHost returns it as-is
	_, err = res.Resolve(context.Background(), "did:web:169.254.169.254")
	if err == nil {
		t.Fatal("expected error for did:web:169.254.169.254, got nil")
	}
}

// ── Circuit breaker ───────────────────────────────────────────────────────────

// buildTestDIDDocument returns a JSON DID document containing ed25519TestKey
// as a JsonWebKey2020 verification method. The DID subject is derived from the
// test server's Host header so the document is valid for the caller's DID.
func buildTestDIDDocument(t *testing.T, r *http.Request) []byte {
	t.Helper()
	x := base64.RawURLEncoding.EncodeToString(ed25519TestKey[:])
	doc := fmt.Sprintf(`{
		"@context": ["https://www.w3.org/ns/did/v1"],
		"id": "did:web:%s",
		"verificationMethod": [{
			"id": "did:web:%s#key-1",
			"type": "JsonWebKey2020",
			"controller": "did:web:%s",
			"publicKeyJwk": {
				"kty": "OKP",
				"crv": "Ed25519",
				"x": "%s"
			}
		}]
	}`, r.Host, r.Host, r.Host, x)
	return []byte(doc)
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	// Server that always returns 500 — simulates a dead did:web endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	did := "did:web:" + strings.ReplaceAll(host, ":", "%3A")

	res, err := NewWithCircuitBreaker(10, time.Hour, 3, 60*time.Second)
	if err != nil {
		t.Fatalf("NewWithCircuitBreaker: %v", err)
	}
	// Allow the test server (127.0.0.1) through the SSRF guard.
	res.allowPrivateHosts = true

	// First 3 attempts fail normally (circuit closed).
	for i := 0; i < 3; i++ {
		_, err := res.Resolve(context.Background(), did)
		if err == nil {
			t.Errorf("attempt %d: expected error, got nil", i)
		}
	}

	// 4th attempt: circuit is open — must return error immediately (no HTTP call).
	start := time.Now()
	_, err = res.Resolve(context.Background(), did)
	elapsed := time.Since(start)
	if err == nil {
		t.Error("open circuit: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "circuit") && !strings.Contains(err.Error(), "open") {
		t.Errorf("open circuit error should mention circuit/open, got: %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("open circuit should return immediately, took %v", elapsed)
	}
}

func TestCircuitBreakerClosesAfterCooldown(t *testing.T) {
	callCount := 0
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		cc := callCount
		mu.Unlock()
		if cc <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Third call (probe after cooldown): return a valid DID document.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buildTestDIDDocument(t, r))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	did := "did:web:" + strings.ReplaceAll(host, ":", "%3A")

	// 10ms cooldown for a fast test.
	res, err := NewWithCircuitBreaker(10, time.Hour, 2, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewWithCircuitBreaker: %v", err)
	}
	// Allow the test server (127.0.0.1) through the SSRF guard.
	res.allowPrivateHosts = true

	// 2 failures open the circuit.
	for i := 0; i < 2; i++ {
		res.Resolve(context.Background(), did) //nolint:errcheck
	}

	// Wait for cooldown.
	time.Sleep(20 * time.Millisecond)

	// Probe should succeed and close the circuit.
	_, err = res.Resolve(context.Background(), did)
	if err != nil {
		t.Errorf("probe after cooldown: expected success, got %v", err)
	}
}
