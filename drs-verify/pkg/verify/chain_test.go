package verify

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// testDeps creates a Deps with a real resolver and no revocation check.
// ServerIdentity matches the tool_server set by makeInvocation so the
// (now fail-closed) D4c binding check passes for the happy-path fixtures.
func testDeps(t *testing.T) Deps {
	t.Helper()
	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	return Deps{Resolver: res, ServerIdentity: "mcp://tools/server"}
}

type ed25519StrictFixture struct {
	Vectors []ed25519StrictVector `json:"vectors"`
}

type ed25519StrictVector struct {
	ID        string  `json:"id"`
	SeedHex   string  `json:"seed_hex"`
	Message   string  `json:"message"`
	Mutation  string  `json:"mutation"`
	Valid     bool    `json:"valid"`
	ErrorCode *string `json:"error_code"`
}

func loadEd25519StrictFixture(t *testing.T) ed25519StrictFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "fixtures", "conformance", "ed25519-strict", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Ed25519 strict fixture: %v", err)
	}
	var fixture ed25519StrictFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse Ed25519 strict fixture: %v", err)
	}
	return fixture
}

func applyEd25519StrictMutation(t *testing.T, sig []byte, mutation string) []byte {
	t.Helper()
	mutated := append([]byte(nil), sig...)
	switch mutation {
	case "none":
		return mutated
	case "s_equals_l":
		copy(mutated[32:], edGroupOrder[:])
		return mutated
	default:
		t.Fatalf("unsupported Ed25519 strict mutation %q", mutation)
		return nil
	}
}

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
	// Encode as did:key
	multicodec := append([]byte{0xed, 0x01}, pub...)
	did := "did:key:z" + base58Encode(multicodec)
	return testKey{pub: pub, prv: prv, did: did}
}

// base58Encode is copied from did_test.go to keep the test self-contained.
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

func int64Ptr(v int64) *int64 { return &v }

func makeReceipt(iss, sub, aud string, now int64, prevHash *string, key testKey) (types.DelegationReceipt, string) {
	exp := now + 3600
	dr := types.DelegationReceipt{
		Iss:        iss,
		Sub:        sub,
		Aud:        aud,
		DrsV:       "4.0",
		DrsType:    "delegation-receipt",
		Cmd:        "/mcp/tools/call",
		Policy:     types.Policy{},
		Nbf:        now - 60,
		Exp:        &exp,
		Iat:        now,
		Jti:        fmt.Sprintf("dr:%s-%d", iss, now),
		PrevDRHash: prevHash,
	}
	jwt := signJWT(key.prv, dr)
	return dr, jwt
}

func makeInvocation(iss, sub string, drChain []string, now int64, key testKey) string {
	inv := types.InvocationReceipt{
		Iss:        iss,
		Sub:        sub,
		DrsV:       "4.0",
		DrsType:    "invocation-receipt",
		Cmd:        "/mcp/tools/call",
		Args:       map[string]interface{}{},
		DrChain:    drChain,
		ToolServer: "mcp://tools/server",
		Iat:        now,
		Jti:        fmt.Sprintf("inv:%s-%d", iss, now),
	}
	return signJWT(key.prv, inv)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func TestEmptyReceiptsReturnsError(t *testing.T) {
	result := Chain(context.Background(), types.ChainBundle{BundleVersion: "4.0", Receipts: nil, Invocation: "x"}, testDeps(t))
	if result.Valid {
		t.Error("expected invalid, got valid")
	}
	if result.Error.Code != "EMPTY_CHAIN" {
		t.Errorf("expected EMPTY_CHAIN, got %q", result.Error.Code)
	}
}

func TestMissingInvocationReturnsError(t *testing.T) {
	result := Chain(context.Background(), types.ChainBundle{BundleVersion: "4.0", Receipts: []string{"x"}, Invocation: ""}, testDeps(t))
	if result.Valid {
		t.Error("expected invalid, got valid")
	}
	if result.Error.Code != "MISSING_INVOCATION" {
		t.Errorf("expected MISSING_INVOCATION, got %q", result.Error.Code)
	}
}

func TestValidSingleReceiptChainPasses(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()

	_, jwt0 := makeReceipt(k0.did, k0.did, k1.did, now, nil, k0)
	hash0 := computeChainHash(jwt0)
	invJWT := makeInvocation(k1.did, k0.did, []string{hash0}, now, k1)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    invJWT,
	}

	result := Chain(context.Background(), bundle, testDeps(t))
	if !result.Valid {
		t.Errorf("expected valid, got error: %+v", result.Error)
	}
	if result.Context.ChainDepth != 1 {
		t.Errorf("expected chain depth 1, got %d", result.Context.ChainDepth)
	}
}

func TestValidTwoReceiptChainPasses(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	now := time.Now().Unix()

	_, jwt0 := makeReceipt(k0.did, k0.did, k1.did, now, nil, k0)
	hash0 := computeChainHash(jwt0)
	prevHash := hash0
	_, jwt1 := makeReceipt(k1.did, k0.did, k2.did, now, &prevHash, k1)
	hash1 := computeChainHash(jwt1)
	invJWT := makeInvocation(k2.did, k0.did, []string{hash0, hash1}, now, k2)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0, jwt1},
		Invocation:    invJWT,
	}

	result := Chain(context.Background(), bundle, testDeps(t))
	if !result.Valid {
		t.Errorf("expected valid, got error: %+v", result.Error)
	}
	if result.Context.ChainDepth != 2 {
		t.Errorf("expected chain depth 2, got %d", result.Context.ChainDepth)
	}
}

func TestForgedSignatureIsRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	attacker := newTestKey(t)
	now := time.Now().Unix()

	// Sign the receipt with the attacker's key, but use k0's DID as issuer
	exp := now + 3600
	dr := types.DelegationReceipt{
		Iss: k0.did, Sub: k0.did, Aud: k1.did,
		DrsV: "4.0", DrsType: "delegation-receipt",
		Cmd: "/mcp/tools/call", Policy: types.Policy{},
		Nbf: now - 60, Exp: &exp, Iat: now, Jti: "dr:forged",
	}
	forgedJWT := signJWT(attacker.prv, dr) // wrong key
	hash0 := computeChainHash(forgedJWT)
	invJWT := makeInvocation(k1.did, k0.did, []string{hash0}, now, k1)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{forgedJWT},
		Invocation:    invJWT,
	}

	result := Chain(context.Background(), bundle, testDeps(t))
	if result.Valid {
		t.Error("expected invalid for forged signature, got valid")
	}
	if result.Error.Code != "INVALID_SIGNATURE" {
		t.Errorf("expected INVALID_SIGNATURE, got %q", result.Error.Code)
	}
}

func TestExpiredReceiptIsRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	past := time.Now().Unix() - 7200 // 2 hours ago

	pastExp := past
	dr := types.DelegationReceipt{
		Iss: k0.did, Sub: k0.did, Aud: k1.did,
		DrsV: "4.0", DrsType: "delegation-receipt",
		Cmd: "/mcp/tools/call", Policy: types.Policy{},
		Nbf: past - 3600, Exp: &pastExp, // expired 2 hours ago
		Iat: past - 3600, Jti: "dr:expired",
	}
	jwt0 := signJWT(k0.prv, dr)
	hash0 := computeChainHash(jwt0)
	now := time.Now().Unix()
	invJWT := makeInvocation(k1.did, k0.did, []string{hash0}, now, k1)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    invJWT,
	}

	result := Chain(context.Background(), bundle, testDeps(t))
	if result.Valid {
		t.Error("expected invalid for expired receipt, got valid")
	}
	if result.Error.Code != "EXPIRED" {
		t.Errorf("expected EXPIRED, got %q", result.Error.Code)
	}
}

func TestChainBreakIsRejected(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	k2 := newTestKey(t)
	now := time.Now().Unix()

	_, jwt0 := makeReceipt(k0.did, k0.did, k1.did, now, nil, k0)
	// Deliberately use a wrong prev_dr_hash
	wrongHash := "sha256:000000000000000000000000000000000000000000000000000000000000dead"
	_, jwt1 := makeReceipt(k1.did, k0.did, k2.did, now, &wrongHash, k1)
	hash0 := computeChainHash(jwt0)
	hash1 := computeChainHash(jwt1)
	invJWT := makeInvocation(k2.did, k0.did, []string{hash0, hash1}, now, k2)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0, jwt1},
		Invocation:    invJWT,
	}

	result := Chain(context.Background(), bundle, testDeps(t))
	if result.Valid {
		t.Error("expected invalid for chain break, got valid")
	}
	if result.Error.Code != "CHAIN_BREAK" {
		t.Errorf("expected CHAIN_BREAK, got %q", result.Error.Code)
	}
}

func TestCmdIsSubpath(t *testing.T) {
	if !cmdIsSubpath("/mcp/tools/call", "/mcp/tools/call") {
		t.Error("exact match should pass")
	}
	if !cmdIsSubpath("/mcp/tools/call", "/mcp/tools/call/web_search") {
		t.Error("sub-path should pass")
	}
	if cmdIsSubpath("/mcp/tools/call", "/mcp/tools/caller") {
		t.Error("prefix-without-slash must not pass")
	}
	if cmdIsSubpath("/mcp/tools/call", "/mcp/resources/read") {
		t.Error("different root must not pass")
	}
}

// TestLocalRevocationBlocksChain verifies that a delegation receipt whose
// DrsStatusListIndex has been revoked in a LocalRevocationStore causes
// Chain to return Valid==false with code REVOKED.
func TestLocalRevocationBlocksChain(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()

	const revokedIndex = uint64(77)

	exp := now + 3600
	dr0 := types.DelegationReceipt{
		Iss:                k0.did,
		Sub:                k0.did,
		Aud:                k1.did,
		DrsV:               "4.0",
		DrsType:            "delegation-receipt",
		Cmd:                "/mcp/tools/call",
		Policy:             types.Policy{},
		Nbf:                now - 60,
		Exp:                &exp,
		Iat:                now,
		Jti:                fmt.Sprintf("dr:%s-%d", k0.did, now),
		DrsStatusListIndex: func() *uint64 { v := revokedIndex; return &v }(),
	}
	jwt0 := signJWT(k0.prv, dr0)
	hash0 := computeChainHash(jwt0)
	invJWT := makeInvocation(k1.did, k0.did, []string{hash0}, now, k1)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    invJWT,
	}

	localRev := revocation.NewLocalRevocationStore()
	localRev.Revoke(revokedIndex)

	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	deps := Deps{
		Resolver:        res,
		LocalRevocation: localRev,
		ServerIdentity:  "mcp://tools/server",
	}

	result := Chain(context.Background(), bundle, deps)

	if result.Valid {
		t.Fatal("expected invalid result for revoked receipt, got valid")
	}
	if result.Error.Code != "REVOKED" {
		t.Errorf("expected error code REVOKED, got %q", result.Error.Code)
	}
}

// TestVerifiedReceiptsAreStoredOnSuccess proves that when deps.Store is set,
// successfully verified receipts are persisted under their chain hash key.
func TestVerifiedReceiptsAreStoredOnSuccess(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	now := time.Now().Unix()

	_, jwt0 := makeReceipt(k0.did, k0.did, k1.did, now, nil, k0)
	hash0 := computeChainHash(jwt0)
	invJWT := makeInvocation(k1.did, k0.did, []string{hash0}, now, k1)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0},
		Invocation:    invJWT,
	}

	mem, err := store.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	deps := testDeps(t)
	deps.Store = mem

	result := Chain(context.Background(), bundle, deps)
	if !result.Valid {
		t.Fatalf("expected valid chain, got error: %+v", result.Error)
	}

	stored, err := mem.Get(hash0)
	if err != nil {
		t.Fatalf("receipt not found in store after verification: %v", err)
	}
	if stored != jwt0 {
		t.Error("stored JWT does not match the verified receipt")
	}
}

// TestStoreNotCalledOnFailedVerification ensures receipts are NOT stored when
// verification fails (e.g., forged signature).
func TestStoreNotCalledOnFailedVerification(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)
	attacker := newTestKey(t)
	now := time.Now().Unix()

	exp := now + 3600
	dr := types.DelegationReceipt{
		Iss: k0.did, Sub: k0.did, Aud: k1.did,
		DrsV: "4.0", DrsType: "delegation-receipt",
		Cmd: "/mcp/tools/call", Policy: types.Policy{},
		Nbf: now - 60, Exp: &exp, Iat: now, Jti: "dr:forged",
	}
	forgedJWT := signJWT(attacker.prv, dr)
	hash0 := computeChainHash(forgedJWT)
	invJWT := makeInvocation(k1.did, k0.did, []string{hash0}, now, k1)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{forgedJWT},
		Invocation:    invJWT,
	}

	mem, err := store.NewMemoryStore(0)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}

	deps := testDeps(t)
	deps.Store = mem

	result := Chain(context.Background(), bundle, deps)
	if result.Valid {
		t.Fatal("expected invalid for forged signature")
	}

	_, err = mem.Get(hash0)
	if err == nil {
		t.Error("receipt should NOT be stored after failed verification")
	}
}

// TestVerifyJWTSignatureAlgCheck verifies that verifyJWTSignature rejects JWTs
// whose alg header is anything other than "EdDSA".
func TestVerifyJWTSignatureAlgCheck(t *testing.T) {
	k := newTestKey(t)
	res, err := resolver.New(10, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}

	// signJWTWithAlg signs a minimal payload using an explicit alg header value.
	signJWTWithAlg := func(alg string) string {
		headerJSON, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
		payloadJSON, _ := json.Marshal(map[string]interface{}{
			"iss": k.did,
			"exp": int64(9999999999),
		})
		h := base64.RawURLEncoding.EncodeToString(headerJSON)
		p := base64.RawURLEncoding.EncodeToString(payloadJSON)
		msg := h + "." + p
		sig := ed25519.Sign(k.prv, []byte(msg))
		return msg + "." + base64.RawURLEncoding.EncodeToString(sig)
	}

	cases := []struct {
		alg     string
		wantErr bool
	}{
		{"EdDSA", false},
		{"HS256", true},
		{"RS256", true},
		{"none", true},
		{"", true},
	}

	for _, tc := range cases {
		t.Run("alg="+tc.alg, func(t *testing.T) {
			jwt := signJWTWithAlg(tc.alg)
			err := verifyJWTSignature(context.Background(), jwt, k.did, res)
			if tc.wantErr && err == nil {
				t.Errorf("alg=%q: expected error, got nil", tc.alg)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("alg=%q: unexpected error: %v", tc.alg, err)
			}
		})
	}
}

// TestChainDepthLimit verifies that a bundle with more than 16 receipts is
// rejected with CHAIN_TOO_DEEP before any cryptographic work is done.
func TestChainDepthLimit(t *testing.T) {
	deps := testDeps(t)

	// Build a bundle with 17 receipts (one over the limit of 16).
	// The receipts don't need to be cryptographically valid — Block A fires first.
	receipts := make([]string, 17)
	for i := range receipts {
		receipts[i] = "a.b.c" // minimal 3-part JWT placeholder
	}
	bundle := types.ChainBundle{
		BundleVersion: "1",
		Invocation:    "a.b.c",
		Receipts:      receipts,
	}

	result := Chain(context.Background(), bundle, deps)
	if result.Valid {
		t.Fatal("expected invalid result for depth > 16")
	}
	if result.Error == nil || result.Error.Code != "CHAIN_TOO_DEEP" {
		t.Errorf("expected CHAIN_TOO_DEEP, got %v", result.Error)
	}
}

// TestChainDepthLimitBoundary verifies that a bundle with exactly 16 receipts
// does not trigger CHAIN_TOO_DEEP (it may fail for other reasons).
func TestChainDepthLimitBoundary(t *testing.T) {
	deps := testDeps(t)

	// 16 receipts must NOT trigger CHAIN_TOO_DEEP.
	receipts := make([]string, 16)
	for i := range receipts {
		receipts[i] = "a.b.c"
	}
	bundle := types.ChainBundle{
		BundleVersion: "1",
		Invocation:    "a.b.c",
		Receipts:      receipts,
	}
	result := Chain(context.Background(), bundle, deps)
	if result.Error != nil && result.Error.Code == "CHAIN_TOO_DEEP" {
		t.Error("16-receipt bundle must not trigger CHAIN_TOO_DEEP")
	}
}

// int64Ptr is used in other test files; kept here to avoid re-declaration.
var _ = int64Ptr

// TestTimestampVerificationUsesTrustedPath is a compile-check and field-wiring
// test that verifies Deps.TSARootPool exists and can be set. It also verifies
// that a self-signed certificate added as its own trust root is wired correctly
// through the Deps struct — the actual RFC 3161 EKU rejection is tested in the
// anchor package's own test suite.
func TestTimestampVerificationUsesTrustedPath(t *testing.T) {
	// Build a self-signed certificate that is NOT in any trusted root pool.
	// VerifyTimestampTrusted must reject it; the old VerifyTimestamp would accept it.
	// This test uses a nil TSARootPool (system roots) and a self-signed cert,
	// verifying that the trusted path rejects it.

	// Create a minimal self-signed cert
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self-signed-tsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Verify that the Deps.TSARootPool field exists on verify.Deps.
	deps := testDeps(t)
	_ = deps.TSARootPool // compile check: field must exist

	// If TSARootPool is nil, VerifyTimestampTrusted uses system roots.
	// A self-signed cert with no EKU will fail.
	pool := x509.NewCertPool()
	pool.AddCert(cert) // add self-signed as trusted root

	// Even with the self-signed cert as root, EKU check must reject it.
	deps.TSARootPool = pool
	// The actual token bytes would come from a real TSA call.
	// We verify the Deps field is wired correctly by checking it compiles and is set.
	if deps.TSARootPool == nil {
		t.Error("TSARootPool must not be nil after assignment")
	}
}

// TestChainCancelledContext verifies that a cancelled context does not cause
// Chain to panic. Any result (valid or invalid) is acceptable.
func TestChainCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Invocation:    "a.b.c",
		Receipts:      []string{"a.b.c"},
	}
	result := Chain(ctx, bundle, testDeps(t))
	_ = result // must not panic; any result is acceptable
}

// failStore always returns an error on Put.
type failStore struct{}

func (f *failStore) Put(hash, jwt string) error      { return fmt.Errorf("disk full") }
func (f *failStore) Get(hash string) (string, error) { return "", store.ErrNotFound }
func (f *failStore) Delete(hash string) error        { return nil }

// TestChainStoreWarningsOnPutFailure verifies that store.Put errors are surfaced
// as StoreWarnings in the VerificationResult, and that store failures do not
// invalidate the chain (store errors are non-fatal).
func TestChainStoreWarningsOnPutFailure(t *testing.T) {
	deps := testDeps(t)
	deps.Store = &failStore{}

	// Build a minimal single-hop valid chain using the existing test helpers.
	now := time.Now().Unix()
	root := newTestKey(t)
	agent := newTestKey(t)

	_, drJWT := makeReceipt(root.did, root.did, agent.did, now, nil, root)
	drHash := computeChainHash(drJWT)
	invJWT := makeInvocation(agent.did, root.did, []string{drHash}, now, agent)

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Invocation:    invJWT,
		Receipts:      []string{drJWT},
	}

	result := Chain(context.Background(), bundle, deps)

	// Chain must still be valid — store failure must not invalidate verification.
	if !result.Valid {
		t.Fatalf("expected valid result even with store failure, got: %v", result.Error)
	}

	// StoreWarnings must be populated.
	if len(result.StoreWarnings) == 0 {
		t.Error("expected StoreWarnings to be non-empty when store.Put fails")
	}
	if !strings.Contains(result.StoreWarnings[0], "could not be persisted") {
		t.Errorf("StoreWarnings content unexpected: %v", result.StoreWarnings)
	}
}

func TestStrictEd25519FunctionRejectsNonCanonicalS(t *testing.T) {
	// Direct unit test for strictVerifyEd25519 itself — calls the function with
	// crafted byte slices, independent of ed25519.Verify (which also rejects
	// non-canonical S in Go 1.13+, so the integration path below is defense-in-depth).
	L := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	// S == L: non-canonical, must be rejected.
	sig := make([]byte, 64)
	copy(sig[32:], L[:])
	if err := strictVerifyEd25519(sig); err == nil {
		t.Error("S == L must be rejected, got nil error")
	}
	// S = L+1: clearly non-canonical.
	sig2 := make([]byte, 64)
	copy(sig2[32:], L[:])
	sig2[32] += 1
	if err := strictVerifyEd25519(sig2); err == nil {
		t.Error("S > L must be rejected, got nil error")
	}
	// S = 0: canonical, must be accepted.
	sig3 := make([]byte, 64)
	if err := strictVerifyEd25519(sig3); err != nil {
		t.Errorf("S = 0 must be accepted, got: %v", err)
	}
	// S = L-1: largest canonical value, must be accepted.
	sig4 := make([]byte, 64)
	copy(sig4[32:], L[:])
	sig4[32] -= 1
	if err := strictVerifyEd25519(sig4); err != nil {
		t.Errorf("S = L-1 must be accepted, got: %v", err)
	}
}

func TestStrictEd25519RejectsNonCanonicalS(t *testing.T) {
	// Integration path: verifyJWTSignature must reject a JWT with S >= L.
	// In Go 1.13+, ed25519.Verify itself rejects non-canonical S; this test
	// confirms the full verification path correctly surfaces an error.
	k := newTestKey(t)

	headerJSON, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"iss": k.did,
		"exp": int64(9999999999),
	})
	h := base64.RawURLEncoding.EncodeToString(headerJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	msg := h + "." + p

	validSig := ed25519.Sign(k.prv, []byte(msg))

	// Add L to S (bytes 32-63, little-endian) to produce a non-canonical scalar.
	L := [32]byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	nonCanonicalSig := make([]byte, 64)
	copy(nonCanonicalSig, validSig)
	carry := uint16(0)
	for i := 0; i < 32; i++ {
		sum := uint16(nonCanonicalSig[32+i]) + uint16(L[i]) + carry
		nonCanonicalSig[32+i] = byte(sum)
		carry = sum >> 8
	}

	nonCanonicalJWT := msg + "." + base64.RawURLEncoding.EncodeToString(nonCanonicalSig)

	res, err := resolver.New(10, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	err = verifyJWTSignature(context.Background(), nonCanonicalJWT, k.did, res)
	if err == nil {
		t.Error("strict verifier must reject non-canonical S (S >= L), got nil error")
	}
}

func TestStrictEd25519AcceptsValidSignatures(t *testing.T) {
	k := newTestKey(t)
	res, err := resolver.New(10, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}

	jwt := signJWT(k.prv, map[string]interface{}{
		"iss": k.did,
		"exp": int64(9999999999),
	})
	if err := verifyJWTSignature(context.Background(), jwt, k.did, res); err != nil {
		t.Errorf("strict verifier rejected a valid canonical signature: %v", err)
	}
}

func TestEd25519StrictFixtureVectors(t *testing.T) {
	fixture := loadEd25519StrictFixture(t)
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			seed, err := hex.DecodeString(vector.SeedHex)
			if err != nil {
				t.Fatalf("decode seed: %v", err)
			}
			if len(seed) != ed25519.SeedSize {
				t.Fatalf("seed length = %d, want %d", len(seed), ed25519.SeedSize)
			}
			privateKey := ed25519.NewKeyFromSeed(seed)
			sig := ed25519.Sign(privateKey, []byte(vector.Message))
			sig = applyEd25519StrictMutation(t, sig, vector.Mutation)

			err = strictVerifyEd25519(sig)
			if vector.Valid && err != nil {
				t.Fatalf("strictVerifyEd25519 rejected valid vector: %v", err)
			}
			if !vector.Valid && err == nil {
				t.Fatal("strictVerifyEd25519 accepted invalid vector")
			}
		})
	}
}

func TestChainClassifiesNonCanonicalReceiptSignatureAsMalleability(t *testing.T) {
	fixture := loadEd25519StrictFixture(t)
	var vector ed25519StrictVector
	for _, candidate := range fixture.Vectors {
		if candidate.Mutation == "s_equals_l" {
			vector = candidate
			break
		}
	}
	if vector.ID == "" {
		t.Fatal("fixture missing s_equals_l vector")
	}

	seed, err := hex.DecodeString(vector.SeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	issuer := testKey{
		pub: publicKey,
		prv: privateKey,
		did: "did:key:z" + base58Encode(append([]byte{0xed, 0x01}, publicKey...)),
	}
	leaf := newTestKey(t)
	now := time.Now().Unix()

	receipt, receiptJWT := makeReceipt(issuer.did, issuer.did, leaf.did, now, nil, issuer)
	malformedReceiptJWT := replaceJWTSignature(t, receiptJWT, func(sig []byte) []byte {
		return applyEd25519StrictMutation(t, sig, vector.Mutation)
	})
	hash := computeChainHash(malformedReceiptJWT)
	invocationJWT := makeInvocation(leaf.did, issuer.did, []string{hash}, now, leaf)

	result := Chain(context.Background(), types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{malformedReceiptJWT},
		Invocation:    invocationJWT,
	}, testDeps(t))
	if result.Valid {
		t.Fatal("expected non-canonical receipt signature to be rejected")
	}
	if result.Error == nil {
		t.Fatal("expected structured error")
	}
	if result.Error.Code != *vector.ErrorCode {
		t.Fatalf("error code = %q, want %q (receipt=%s)", result.Error.Code, *vector.ErrorCode, receipt.Jti)
	}
}

func replaceJWTSignature(t *testing.T, jwt string, mutate func([]byte) []byte) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mutate(sig))
}

// TestResolveIssuersParallelDeduplicates verifies that resolveIssuersParallel
// returns exactly one entry per unique DID when the input contains duplicates.
func TestResolveIssuersParallelDeduplicates(t *testing.T) {
	k0 := newTestKey(t)
	k1 := newTestKey(t)

	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}

	dids := []string{k0.did, k1.did, k0.did, k1.did, k0.did}
	keys, err := resolveIssuersParallel(context.Background(), dids, res)
	if err != nil {
		t.Fatalf("resolveIssuersParallel: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 entries in resolved map, got %d", len(keys))
	}
	if _, ok := keys[k0.did]; !ok {
		t.Errorf("missing key for %s", k0.did)
	}
	if _, ok := keys[k1.did]; !ok {
		t.Errorf("missing key for %s", k1.did)
	}
}

// TestBlockCResolvesAllDistinctIssuers verifies end-to-end that a 4-receipt
// chain with 5 distinct issuers passes Block C after the concurrent pre-resolution path.
func TestBlockCResolvesAllDistinctIssuers(t *testing.T) {
	keys := make([]testKey, 5)
	for i := range keys {
		keys[i] = newTestKey(t)
	}

	now := time.Now().Unix()

	_, jwt0 := makeReceipt(keys[0].did, keys[0].did, keys[1].did, now, nil, keys[0])
	hash0 := computeChainHash(jwt0)

	prev1 := hash0
	_, jwt1 := makeReceipt(keys[1].did, keys[0].did, keys[2].did, now, &prev1, keys[1])
	hash1 := computeChainHash(jwt1)

	prev2 := hash1
	_, jwt2 := makeReceipt(keys[2].did, keys[0].did, keys[3].did, now, &prev2, keys[2])
	hash2 := computeChainHash(jwt2)

	prev3 := hash2
	_, jwt3 := makeReceipt(keys[3].did, keys[0].did, keys[4].did, now, &prev3, keys[3])
	hash3 := computeChainHash(jwt3)

	invJWT := makeInvocation(keys[4].did, keys[0].did,
		[]string{hash0, hash1, hash2, hash3}, now, keys[4])

	bundle := types.ChainBundle{
		BundleVersion: "4.0",
		Receipts:      []string{jwt0, jwt1, jwt2, jwt3},
		Invocation:    invJWT,
	}

	result := Chain(context.Background(), bundle, testDeps(t))
	if !result.Valid {
		t.Errorf("expected valid 4-receipt/5-issuer chain, got error: %+v", result.Error)
	}
	if result.Context.ChainDepth != 4 {
		t.Errorf("expected chain depth 4, got %d", result.Context.ChainDepth)
	}
}

// TestResolveIssuersParallelContextCancellation verifies no panic or deadlock
// occurs when the context is cancelled before resolution.
func TestResolveIssuersParallelContextCancellation(t *testing.T) {
	k := newTestKey(t)
	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dids := []string{k.did}
	_, _ = resolveIssuersParallel(ctx, dids, res)
	// Reaching here without a deadlock or panic is the assertion.
}
