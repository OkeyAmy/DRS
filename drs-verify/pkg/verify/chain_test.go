package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// testDeps creates a Deps with a real resolver and no revocation check.
func testDeps(t *testing.T) Deps {
	t.Helper()
	res, err := resolver.New(100, time.Hour)
	if err != nil {
		t.Fatalf("resolver.New: %v", err)
	}
	return Deps{Resolver: res}
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
