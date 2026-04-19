// Package verify implements the six-block DRS chain verification algorithm.
//
// Block A — Completeness
// Block B — Structural Integrity
// Block C — Cryptographic Validity (Ed25519 via Go stdlib crypto/ed25519)
// Block D — Semantic/Policy Validity
// Block E — Temporal Validity
// Block F — Revocation (requires I/O; handled here, unlike the Rust core)
//
// Returns VerificationResult always — never panics.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
	"github.com/drs-protocol/drs-verify/pkg/policy"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
)

const (
	expectedDRSVersion = "4.0"
	expectedDRType     = "delegation-receipt"
	expectedInvType    = "invocation-receipt"
)

// jwtHeader holds the minimum fields needed to validate a JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
}

// decodeJWTHeader base64url-decodes the JWT header (parts[0]) into a jwtHeader.
func decodeJWTHeader(jwt string) (jwtHeader, error) {
	parts := strings.SplitN(jwt, ".", 4)
	if len(parts) != 3 {
		return jwtHeader{}, fmt.Errorf("expected 3 dot-separated JWT parts, got %d", len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return jwtHeader{}, fmt.Errorf("JWT header base64 decode: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return jwtHeader{}, fmt.Errorf("JWT header JSON unmarshal: %w", err)
	}
	return hdr, nil
}

// Deps bundles the I/O dependencies needed for Block C, Block F, and DR storage.
type Deps struct {
	Resolver          *resolver.Resolver
	Revocation        *revocation.StatusCache
	LocalRevocation   *revocation.LocalRevocationStore
	Store             store.Store
	// ServerIdentity is this server's DID or identifier. When set, the verifier
	// enforces that invocation.tool_server matches this value, binding the
	// invocation to the intended destination. Empty disables the check.
	ServerIdentity string
	// IncludeTimestamps enables RFC 3161 timestamp verification after Block F.
	// For each receipt, retrieves the stored .tst token (if any) and verifies it.
	// Timestamp failures are reported in VerificationResult.Timestamps but do not
	// fail the overall chain verification.
	IncludeTimestamps bool
}

// Chain verifies a DRS chain bundle through all six blocks.
// Returns a VerificationResult — never panics.
func Chain(bundle types.ChainBundle, deps Deps) types.VerificationResult {
	// ── Block A: Completeness ────────────────────────────────────────────────

	if len(bundle.Receipts) == 0 {
		return types.Invalid("EMPTY_CHAIN",
			"bundle.receipts is empty — at least one delegation receipt is required.",
			"Ensure the chain bundle includes all delegation receipts from root to leaf.")
	}
	if bundle.Invocation == "" {
		return types.Invalid("MISSING_INVOCATION",
			"bundle.invocation is empty.",
			"Include the signed invocation receipt in the bundle.")
	}

	// ── Decode all receipt payloads ──────────────────────────────────────────

	receipts := make([]types.DelegationReceipt, 0, len(bundle.Receipts))
	for i, jwt := range bundle.Receipts {
		var dr types.DelegationReceipt
		if err := decodeJWTPayload(jwt, &dr); err != nil {
			return types.Invalid("MALFORMED_RECEIPT",
				fmt.Sprintf("receipt[%d] JWT decoding failed: %v", i, err),
				"Ensure all receipts are valid JWTs.")
		}
		receipts = append(receipts, dr)
	}

	// ── Decode invocation payload ────────────────────────────────────────────

	var invocation types.InvocationReceipt
	if err := decodeJWTPayload(bundle.Invocation, &invocation); err != nil {
		return types.Invalid("MALFORMED_INVOCATION",
			fmt.Sprintf("invocation JWT decoding failed: %v", err),
			"Ensure the invocation receipt is a valid JWT.")
	}

	// ── Block B: Structural Integrity ────────────────────────────────────────

	// B1: type and version checks
	for i, r := range receipts {
		if r.DrsType != expectedDRType {
			return types.Invalid("WRONG_TYPE",
				fmt.Sprintf("receipt[%d].drs_type is %q but must be %q.", i, r.DrsType, expectedDRType),
				"Only delegation receipts may appear in bundle.receipts.")
		}
		if r.DrsV != expectedDRSVersion {
			return types.Invalid("VERSION_MISMATCH",
				fmt.Sprintf("receipt[%d].drs_v is %q but this verifier requires %q.", i, r.DrsV, expectedDRSVersion),
				"Ensure all receipts are issued against DRS spec version 4.0.")
		}
	}
	if invocation.DrsType != expectedInvType {
		return types.Invalid("WRONG_TYPE",
			fmt.Sprintf("invocation.drs_type is %q but must be %q.", invocation.DrsType, expectedInvType),
			"The invocation field must contain an invocation-receipt, not a delegation-receipt.")
	}
	if invocation.DrsV != expectedDRSVersion {
		return types.Invalid("VERSION_MISMATCH",
			fmt.Sprintf("invocation.drs_v is %q but this verifier requires %q.", invocation.DrsV, expectedDRSVersion),
			"Ensure the invocation receipt is issued against DRS spec version 4.0.")
	}

	// B1b: JTI prefix validation
	for i, r := range receipts {
		if !strings.HasPrefix(r.Jti, "dr:") {
			return types.Invalid("INVALID_JTI",
				fmt.Sprintf("receipt[%d].jti %q must start with 'dr:'.", i, r.Jti),
				"Delegation receipt JTIs must use the 'dr:' prefix per DRS 4.0 §5.")
		}
	}
	if !strings.HasPrefix(invocation.Jti, "inv:") {
		return types.Invalid("INVALID_JTI",
			fmt.Sprintf("invocation.jti %q must start with 'inv:'.", invocation.Jti),
			"Invocation receipt JTIs must use the 'inv:' prefix per DRS 4.0 §5.")
	}

	// B2: root DR — prev_dr_hash must be null
	if receipts[0].PrevDRHash != nil {
		return types.Invalid("CHAIN_STRUCTURE",
			"receipt[0] must have no prev_dr_hash (it is the root delegation).",
			"The first receipt in the chain must be the root delegation with no parent.")
	}
	if receipts[0].DrsRootType != nil && *receipts[0].DrsRootType == "human" && receipts[0].DrsConsent == nil {
		return types.Invalid("MISSING_CONSENT",
			"receipt[0].drs_root_type is 'human' but drs_consent is absent.",
			"Human-rooted delegations must include consent evidence (method, timestamp, session_id, policy_hash, locale).")
	}

	// B3: chain hash linkage
	for i := 1; i < len(bundle.Receipts); i++ {
		expected := computeChainHash(bundle.Receipts[i-1])
		if receipts[i].PrevDRHash == nil {
			return types.Invalid("CHAIN_BREAK",
				fmt.Sprintf("receipt[%d] missing prev_dr_hash (expected %s).", i, expected),
				"Each receipt after the root must reference the hash of the previous receipt.")
		}
		if *receipts[i].PrevDRHash != expected {
			return types.Invalid("CHAIN_BREAK",
				fmt.Sprintf("receipt[%d] prev_dr_hash mismatch: claimed %q, expected %q.", i, *receipts[i].PrevDRHash, expected),
				"DR at index 0 may have been modified after DR at index 1 was issued, or the receipts are in the wrong order.")
		}
	}

	// B4: DRᵢ.iss must equal DRᵢ₋₁.aud
	for i := 1; i < len(receipts); i++ {
		if receipts[i].Iss != receipts[i-1].Aud {
			return types.Invalid("ISSUER_MISMATCH",
				fmt.Sprintf("receipt[%d].iss %q ≠ receipt[%d].aud %q.", i, receipts[i].Iss, i-1, receipts[i-1].Aud),
				"Each delegation must be issued by the audience of the previous delegation.")
		}
	}

	// B5: invocation.iss must equal last receipt's aud
	last := receipts[len(receipts)-1]
	if invocation.Iss != last.Aud {
		return types.Invalid("INVOKER_MISMATCH",
			fmt.Sprintf("invocation.iss %q ≠ last receipt.aud %q.", invocation.Iss, last.Aud),
			"The invocation must be issued by the audience of the leaf delegation receipt.")
	}

	// B6: invocation.dr_chain must match SHA-256 hashes of all receipts
	if len(invocation.DrChain) != len(bundle.Receipts) {
		return types.Invalid("CHAIN_REFERENCE_MISMATCH",
			fmt.Sprintf("invocation.dr_chain has %d entries but bundle has %d receipts.",
				len(invocation.DrChain), len(bundle.Receipts)),
			"invocation.dr_chain must contain exactly one hash per receipt, in root-first order.")
	}
	for i, jwt := range bundle.Receipts {
		expected := computeChainHash(jwt)
		if invocation.DrChain[i] != expected {
			return types.Invalid("CHAIN_REFERENCE_MISMATCH",
				fmt.Sprintf("invocation.dr_chain[%d] %q ≠ computed hash %q.", i, invocation.DrChain[i], expected),
				"The dr_chain references do not match the provided receipts.")
		}
	}

	// ── Block C: Cryptographic Validity ─────────────────────────────────────

	for i, jwt := range bundle.Receipts {
		if err := verifyJWTSignature(jwt, receipts[i].Iss, deps.Resolver); err != nil {
			code, suggestion := classifySignatureError(err)
			return types.Invalid(code,
				fmt.Sprintf("receipt[%d] signature check failed: %v", i, err),
				suggestion)
		}
	}
	if err := verifyJWTSignature(bundle.Invocation, invocation.Iss, deps.Resolver); err != nil {
		code, suggestion := classifySignatureError(err)
		if code == "INVALID_SIGNATURE" {
			code = "INVALID_INVOCATION_SIGNATURE"
		}
		return types.Invalid(code,
			fmt.Sprintf("invocation signature check failed: %v", err),
			suggestion)
	}

	// ── Block D: Semantic/Policy Validity ────────────────────────────────────
	// D1–D4 are spec section numbers from §6.2, not execution order.
	// Execution order is D3 → D4 → D2 → D1 (structural checks before semantic).

	// D3: command must be equal or a sub-path of root cmd
	rootCmd := receipts[0].Cmd
	for i := 1; i < len(receipts); i++ {
		if !cmdIsSubpath(rootCmd, receipts[i].Cmd) {
			return types.Invalid("COMMAND_MISMATCH",
				fmt.Sprintf("receipt[%d].cmd %q is not equal to or a sub-path of root cmd %q.", i, receipts[i].Cmd, rootCmd),
				"All delegation receipts in a chain must delegate the same command or a sub-command.")
		}
	}
	if !cmdIsSubpath(rootCmd, invocation.Cmd) {
		return types.Invalid("COMMAND_MISMATCH",
			fmt.Sprintf("invocation.cmd %q is not equal to or a sub-path of root cmd %q.", invocation.Cmd, rootCmd),
			"The invocation command must match or be a sub-path of the delegated command.")
	}

	// D4: all DRs must share the same sub
	rootSub := receipts[0].Sub
	for i := 1; i < len(receipts); i++ {
		if receipts[i].Sub != rootSub {
			return types.Invalid("SUBJECT_MISMATCH",
				fmt.Sprintf("receipt[%d].sub %q ≠ root sub %q.", i, receipts[i].Sub, rootSub),
				"All delegation receipts must carry the same sub (the original resource owner).")
		}
	}

	// D4b: invocation.sub must equal root sub (binding invocation to chain subject)
	if invocation.Sub != rootSub {
		return types.Invalid("INVOCATION_SUBJECT_MISMATCH",
			fmt.Sprintf("invocation.sub %q ≠ chain root sub %q.", invocation.Sub, rootSub),
			"The invocation must reference the same subject as the delegation chain.")
	}

	// D4c: invocation.tool_server must match the server's configured identity
	if deps.ServerIdentity != "" && invocation.ToolServer != deps.ServerIdentity {
		return types.Invalid("TOOL_SERVER_MISMATCH",
			fmt.Sprintf("invocation.tool_server %q ≠ expected server identity %q.", invocation.ToolServer, deps.ServerIdentity),
			"The invocation targets a different tool server than this verifier.")
	}

	// D2: policy attenuation — child policy must be a subset of parent policy
	for i := 1; i < len(receipts); i++ {
		if err := policy.CheckAttenuation(receipts[i-1].Policy, receipts[i].Policy); err != nil {
			return types.Invalid("POLICY_ESCALATION",
				fmt.Sprintf("receipt[%d] escalates policy beyond parent: %v", i, err),
				"A sub-delegation cannot grant more permissions than its parent.")
		}
		// D2 (temporal): child nbf must be >= parent nbf
		if receipts[i].Nbf < receipts[i-1].Nbf {
			return types.Invalid("TEMPORAL_BOUNDS_VIOLATION",
				fmt.Sprintf("receipt[%d].nbf %d < receipt[%d].nbf %d — child cannot activate before parent.",
					i, receipts[i].Nbf, i-1, receipts[i-1].Nbf),
				"A sub-delegation cannot become active before its parent delegation.")
		}
		// D2 (temporal): child exp must be <= parent exp when both are set
		if receipts[i].Exp != nil && receipts[i-1].Exp != nil {
			if *receipts[i].Exp > *receipts[i-1].Exp {
				return types.Invalid("TEMPORAL_BOUNDS_VIOLATION",
					fmt.Sprintf("receipt[%d].exp %d > receipt[%d].exp %d — child cannot outlive parent.",
						i, *receipts[i].Exp, i-1, *receipts[i-1].Exp),
					"A sub-delegation cannot expire after its parent delegation.")
			}
		}
	}

	// D1: all DRs' policies must be satisfied by the invocation args
	for i, r := range receipts {
		if err := policy.Evaluate(r.Policy, invocation.Args); err != nil {
			return types.Invalid("POLICY_VIOLATION",
				fmt.Sprintf("receipt[%d] policy violated by invocation args: %v", i, err),
				"The invocation arguments exceed the permissions granted in the delegation chain.")
		}
	}

	// ── Block E: Temporal Validity ───────────────────────────────────────────

	now := time.Now().Unix()
	for i, r := range receipts {
		if now < r.Nbf {
			return types.Invalid("NOT_YET_VALID",
				fmt.Sprintf("receipt[%d] is not valid until %d (now: %d).", i, r.Nbf, now),
				"The delegation receipt is not yet active — check the nbf timestamp.")
		}
		// exp is nullable — machine-rooted standing delegations may omit it
		if r.Exp != nil && now > *r.Exp {
			return types.Invalid("EXPIRED",
				fmt.Sprintf("receipt[%d] expired at %d (now: %d).", i, *r.Exp, now),
				"The delegation has expired — the delegator must issue a new one.")
		}
	}

	// ── Block F: Revocation ──────────────────────────────────────────────────

	// Revocation is only checked on delegation receipts.
	// Invocation receipts do not carry a DrsStatusListIndex per DRS spec.

	if deps.Revocation != nil {
		for i, r := range receipts {
			if r.DrsStatusListIndex != nil {
				revoked, err := deps.Revocation.IsRevoked(*r.DrsStatusListIndex)
				if err != nil {
					return types.Invalid("REVOCATION_CHECK_FAILED",
						fmt.Sprintf("receipt[%d] revocation check failed: %v", i, err),
						"The revocation status list could not be fetched. Retry or contact the issuer.")
				}
				if revoked {
					return types.Invalid("REVOKED",
						fmt.Sprintf("receipt[%d] has been revoked (status list index %d).", i, *r.DrsStatusListIndex),
						"The delegation has been revoked — request a new delegation from the issuer.")
				}
			}
		}
	}

	if deps.LocalRevocation != nil {
		for i, r := range receipts {
			if r.DrsStatusListIndex != nil && deps.LocalRevocation.IsRevoked(*r.DrsStatusListIndex) {
				return types.Invalid("REVOKED",
					fmt.Sprintf("receipt[%d] has been locally revoked (status list index %d).", i, *r.DrsStatusListIndex),
					"The delegation has been revoked — request a new delegation from the issuer.")
			}
		}
	}

	// ── Store verified receipts ──────────────────────────────────────────────
	// Persist each verified receipt in the store for audit retention and
	// Tier 3 timestamping. Non-fatal: store failures are logged but do not
	// invalidate the verification. Must run before timestamp verification so
	// that Tier3Store can create .tst tokens that are then immediately verifiable.
	if deps.Store != nil {
		for _, jwt := range bundle.Receipts {
			hash := computeChainHash(jwt)
			if err := deps.Store.Put(hash, jwt); err != nil {
				_ = err
			}
		}
	}

	// ── Timestamp Verification (optional) ───────────────────────────────────
	// Enabled when deps.IncludeTimestamps is true and a store is configured.
	// For each receipt, retrieves the associated RFC 3161 token (stored under
	// hash+".tst" by Tier3Store) and calls VerifyTimestamp.
	// Failures are reported per-receipt in VerificationResult.Timestamps;
	// they do not invalidate the chain (the chain blocks A–F are authoritative).

	var timestamps []types.TimestampResult
	if deps.IncludeTimestamps && deps.Store != nil {
		timestamps = make([]types.TimestampResult, 0, len(bundle.Receipts))
		for i, jwt := range bundle.Receipts {
			hash := computeChainHash(jwt)
			tokenKey := hash + ".tst"
			tokenStr, err := deps.Store.Get(tokenKey)
			if err != nil {
				timestamps = append(timestamps, types.TimestampResult{
					Index: i,
					Valid: false,
					Error: "no timestamp token stored for this receipt",
				})
				continue
			}
			jwtHash := sha256.Sum256([]byte(jwt))
			genTime, err := anchor.VerifyTimestamp([]byte(tokenStr), jwtHash[:])
			if err != nil {
				timestamps = append(timestamps, types.TimestampResult{
					Index: i,
					Valid: false,
					Error: err.Error(),
				})
			} else {
				timestamps = append(timestamps, types.TimestampResult{
					Index: i,
					Valid: true,
					Time:  genTime.UTC().Format(time.RFC3339),
				})
			}
		}
	}

	// ── Success ──────────────────────────────────────────────────────────────

	root := receipts[0]
	var sessionID *string
	if root.DrsConsent != nil {
		id := root.DrsConsent.SessionID
		sessionID = &id
	}

	result := types.Valid(types.VerificationContext{
		RootPrincipal: root.Iss,
		RootType:      root.DrsRootType,
		ConsentRecord: root.DrsConsent,
		Regulatory:    root.DrsRegulatory,
		LeafPolicy:    last.Policy,
		ChainDepth:    len(receipts),
		SessionID:     sessionID,
	})
	result.Timestamps = timestamps
	return result
}

// computeChainHash returns "sha256:{hex}" of the raw JWT bytes.
func computeChainHash(jwt string) string {
	digest := sha256.Sum256([]byte(jwt))
	return fmt.Sprintf("sha256:%x", digest)
}

// decodeJWTPayload decodes the base64url payload of a JWT into dst.
func decodeJWTPayload(jwt string, dst interface{}) error {
	parts := strings.SplitN(jwt, ".", 4)
	if len(parts) != 3 {
		return fmt.Errorf("expected 3 dot-separated parts, got %d", len(parts))
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, dst); err != nil {
		return fmt.Errorf("JSON unmarshal: %w", err)
	}
	return nil
}

// verifyJWTSignature resolves the issuer DID and verifies the JWT's Ed25519 signature.
// Uses Go stdlib crypto/ed25519 — no CGO required.
func verifyJWTSignature(jwt string, issuerDID string, res *resolver.Resolver) error {
	hdr, err := decodeJWTHeader(jwt)
	if err != nil {
		return fmt.Errorf("JWT header decode failed: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
	}

	pubKeyBytes, err := res.Resolve(issuerDID)
	if err != nil {
		return fmt.Errorf("DID resolution failed: %w", err)
	}

	parts := strings.SplitN(jwt, ".", 4)
	if len(parts) != 3 {
		return fmt.Errorf("malformed JWT")
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("signature base64 decode: %w", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes[:])
	if !ed25519.Verify(pubKey, []byte(signingInput), sigBytes) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// classifySignatureError maps a verifyJWTSignature error to a VerificationResult error code.
// DID resolution failures get UNRESOLVABLE_DID; all others get INVALID_SIGNATURE.
func classifySignatureError(err error) (code, suggestion string) {
	msg := err.Error()
	if strings.Contains(msg, "DID resolution failed") ||
		strings.Contains(msg, "unsupported DID method") ||
		strings.Contains(msg, "base58 decoding failed") ||
		strings.Contains(msg, "decoded length") ||
		strings.Contains(msg, "unsupported key type") {
		return "UNRESOLVABLE_DID",
			"Could not resolve public key from issuer DID. Verify the DID format (did:key) or check DNS/TLS (did:web)."
	}
	return "INVALID_SIGNATURE",
		"The receipt has been tampered with or was signed with the wrong key."
}

// cmdIsSubpath returns true if cmd equals rootCmd or is a sub-path of it.
func cmdIsSubpath(rootCmd, cmd string) bool {
	if cmd == rootCmd {
		return true
	}
	if strings.HasPrefix(cmd, rootCmd) {
		rest := cmd[len(rootCmd):]
		return strings.HasPrefix(rest, "/")
	}
	return false
}
