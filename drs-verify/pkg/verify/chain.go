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
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
	"github.com/drs-protocol/drs-verify/pkg/policy"
	"github.com/drs-protocol/drs-verify/pkg/resolver"
	"github.com/drs-protocol/drs-verify/pkg/revocation"
	"github.com/drs-protocol/drs-verify/pkg/store"
	"github.com/drs-protocol/drs-verify/pkg/types"
)

var errSignatureMalleability = errors.New("signature malleability")

// blockCConcurrency is the maximum number of concurrent DID resolutions that
// Block C will run in parallel within a single Chain call. Eight covers the
// realistic maximum of distinct issuers in a 16-hop chain while keeping
// outbound HTTP concurrency well below any server-side rate limit.
const blockCConcurrency = 8

const (
	expectedDRSVersion = "4.0"
	expectedDRType     = "delegation-receipt"
	expectedInvType    = "invocation-receipt"
	// maxChainDepth is the maximum number of delegation receipts allowed in a
	// single bundle. 16 hops is more than any legitimate delegation chain needs.
	// This bounds CPU work per request independently of rate limiting.
	maxChainDepth = 16
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
	Resolver        *resolver.Resolver
	Revocation      *revocation.StatusCache
	LocalRevocation revocation.LocalStore
	Store           store.Store
	// ServerIdentity is this server's DID or identifier. When set, the verifier
	// enforces that invocation.tool_server matches this value, binding the
	// invocation to the intended destination. Empty disables the check.
	ServerIdentity string
	// IncludeTimestamps enables RFC 3161 timestamp verification after Block F.
	// For each receipt, retrieves the stored .tst token (if any) and verifies it.
	// Timestamp failures are reported in VerificationResult.Timestamps but do not
	// fail the overall chain verification.
	IncludeTimestamps bool
	// TSARootPool is the set of trusted root CA certificates for RFC 3161
	// timestamp token verification. When nil, system roots are used.
	// Set via TSA_ROOT_CERT_PEM env var parsed in main().
	TSARootPool *x509.CertPool
	// MaxInvocationAge bounds how old an invocation's iat may be. Once the nonce
	// store evicts a JTI (after its TTL) the same invocation could otherwise be
	// replayed; rejecting stale invocations closes that window. Set from the
	// nonce TTL in main(). Zero disables the check.
	MaxInvocationAge time.Duration
}

// invocationClockSkew is the tolerance for an invocation iat that is slightly in
// the future relative to this verifier's clock (NTP jitter between issuer and
// verifier). Beyond this, the iat is treated as malformed.
const invocationClockSkew = 5 * time.Minute

// Chain verifies a DRS chain bundle through all six blocks.
// Returns a VerificationResult — never panics.
func Chain(ctx context.Context, bundle types.ChainBundle, deps Deps) types.VerificationResult {
	// ── Block A: Completeness ────────────────────────────────────────────────

	if len(bundle.Receipts) == 0 {
		return types.Invalid("EMPTY_CHAIN",
			"bundle.receipts is empty — at least one delegation receipt is required.",
			"Ensure the chain bundle includes all delegation receipts from root to leaf.")
	}
	if len(bundle.Receipts) > maxChainDepth {
		return types.Invalid("CHAIN_TOO_DEEP",
			fmt.Sprintf("bundle has %d receipts; maximum allowed chain depth is %d.",
				len(bundle.Receipts), maxChainDepth),
			"Reduce the delegation chain depth. Legitimate chains rarely exceed 4 hops.")
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
	if receipts[0].DrsRootType != nil && *receipts[0].DrsRootType == "human" {
		if receipts[0].DrsConsent == nil {
			return types.Invalid("MISSING_CONSENT",
				"receipt[0].drs_root_type is 'human' but drs_consent is absent.",
				"Human-rooted delegations must include consent evidence (method, timestamp, session_id, policy_hash, locale).")
		}
		if msg := validateConsentRecord(receipts[0].DrsConsent); msg != "" {
			return types.Invalid("INVALID_CONSENT",
				fmt.Sprintf("receipt[0].drs_consent is structurally present but %s", msg),
				"Human-rooted delegations must carry a fully-populated consent record.")
		}
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

	// Pre-resolve every unique issuer DID concurrently so that did:web round
	// trips for N distinct issuers happen in parallel (max blockCConcurrency
	// at once) rather than serially. Cached results are then used by the
	// signature verification loop, which does no further network I/O.
	issuerDIDs := make([]string, 0, len(receipts)+1)
	for _, r := range receipts {
		issuerDIDs = append(issuerDIDs, r.Iss)
	}
	issuerDIDs = append(issuerDIDs, invocation.Iss)

	resolvedKeys, resolveErr := resolveIssuersParallel(ctx, issuerDIDs, deps.Resolver)
	if resolveErr != nil {
		code, suggestion := classifySignatureError(resolveErr)
		return types.Invalid(code,
			fmt.Sprintf("DID resolution failed during Block C pre-resolution: %v", resolveErr),
			suggestion)
	}

	for i, jwt := range bundle.Receipts {
		if err := verifyJWTSignatureWithKey(jwt, receipts[i].Iss, resolvedKeys); err != nil {
			code, suggestion := classifySignatureError(err)
			return types.Invalid(code,
				fmt.Sprintf("receipt[%d] signature check failed: %v", i, err),
				suggestion)
		}
	}
	if err := verifyJWTSignatureWithKey(bundle.Invocation, invocation.Iss, resolvedKeys); err != nil {
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

	// D3: command narrowing must hold hop-by-hop, not merely against the root.
	// Each receipt's cmd must equal or be a sub-path of its PARENT's cmd, and the
	// invocation cmd must be a sub-path of the LEAF receipt's cmd. Checking only
	// against the root would let a chain that narrows /tools → /tools/read still
	// authorise an invocation of /tools/write (both are sub-paths of /tools).
	rootCmd := receipts[0].Cmd
	if rootCmd == "" || !strings.HasPrefix(rootCmd, "/") {
		return types.Invalid("INVALID_ROOT_CMD",
			fmt.Sprintf("root receipt cmd %q must be a non-empty absolute path beginning with '/'.", rootCmd),
			"The root delegation must declare a concrete command path so sub-path checks are meaningful.")
	}
	for i := 1; i < len(receipts); i++ {
		if !cmdIsSubpath(receipts[i-1].Cmd, receipts[i].Cmd) {
			return types.Invalid("COMMAND_MISMATCH",
				fmt.Sprintf("receipt[%d].cmd %q is not equal to or a sub-path of parent receipt[%d].cmd %q.",
					i, receipts[i].Cmd, i-1, receipts[i-1].Cmd),
				"Each delegation may only narrow — never widen — the command path of its parent.")
		}
	}
	leafCmd := receipts[len(receipts)-1].Cmd
	if !cmdIsSubpath(leafCmd, invocation.Cmd) {
		return types.Invalid("COMMAND_MISMATCH",
			fmt.Sprintf("invocation.cmd %q is not equal to or a sub-path of leaf cmd %q.", invocation.Cmd, leafCmd),
			"The invocation command must match or be a sub-path of the leaf delegation's command.")
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

	// D4c: bind the invocation to this server. When ServerIdentity is configured
	// it must match invocation.tool_server. When it is NOT configured, an
	// invocation that names a specific tool_server is rejected fail-closed —
	// otherwise a bundle minted for server A would verify on any server B that
	// simply left SERVER_IDENTITY unset (cross-server replay / confused deputy).
	if deps.ServerIdentity != "" {
		if invocation.ToolServer != deps.ServerIdentity {
			return types.Invalid("TOOL_SERVER_MISMATCH",
				fmt.Sprintf("invocation.tool_server %q ≠ expected server identity %q.", invocation.ToolServer, deps.ServerIdentity),
				"The invocation targets a different tool server than this verifier.")
		}
	} else if invocation.ToolServer != "" {
		return types.Invalid("TOOL_SERVER_MISMATCH",
			fmt.Sprintf("invocation.tool_server %q is set but this verifier has no SERVER_IDENTITY configured.", invocation.ToolServer),
			"Set SERVER_IDENTITY on the verifier so tool_server binding can be enforced.")
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
		// D2 (temporal): child exp must be <= parent exp. If the parent sets an
		// expiry, the child may not omit it — an absent child exp means unbounded
		// lifetime, which outlives the time-bounded parent (temporal escalation).
		if receipts[i-1].Exp != nil {
			if receipts[i].Exp == nil {
				return types.Invalid("TEMPORAL_BOUNDS_VIOLATION",
					fmt.Sprintf("receipt[%d] omits exp but parent receipt[%d] expires at %d — child cannot outlive parent.",
						i, i-1, *receipts[i-1].Exp),
					"A sub-delegation must carry an exp no later than its parent's expiry.")
			}
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

	// Invocation freshness: an invocation must be recent. This bounds the replay
	// window to the nonce TTL — after a JTI is evicted from the nonce store, a
	// captured invocation older than MaxInvocationAge is rejected here rather than
	// being re-accepted. A far-future iat (beyond clock skew) is also rejected.
	if invocation.Iat > now+int64(invocationClockSkew.Seconds()) {
		return types.Invalid("INVOCATION_NOT_YET_VALID",
			fmt.Sprintf("invocation.iat %d is in the future (now: %d).", invocation.Iat, now),
			"Check clock synchronisation between the issuer and the verifier.")
	}
	if deps.MaxInvocationAge > 0 {
		if age := now - invocation.Iat; age > int64(deps.MaxInvocationAge.Seconds()) {
			return types.Invalid("INVOCATION_STALE",
				fmt.Sprintf("invocation.iat %d is %ds old; maximum allowed age is %ds.",
					invocation.Iat, age, int64(deps.MaxInvocationAge.Seconds())),
				"Re-issue the invocation; a stale invocation can be a replay after its nonce expired.")
		}
	}

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
				revoked, err := deps.Revocation.IsRevoked(ctx, *r.DrsStatusListIndex)
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
	var storeWarnings []string
	if deps.Store != nil {
		for _, jwt := range bundle.Receipts {
			hash := computeChainHash(jwt)
			if err := deps.Store.Put(hash, jwt); err != nil {
				slog.Warn("store: Put failed", "hash", hash, "error", err)
				storeWarnings = append(storeWarnings,
					fmt.Sprintf("receipt %s could not be persisted: %v", hash, err))
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
			genTime, err := anchor.VerifyTimestampTrusted([]byte(tokenStr), jwtHash[:], deps.TSARootPool)
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
		CorrelationID: root.CorrelationID,
	})
	result.Timestamps = timestamps
	result.StoreWarnings = storeWarnings
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

// resolveIssuersParallel resolves each unique DID in dids using at most
// blockCConcurrency concurrent goroutines. It returns a map from DID to its
// 32-byte Ed25519 public key, or the first resolution error encountered.
//
// Deduplication is performed before dispatch: a chain with repeated issuers
// incurs only one network round trip per unique DID.
func resolveIssuersParallel(
	ctx context.Context,
	dids []string,
	res *resolver.Resolver,
) (map[string][32]byte, error) {
	seen := make(map[string]struct{}, len(dids))
	unique := make([]string, 0, len(dids))
	for _, did := range dids {
		if _, ok := seen[did]; !ok {
			seen[did] = struct{}{}
			unique = append(unique, did)
		}
	}

	type resolveResult struct {
		did string
		key [32]byte
		err error
	}

	// INVARIANT: results must be buffered to len(unique). The workers send
	// exactly one result each and wg.Wait() runs BEFORE the drain loop below —
	// with an unbuffered (or under-sized) channel every send would block and
	// wg.Wait() would deadlock. If you refactor this, drain concurrently or
	// keep the buffer sized to the number of sends.
	results := make(chan resolveResult, len(unique))
	sem := make(chan struct{}, blockCConcurrency)

	var wg sync.WaitGroup
	for _, did := range unique {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			key, err := res.Resolve(ctx, d)
			results <- resolveResult{did: d, key: key, err: err}
		}(did)
	}

	wg.Wait()
	close(results)

	keys := make(map[string][32]byte, len(unique))
	for r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("resolve %s: %w", r.did, r.err)
		}
		keys[r.did] = r.key
	}
	return keys, nil
}

// verifyJWTSignatureWithKey verifies a JWT's Ed25519 signature using a
// pre-resolved public key from resolvedKeys. It performs no network I/O.
func verifyJWTSignatureWithKey(jwt string, issuerDID string, resolvedKeys map[string][32]byte) error {
	hdr, err := decodeJWTHeader(jwt)
	if err != nil {
		return fmt.Errorf("JWT header decode failed: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
	}

	pubKeyBytes, ok := resolvedKeys[issuerDID]
	if !ok {
		return fmt.Errorf("DID resolution failed: no key found for %s", issuerDID)
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
	if err := strictVerifyEd25519(sigBytes); err != nil {
		return fmt.Errorf("Ed25519 strict check failed: %w", err)
	}
	pubKey := ed25519.PublicKey(pubKeyBytes[:])
	if !ed25519.Verify(pubKey, []byte(signingInput), sigBytes) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// verifyJWTSignature resolves the issuer DID and verifies the JWT's Ed25519 signature.
// Uses Go stdlib crypto/ed25519 — no CGO required.
func verifyJWTSignature(ctx context.Context, jwt string, issuerDID string, res *resolver.Resolver) error {
	hdr, err := decodeJWTHeader(jwt)
	if err != nil {
		return fmt.Errorf("JWT header decode failed: %w", err)
	}
	if hdr.Alg != "EdDSA" {
		return fmt.Errorf("unsupported JWT algorithm %q: DRS receipts must use EdDSA", hdr.Alg)
	}

	pubKeyBytes, err := res.Resolve(ctx, issuerDID)
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

	// Strict S-range check: reject non-canonical signatures that Go's stdlib
	// either rejects generically or accepted in older/alternate implementations.
	// Running this before ed25519.Verify lets DRS surface the documented
	// SIGNATURE_MALLEABILITY code instead of collapsing the failure into a
	// generic INVALID_SIGNATURE.
	if err := strictVerifyEd25519(sigBytes); err != nil {
		return fmt.Errorf("Ed25519 strict check failed: %w", err)
	}

	pubKey := ed25519.PublicKey(pubKeyBytes[:])
	if !ed25519.Verify(pubKey, []byte(signingInput), sigBytes) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// edGroupOrder is the Ed25519 group order L in little-endian bytes.
// L = 2^252 + 27742317777372353535851937790883648493
var edGroupOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

// strictVerifyEd25519 checks that the scalar S in an Ed25519 signature is
// canonical (S < L, the group order). Go's stdlib ed25519.Verify has not
// always surfaced this distinction as DRS's documented SIGNATURE_MALLEABILITY
// result. This check closes the cross-implementation gap without external
// dependencies and runs before ed25519.Verify so non-canonical signatures are
// classified precisely.
func strictVerifyEd25519(sig []byte) error {
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: %d", len(sig))
	}
	// S occupies bytes 32–63 (little-endian). Compare from most-significant
	// byte (index 31) downward to determine whether S < L.
	for i := 31; i >= 0; i-- {
		if sig[32+i] > edGroupOrder[i] {
			return fmt.Errorf("non-canonical Ed25519 signature scalar: S >= group order L: %w", errSignatureMalleability)
		}
		if sig[32+i] < edGroupOrder[i] {
			return nil // S < L — canonical
		}
		// bytes equal at this position; continue to less-significant byte
	}
	// S == L exactly — also non-canonical (must be strictly less than L)
	return fmt.Errorf("non-canonical Ed25519 signature scalar: S == group order L: %w", errSignatureMalleability)
}

// classifySignatureError maps a verifyJWTSignature error to a VerificationResult error code.
// DID resolution failures get UNRESOLVABLE_DID; all others get INVALID_SIGNATURE.
func classifySignatureError(err error) (code, suggestion string) {
	msg := err.Error()
	if errors.Is(err, errSignatureMalleability) {
		return "SIGNATURE_MALLEABILITY",
			"The receipt signature is non-canonical. Re-issue the receipt with a canonical Ed25519 signature."
	}
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

// validateConsentRecord returns a non-empty description of the first missing
// required field in a human-consent record, or "" if the record is complete.
//
// This enforces that a structurally-present consent record actually carries
// evidence: an all-empty ConsentRecord must not satisfy the human-root check.
// Full policy_hash↔policy binding is intentionally NOT enforced here: the
// canonical preimage for policy_hash is not yet defined in the DRS spec (the
// SDK accepts it as caller-supplied), so equality enforcement would reject
// legitimate chains. Non-emptiness is the safe interim guarantee.
func validateConsentRecord(c *types.ConsentRecord) string {
	switch {
	case strings.TrimSpace(c.Method) == "":
		return "method is empty"
	case strings.TrimSpace(c.Timestamp) == "":
		return "timestamp is empty"
	case strings.TrimSpace(c.SessionID) == "":
		return "session_id is empty"
	case strings.TrimSpace(c.PolicyHash) == "":
		return "policy_hash is empty"
	}
	return ""
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
