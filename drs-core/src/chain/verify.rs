#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;

use crate::capability::policy::{check_policy_attenuation, evaluate_policy};
use crate::chain::hash::compute_chain_hash;
use crate::crypto::ed25519::verify_strict;
use crate::did::key::resolve_did_key;
use crate::jwt::decode::{decode_jwt_payload, extract_signature, extract_signing_input};
use crate::types::{
    ChainBundle, DelegationReceipt, InvocationReceipt, VerificationContext, VerificationResult,
};

/// Maximum number of delegation receipts permitted in a single chain bundle.
/// Mirrors the Go layer's `maxChainDepth` constant in `drs-verify/pkg/verify/chain.go`.
const MAX_CHAIN_DEPTH: usize = 16;

const EXPECTED_DRS_VERSION: &str = "4.0";
const EXPECTED_DR_TYPE: &str = "delegation-receipt";
const EXPECTED_INV_TYPE: &str = "invocation-receipt";

/// Verifies a DRS chain bundle.
///
/// Implements verification Blocks A–E from §6.2 of the technical audit.
/// Block F (revocation) is handled by the Go middleware before this function
/// is called — Rust core performs no I/O.
///
/// Returns `VerificationResult` always — never panics. All failure paths return
/// `valid: false` with a machine-readable error code and a human-readable suggestion.
pub fn verify_chain(bundle: &ChainBundle) -> VerificationResult {
    // ── Block A: Completeness ──────────────────────────────────────────────────
    // A1: bundle.receipts.length > 0
    if bundle.receipts.is_empty() {
        return VerificationResult::invalid(
            "EMPTY_CHAIN",
            "bundle.receipts is empty — at least one delegation receipt is required.",
            "Ensure the chain bundle includes all delegation receipts from root to leaf.",
        );
    }
    // A1b: depth cap — reject before any crypto work to prevent CPU exhaustion
    // and WASM stack pressure on deep chains submitted via the WASM surface.
    if bundle.receipts.len() > MAX_CHAIN_DEPTH {
        return VerificationResult::invalid(
            "CHAIN_TOO_DEEP",
            format!(
                "bundle has {} receipts; maximum allowed chain depth is {MAX_CHAIN_DEPTH}.",
                bundle.receipts.len()
            ),
            "Reduce the delegation chain depth. Legitimate chains rarely exceed 4 hops.",
        );
    }
    // A2: bundle.invocation exists
    if bundle.invocation.is_empty() {
        return VerificationResult::invalid(
            "MISSING_INVOCATION",
            "bundle.invocation is empty.",
            "Include the signed invocation receipt in the bundle.",
        );
    }

    // ── Decode all receipt payloads ────────────────────────────────────────────
    let mut receipts: Vec<DelegationReceipt> = Vec::with_capacity(bundle.receipts.len());
    for (i, jwt) in bundle.receipts.iter().enumerate() {
        let payload = match decode_jwt_payload(jwt) {
            Ok(p) => p,
            Err(e) => {
                return VerificationResult::invalid(
                    "MALFORMED_RECEIPT",
                    format!("receipt[{i}] JWT decoding failed: {e}"),
                    "Ensure all receipts are valid JWTs.",
                );
            }
        };
        match serde_json::from_value::<DelegationReceipt>(payload) {
            Ok(r) => receipts.push(r),
            Err(e) => {
                return VerificationResult::invalid(
                    "MALFORMED_RECEIPT",
                    format!("receipt[{i}] payload does not match DelegationReceipt schema: {e}"),
                    "Ensure receipts conform to the DRS 4.0 schema.",
                );
            }
        }
    }

    // ── Decode invocation payload ──────────────────────────────────────────────
    let inv_payload = match decode_jwt_payload(&bundle.invocation) {
        Ok(p) => p,
        Err(e) => {
            return VerificationResult::invalid(
                "MALFORMED_INVOCATION",
                format!("invocation JWT decoding failed: {e}"),
                "Ensure the invocation receipt is a valid JWT.",
            );
        }
    };
    let invocation = match serde_json::from_value::<InvocationReceipt>(inv_payload) {
        Ok(r) => r,
        Err(e) => {
            return VerificationResult::invalid(
                "MALFORMED_INVOCATION",
                format!("invocation payload does not match InvocationReceipt schema: {e}"),
                "Ensure the invocation receipt conforms to the DRS 4.0 schema.",
            );
        }
    };

    // ── Block B: Structural Integrity ──────────────────────────────────────────

    // B1: For each DR — confirm drs_type == "delegation-receipt" and drs_v == "4.0"
    for (i, receipt) in receipts.iter().enumerate() {
        if receipt.drs_type != EXPECTED_DR_TYPE {
            return VerificationResult::invalid(
                "WRONG_TYPE",
                format!(
                    "receipt[{i}].drs_type is '{}' but must be '{EXPECTED_DR_TYPE}'.",
                    receipt.drs_type
                ),
                "Only delegation receipts may appear in bundle.receipts.",
            );
        }
        if receipt.drs_v != EXPECTED_DRS_VERSION {
            return VerificationResult::invalid(
                "VERSION_MISMATCH",
                format!(
                    "receipt[{i}].drs_v is '{}' but this verifier requires '{EXPECTED_DRS_VERSION}'.",
                    receipt.drs_v
                ),
                "Ensure all receipts are issued against DRS spec version 4.0.",
            );
        }
    }

    // B1 for invocation
    if invocation.drs_type != EXPECTED_INV_TYPE {
        return VerificationResult::invalid(
            "WRONG_TYPE",
            format!(
                "invocation.drs_type is '{}' but must be '{EXPECTED_INV_TYPE}'.",
                invocation.drs_type
            ),
            "The invocation field must contain an invocation-receipt, not a delegation-receipt.",
        );
    }
    if invocation.drs_v != EXPECTED_DRS_VERSION {
        return VerificationResult::invalid(
            "VERSION_MISMATCH",
            format!(
                "invocation.drs_v is '{}' but this verifier requires '{EXPECTED_DRS_VERSION}'.",
                invocation.drs_v
            ),
            "Ensure the invocation receipt is issued against DRS spec version 4.0.",
        );
    }

    // B1b: JTI prefix validation
    for (i, receipt) in receipts.iter().enumerate() {
        if !receipt.jti.starts_with("dr:") {
            return VerificationResult::invalid(
                "INVALID_JTI",
                format!("receipt[{i}].jti '{}' must start with 'dr:'.", receipt.jti),
                "Delegation receipt JTIs must use the 'dr:' prefix per DRS 4.0 §5.",
            );
        }
    }
    if !invocation.jti.starts_with("inv:") {
        return VerificationResult::invalid(
            "INVALID_JTI",
            format!(
                "invocation.jti '{}' must start with 'inv:'.",
                invocation.jti
            ),
            "Invocation receipt JTIs must use the 'inv:' prefix per DRS 4.0 §5.",
        );
    }

    // B2: Root DR — prev_dr_hash must be null
    if receipts[0].prev_dr_hash.is_some() {
        return VerificationResult::invalid(
            "CHAIN_STRUCTURE",
            "receipt[0] must have no prev_dr_hash (it is the root delegation).",
            "The first receipt in the chain must be the root delegation with no parent.",
        );
    }
    // B2: If drs_root_type == "human", drs_consent must be present AND populated.
    // A structurally-present but all-empty consent record must not satisfy the
    // human-root requirement (otherwise the audit trail records "consent present"
    // with no actual evidence). Full policy_hash↔policy binding is intentionally
    // NOT enforced here: the canonical preimage for policy_hash is not yet defined
    // in the DRS spec, so equality enforcement would reject legitimate chains.
    if receipts[0].drs_root_type.as_deref() == Some("human") {
        match &receipts[0].drs_consent {
            None => {
                return VerificationResult::invalid(
                    "MISSING_CONSENT",
                    "receipt[0].drs_root_type is 'human' but drs_consent is absent.",
                    "Human-rooted delegations must include consent evidence (method, timestamp, session_id, policy_hash, locale).",
                );
            }
            Some(consent) => {
                if let Some(missing) = consent_missing_field(consent) {
                    return VerificationResult::invalid(
                        "INVALID_CONSENT",
                        format!("receipt[0].drs_consent is structurally present but {missing} is empty."),
                        "Human-rooted delegations must carry a fully-populated consent record.",
                    );
                }
            }
        }
    }

    // B3: Each DR at index i ≥ 1 must have prev_dr_hash == SHA-256(receipts[i-1])
    for i in 1..bundle.receipts.len() {
        let expected_hash = compute_chain_hash(&bundle.receipts[i - 1]);
        match &receipts[i].prev_dr_hash {
            None => {
                return VerificationResult::invalid(
                    "CHAIN_BREAK",
                    format!("receipt[{i}] missing prev_dr_hash (expected {expected_hash})."),
                    "Each receipt after the root must reference the hash of the previous receipt.",
                );
            }
            Some(claimed) if claimed != &expected_hash => {
                return VerificationResult::invalid(
                    "CHAIN_BREAK",
                    format!(
                        "receipt[{i}] prev_dr_hash mismatch: claimed '{claimed}', expected '{expected_hash}'."
                    ),
                    "DR at index 0 may have been modified after DR at index 1 was issued, or the receipts are in the wrong order.",
                );
            }
            _ => {}
        }
    }

    // B4: DRᵢ.iss must equal DRᵢ₋₁.aud
    for i in 1..receipts.len() {
        if receipts[i].iss != receipts[i - 1].aud {
            return VerificationResult::invalid(
                "ISSUER_MISMATCH",
                format!(
                    "receipt[{i}].iss '{}' ≠ receipt[{}].aud '{}'.",
                    receipts[i].iss,
                    i - 1,
                    receipts[i - 1].aud
                ),
                "Each delegation must be issued by the audience of the previous delegation.",
            );
        }
    }

    // B5: invocation.iss must equal last receipt's aud
    let last = &receipts[receipts.len() - 1];
    if invocation.iss != last.aud {
        return VerificationResult::invalid(
            "INVOKER_MISMATCH",
            format!(
                "invocation.iss '{}' ≠ last receipt.aud '{}'.",
                invocation.iss, last.aud
            ),
            "The invocation must be issued by the audience of the leaf delegation receipt.",
        );
    }

    // B6: invocation.dr_chain must match [SHA-256(receipt₀), ..., SHA-256(receiptₙ)]
    if invocation.dr_chain.len() != bundle.receipts.len() {
        return VerificationResult::invalid(
            "CHAIN_REFERENCE_MISMATCH",
            format!(
                "invocation.dr_chain has {} entries but bundle has {} receipts.",
                invocation.dr_chain.len(),
                bundle.receipts.len()
            ),
            "invocation.dr_chain must contain exactly one hash per receipt, in root-first order.",
        );
    }
    for (i, jwt) in bundle.receipts.iter().enumerate() {
        let expected = compute_chain_hash(jwt);
        if invocation.dr_chain[i] != expected {
            return VerificationResult::invalid(
                "CHAIN_REFERENCE_MISMATCH",
                format!(
                    "invocation.dr_chain[{i}] '{}' ≠ computed hash '{expected}'.",
                    invocation.dr_chain[i]
                ),
                "The dr_chain references do not match the provided receipts.",
            );
        }
    }

    // ── Block C: Cryptographic Validity ────────────────────────────────────────
    // C1: Verify each DR's Ed25519 signature
    for (i, jwt) in bundle.receipts.iter().enumerate() {
        if let Err(e) = verify_jwt_signature(jwt, &receipts[i].iss) {
            let (code, suggestion) = classify_signature_error(&e);
            return VerificationResult::invalid(
                code,
                format!("receipt[{i}] verification failed: {e}"),
                suggestion,
            );
        }
    }

    // C2: Verify invocation's Ed25519 signature. Classify against the invocation
    // path so a bad invocation signature reports INVALID_INVOCATION_SIGNATURE,
    // distinct from a delegation-receipt signature failure, for audit clarity.
    if let Err(e) = verify_jwt_signature(&bundle.invocation, &invocation.iss) {
        let (code, suggestion) = classify_signature_error_for(&e, true);
        return VerificationResult::invalid(
            code,
            format!("invocation verification failed: {e}"),
            suggestion,
        );
    }

    // ── Block D: Semantic/Policy Validity ──────────────────────────────────────
    // D1–D4 are spec section numbers from §6.2, not execution order.
    // Execution order is D3 → D4 → D2 → D1 (structural checks before semantic).

    // D3: Command narrowing must hold hop-by-hop, not merely against the root.
    // Each receipt's cmd must equal or be a sub-path of its PARENT's cmd, and the
    // invocation cmd must be a sub-path of the LEAF receipt's cmd. Checking only
    // against the root would let a chain that narrows /tools → /tools/read still
    // authorise an invocation of /tools/write (both are sub-paths of /tools).
    // Sub-path: "/mcp/tools/call/web_search" is a sub-path of "/mcp/tools/call".
    let root_cmd = &receipts[0].cmd;
    if root_cmd.is_empty() || !root_cmd.starts_with('/') {
        return VerificationResult::invalid(
            "INVALID_ROOT_CMD",
            format!("root receipt cmd '{root_cmd}' must be a non-empty absolute path beginning with '/'."),
            "The root delegation must declare a concrete command path so sub-path checks are meaningful.",
        );
    }
    for i in 1..receipts.len() {
        if !cmd_is_subpath(&receipts[i - 1].cmd, &receipts[i].cmd) {
            return VerificationResult::invalid(
                "COMMAND_MISMATCH",
                format!(
                    "receipt[{i}].cmd '{}' is not equal to or a sub-path of parent receipt[{}].cmd '{}'.",
                    receipts[i].cmd,
                    i - 1,
                    receipts[i - 1].cmd
                ),
                "Each delegation may only narrow — never widen — the command path of its parent.",
            );
        }
    }
    let leaf_cmd = &receipts[receipts.len() - 1].cmd;
    if !cmd_is_subpath(leaf_cmd, &invocation.cmd) {
        return VerificationResult::invalid(
            "COMMAND_MISMATCH",
            format!(
                "invocation.cmd '{}' is not equal to or a sub-path of leaf cmd '{leaf_cmd}'.",
                invocation.cmd
            ),
            "The invocation command must match or be a sub-path of the leaf delegation's command.",
        );
    }

    // D4: All DRs must have the same sub (the resource owner — the human's DID)
    let root_sub = &receipts[0].sub;
    for i in 1..receipts.len() {
        if &receipts[i].sub != root_sub {
            return VerificationResult::invalid(
                "SUBJECT_MISMATCH",
                format!(
                    "receipt[{i}].sub '{}' ≠ root sub '{root_sub}'.",
                    receipts[i].sub
                ),
                "All delegation receipts must carry the same sub (the original resource owner).",
            );
        }
    }

    // D4b: invocation.sub must equal root sub (binding invocation to chain subject)
    if invocation.sub != *root_sub {
        return VerificationResult::invalid(
            "INVOCATION_SUBJECT_MISMATCH",
            format!(
                "invocation.sub '{}' ≠ chain root sub '{root_sub}'.",
                invocation.sub
            ),
            "The invocation must reference the same subject as the delegation chain.",
        );
    }

    // D2: Policy attenuation — child policy must be a subset of parent policy
    for i in 1..receipts.len() {
        if let Err(e) = check_policy_attenuation(&receipts[i - 1].policy, &receipts[i].policy) {
            return VerificationResult::invalid(
                "POLICY_ESCALATION",
                format!("receipt[{i}] escalates policy beyond parent: {e}"),
                "A sub-delegation cannot grant more permissions than its parent.",
            );
        }
        // D2 (temporal): child nbf must be >= parent nbf
        if receipts[i].nbf < receipts[i - 1].nbf {
            return VerificationResult::invalid(
                "TEMPORAL_BOUNDS_VIOLATION",
                format!(
                    "receipt[{i}].nbf {} < receipt[{}].nbf {} — child cannot activate before parent.",
                    receipts[i].nbf, i - 1, receipts[i - 1].nbf
                ),
                "A sub-delegation cannot become active before its parent delegation.",
            );
        }
        // D2 (temporal): child exp must be <= parent exp. If the parent sets an
        // expiry, the child may not omit it — an absent child exp means unbounded
        // lifetime, which outlives the time-bounded parent (temporal escalation).
        if let Some(parent_exp) = receipts[i - 1].exp {
            match receipts[i].exp {
                None => {
                    return VerificationResult::invalid(
                        "TEMPORAL_BOUNDS_VIOLATION",
                        format!(
                            "receipt[{i}] omits exp but parent receipt[{}] expires at {parent_exp} — child cannot outlive parent.",
                            i - 1
                        ),
                        "A sub-delegation must carry an exp no later than its parent's expiry.",
                    );
                }
                Some(child_exp) if child_exp > parent_exp => {
                    return VerificationResult::invalid(
                        "TEMPORAL_BOUNDS_VIOLATION",
                        format!(
                            "receipt[{i}].exp {child_exp} > receipt[{}].exp {parent_exp} — child cannot outlive parent.",
                            i - 1
                        ),
                        "A sub-delegation cannot expire after its parent delegation.",
                    );
                }
                Some(_) => {}
            }
        }
    }

    // D1: All DRs' policies must be satisfied by the invocation args (conjunctive)
    for (i, receipt) in receipts.iter().enumerate() {
        if let Err(e) = evaluate_policy(&receipt.policy, &invocation.args) {
            return VerificationResult::invalid(
                "POLICY_VIOLATION",
                format!("receipt[{i}] policy violated by invocation args: {e}"),
                "The invocation arguments exceed the permissions granted in the delegation chain.",
            );
        }
    }

    // ── Block E: Temporal Validity ─────────────────────────────────────────────
    let now = match unix_now() {
        Ok(t) => t,
        Err(_) => {
            return VerificationResult::invalid(
                "CLOCK_ERROR",
                "the verifier's system clock is unavailable or out of range; temporal validity cannot be checked.",
                "Ensure the host clock is set correctly (and available on WASM hosts) before verifying.",
            );
        }
    };
    for (i, receipt) in receipts.iter().enumerate() {
        // E1: now >= DR.nbf
        if now < receipt.nbf {
            return VerificationResult::invalid(
                "NOT_YET_VALID",
                format!(
                    "receipt[{i}] is not valid until {} (now: {now}).",
                    receipt.nbf
                ),
                "The delegation receipt is not yet active — check the nbf timestamp.",
            );
        }
        // E1: now <= DR.exp (if exp is not null)
        // exp is null for machine-rooted standing delegations — skip expiry check
        if let Some(exp) = receipt.exp {
            if now > exp {
                return VerificationResult::invalid(
                    "EXPIRED",
                    format!("receipt[{i}] expired at {exp} (now: {now})."),
                    "The delegation has expired — the delegator must issue a new one.",
                );
            }
        }
    }

    // ── Success ────────────────────────────────────────────────────────────────
    let root = &receipts[0];
    let leaf = &receipts[receipts.len() - 1];

    VerificationResult::valid(VerificationContext {
        root_principal: root.iss.clone(),
        root_type: root.drs_root_type.clone(),
        consent_record: root.drs_consent.clone(),
        regulatory: root.drs_regulatory.clone(),
        leaf_policy: leaf.policy.clone(),
        chain_depth: receipts.len(),
        session_id: root.drs_consent.as_ref().map(|c| c.session_id.clone()),
    })
}

/// Resolves the issuer DID from a JWT, then verifies the JWT's Ed25519 signature.
fn verify_jwt_signature(jwt: &str, issuer_did: &str) -> Result<(), crate::error::DrsError> {
    let key_bytes = resolve_did_key(issuer_did)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| crate::error::DrsError::SignatureInvalid)?;
    let signing_input = extract_signing_input(jwt)?;
    let signature = extract_signature(jwt)?;
    verify_strict(&verifying_key, &signing_input, &signature)
}

/// Classifies a signature-path error into an error code and suggestion.
///
/// DID resolution failures get `UNRESOLVABLE_DID`; all other failures
/// (bad signature, malformed JWT) get `INVALID_SIGNATURE`.
fn classify_signature_error(e: &crate::error::DrsError) -> (&'static str, &'static str) {
    classify_signature_error_for(e, false)
}

/// Classifies a signature-path error. When `is_invocation` is true, a generic
/// signature failure maps to `INVALID_INVOCATION_SIGNATURE` so the invocation
/// layer is distinguishable from a delegation-receipt failure in audit logs.
/// Matching on the error variant (not on a previously-returned string) keeps
/// this robust if other code codes are renamed.
fn classify_signature_error_for(
    e: &crate::error::DrsError,
    is_invocation: bool,
) -> (&'static str, &'static str) {
    use crate::error::DrsError;
    match e {
        DrsError::UnsupportedDidMethod(_)
        | DrsError::DidDecodingFailed
        | DrsError::DidInvalidLength(_)
        | DrsError::DidUnsupportedKeyType
        | DrsError::UnresolvableDid(_) => (
            "UNRESOLVABLE_DID",
            "Could not resolve public key from issuer DID. Check DID format (did:key) or verify DNS/TLS (did:web).",
        ),
        _ if is_invocation => (
            "INVALID_INVOCATION_SIGNATURE",
            "The invocation has been tampered with or was signed with the wrong key.",
        ),
        _ => (
            "INVALID_SIGNATURE",
            "The receipt has been tampered with or was signed with the wrong key.",
        ),
    }
}

/// Returns the name of the first required consent field that is empty (after
/// trimming), or `None` if every required field is populated. `locale` is not
/// required. See B2 for why policy_hash is checked for presence but not bound.
fn consent_missing_field(c: &crate::types::ConsentRecord) -> Option<&'static str> {
    if c.method.trim().is_empty() {
        return Some("method");
    }
    if c.timestamp.trim().is_empty() {
        return Some("timestamp");
    }
    if c.session_id.trim().is_empty() {
        return Some("session_id");
    }
    if c.policy_hash.trim().is_empty() {
        return Some("policy_hash");
    }
    None
}

/// Returns true if `cmd` is equal to `root_cmd` or is a sub-path of it.
///
/// Sub-path rule: `"/mcp/tools/call/web_search"` is a sub-path of `"/mcp/tools/call"`.
/// The child cmd must start with the parent cmd and the next character (if any) must be '/'.
fn cmd_is_subpath(root_cmd: &str, cmd: &str) -> bool {
    if cmd == root_cmd {
        return true;
    }
    // Sub-path: cmd starts with root_cmd and the next char is '/'
    if cmd.starts_with(root_cmd) {
        let rest = &cmd[root_cmd.len()..];
        return rest.starts_with('/');
    }
    false
}

/// Returns the current Unix time in seconds, or an error if the clock is
/// unavailable or out of range.
///
/// Fail-closed: callers must treat the error as a verification failure rather
/// than substituting a sentinel. Returning 0 on error (the previous behaviour)
/// made every receipt with a positive `exp` pass the expiry check — a temporal
/// bypass on any clock anomaly. The cast uses `i64::try_from` so a clock past
/// year 2262 fails closed instead of silently wrapping to a negative timestamp.
#[cfg(not(target_arch = "wasm32"))]
fn unix_now() -> Result<i64, crate::error::DrsError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::error::DrsError::ClockError)?
        .as_secs();
    i64::try_from(secs).map_err(|_| crate::error::DrsError::ClockError)
}

/// wasm32 variant: `SystemTime::now()` PANICS on wasm32-unknown-unknown
/// ("time not implemented on this platform"), which trapped `verify_chain`
/// on every bundle reaching Block E — unreachable by the fail-closed
/// `ClockError` path, because the panic fired before `duration_since`.
/// `js_sys::Date::now()` returns milliseconds since the Unix epoch as f64
/// from the host JS environment; non-finite or negative values fail closed.
///
/// Constraint: this path requires a JavaScript host (browser or Node via
/// wasm-bindgen glue). On non-JS wasm runtimes (WASI, wasmtime) the
/// `Date.now` import does not exist and instantiation fails. drs-core's
/// supported wasm target is `wasm32-unknown-unknown` + wasm-bindgen only.
#[cfg(target_arch = "wasm32")]
fn unix_now() -> Result<i64, crate::error::DrsError> {
    let millis = js_sys::Date::now();
    if !millis.is_finite() || millis < 0.0 {
        return Err(crate::error::DrsError::ClockError);
    }
    Ok((millis / 1000.0) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_subpath_exact_match() {
        assert!(cmd_is_subpath("/mcp/tools/call", "/mcp/tools/call"));
    }

    #[test]
    fn cmd_subpath_child_is_narrower() {
        assert!(cmd_is_subpath(
            "/mcp/tools/call",
            "/mcp/tools/call/web_search"
        ));
    }

    #[test]
    fn cmd_subpath_rejects_different_root() {
        assert!(!cmd_is_subpath("/mcp/tools/call", "/mcp/resources/read"));
    }

    #[test]
    fn cmd_subpath_rejects_prefix_without_slash() {
        // "/mcp/tools/caller" must NOT match "/mcp/tools/call"
        assert!(!cmd_is_subpath("/mcp/tools/call", "/mcp/tools/caller"));
    }
}
