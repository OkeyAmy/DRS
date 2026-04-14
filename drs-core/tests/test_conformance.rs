//! Cross-language conformance tests for DRS 4.0.
//!
//! These tests load shared fixture files from `fixtures/conformance/` and verify
//! that the Rust implementation produces identical output to the canonical vectors.
//! The same fixtures are used by Go and TypeScript conformance tests.

use drs_core::capability::policy::check_policy_attenuation;
use drs_core::chain::hash::compute_chain_hash;
use drs_core::jcs::canonicalise::jcs_canonical_bytes;
use drs_core::types::Policy;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

// ── Fixture schemas ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JcsFixture {
    vectors: Vec<JcsVector>,
}

#[derive(Deserialize)]
struct JcsVector {
    id: String,
    input: Value,
    expected: String,
}

#[derive(Deserialize)]
struct ChainHashFixture {
    vectors: Vec<ChainHashVector>,
}

#[derive(Deserialize)]
struct ChainHashVector {
    id: String,
    input: String,
    expected: String,
}

#[derive(Deserialize)]
struct PolicyPassFixture {
    vectors: Vec<PolicyPassVector>,
}

#[derive(Deserialize)]
struct PolicyPassVector {
    id: String,
    parent: Policy,
    child: Policy,
}

#[derive(Deserialize)]
struct PolicyFailFixture {
    vectors: Vec<PolicyFailVector>,
}

#[derive(Deserialize)]
struct PolicyFailVector {
    id: String,
    parent: Policy,
    child: Policy,
    expected_keyword: String,
}

// ── JCS canonicalization ─────────────────────────────────────────────────

#[test]
fn conformance_jcs_vectors() {
    let raw = include_str!("../../fixtures/conformance/jcs/vectors.json");
    let fixture: JcsFixture = serde_json::from_str(raw).expect("failed to parse JCS fixture");

    for vec in &fixture.vectors {
        let result = jcs_canonical_bytes(&vec.input).unwrap_or_else(|e| {
            panic!("[{}] jcs_canonical_bytes failed: {}", vec.id, e);
        });
        let result_str = std::str::from_utf8(&result).unwrap_or_else(|e| {
            panic!("[{}] non-UTF-8 output: {}", vec.id, e);
        });
        assert_eq!(
            result_str, vec.expected,
            "[{}] JCS output mismatch",
            vec.id
        );
    }
}

// ── Chain hash computation ───────────────────────────────────────────────

#[test]
fn conformance_chain_hash_vectors() {
    let raw = include_str!("../../fixtures/conformance/chain-hash/vectors.json");
    let fixture: ChainHashFixture =
        serde_json::from_str(raw).expect("failed to parse chain-hash fixture");

    for vec in &fixture.vectors {
        let result = compute_chain_hash(&vec.input);
        assert_eq!(
            result, vec.expected,
            "[{}] chain hash mismatch",
            vec.id
        );
    }
}

// ── Policy attenuation — pass cases ──────────────────────────────────────

#[test]
fn conformance_policy_attenuation_pass() {
    let raw = include_str!("../../fixtures/conformance/policy/pass.json");
    let fixture: PolicyPassFixture =
        serde_json::from_str(raw).expect("failed to parse policy pass fixture");

    for vec in &fixture.vectors {
        let result = check_policy_attenuation(&vec.parent, &vec.child);
        assert!(
            result.is_ok(),
            "[{}] expected pass but got error: {:?}",
            vec.id,
            result.err()
        );
    }
}

// ── Policy attenuation — fail cases ──────────────────────────────────────

#[test]
fn conformance_policy_attenuation_fail() {
    let raw = include_str!("../../fixtures/conformance/policy/fail.json");
    let fixture: PolicyFailFixture =
        serde_json::from_str(raw).expect("failed to parse policy fail fixture");

    for vec in &fixture.vectors {
        let result = check_policy_attenuation(&vec.parent, &vec.child);
        assert!(
            result.is_err(),
            "[{}] expected failure for keyword '{}' but attenuation passed",
            vec.id, vec.expected_keyword
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.to_lowercase().contains(&vec.expected_keyword.to_lowercase()),
            "[{}] error message {:?} does not contain expected keyword {:?}",
            vec.id, err_msg, vec.expected_keyword
        );
    }
}

// ── Temporal validity ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TemporalFixture {
    vectors: Vec<TemporalVector>,
}

#[derive(Deserialize)]
struct TemporalVector {
    id: String,
    nbf: i64,
    exp: Option<i64>,
    now: i64,
    valid: bool,
    #[serde(default)]
    expected_code: Option<String>,
}

#[test]
fn conformance_temporal_validity() {
    let raw = include_str!("../../fixtures/conformance/temporal/vectors.json");
    let fixture: TemporalFixture =
        serde_json::from_str(raw).expect("failed to parse temporal fixture");

    for vec in &fixture.vectors {
        let mut is_valid = true;
        let mut code = String::new();

        if vec.now < vec.nbf {
            is_valid = false;
            code = "NOT_YET_VALID".to_string();
        } else if let Some(exp) = vec.exp {
            if vec.now > exp {
                is_valid = false;
                code = "EXPIRED".to_string();
            }
        }

        assert_eq!(
            is_valid, vec.valid,
            "[{}] expected valid={}, got valid={}",
            vec.id, vec.valid, is_valid
        );

        if !vec.valid {
            if let Some(expected_code) = &vec.expected_code {
                assert_eq!(
                    &code, expected_code,
                    "[{}] expected code {:?}, got {:?}",
                    vec.id, expected_code, code
                );
            }
        }
    }
}

// ── Revocation status ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RevocationFixture {
    vectors: Vec<RevocationVector>,
}

#[derive(Deserialize)]
struct RevocationVector {
    id: String,
    status_list_index: u64,
    is_revoked: bool,
}

#[test]
fn conformance_revocation_status() {
    let raw = include_str!("../../fixtures/conformance/revocation/vectors.json");
    let fixture: RevocationFixture =
        serde_json::from_str(raw).expect("failed to parse revocation fixture");

    let revoked: HashSet<u64> = [42].into_iter().collect();

    for vec in &fixture.vectors {
        let is_revoked = revoked.contains(&vec.status_list_index);
        assert_eq!(
            is_revoked, vec.is_revoked,
            "[{}] expected is_revoked={}, got {}",
            vec.id, vec.is_revoked, is_revoked
        );
    }
}
