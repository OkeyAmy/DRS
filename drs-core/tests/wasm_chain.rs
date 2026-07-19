//! WASM regression test for the Block E clock panic.
//!
//! `SystemTime::now()` panics on wasm32-unknown-unknown, so `verify_chain`
//! trapped on every bundle that reached Block E. This test builds a real
//! signed single-receipt chain and verifies it end-to-end under wasm.
//!
//! Run: wasm-pack test --node -- --features wasm
//!
//! Uses fixed key seeds and fixed JTIs: no RNG, no SystemTime in the test
//! itself, so the only clock call under test is verify_chain's own.

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::wasm_bindgen_test;

use drs_core::chain::hash::compute_chain_hash;
use drs_core::chain::verify::verify_chain;
use drs_core::did::key::encode_did_key;
use drs_core::jwt::encode::build_jwt;
use drs_core::types::ChainBundle;
use ed25519_dalek::SigningKey;
use serde_json::json;

fn fixed_signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[wasm_bindgen_test]
fn full_chain_verifies_on_wasm() {
    let root_sk = fixed_signing_key(7);
    let agent_sk = fixed_signing_key(8);
    let root_did = encode_did_key(&root_sk.verifying_key().to_bytes());
    let agent_did = encode_did_key(&agent_sk.verifying_key().to_bytes());

    let root_jwt = build_jwt(
        &json!({
            "iss": root_did, "sub": root_did, "aud": agent_did,
            "drs_v": "4.0", "drs_type": "delegation-receipt",
            "cmd": "/mcp/tools/call",
            "policy": {},
            "nbf": 1_000_000_000i64, "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64, "jti": "dr:wasm-test-root",
            "prev_dr_hash": null,
            "drs_root_type": "human",
            "drs_consent": {
                "method": "explicit-ui-click",
                "timestamp": "2026-01-01T00:00:00Z",
                "session_id": "sess-wasm-1",
                "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "locale": "en-GB"
            }
        }),
        &root_sk,
    )
    .expect("root JWT builds");

    let invocation_jwt = build_jwt(
        &json!({
            "iss": agent_did, "sub": root_did,
            "drs_v": "4.0", "drs_type": "invocation-receipt",
            "cmd": "/mcp/tools/call",
            "args": {"tool": "web_search"},
            "dr_chain": [compute_chain_hash(&root_jwt)],
            "tool_server": "did:key:z6MkToolServer",
            "iat": 1_700_000_000i64, "jti": "inv:wasm-test-1"
        }),
        &agent_sk,
    )
    .expect("invocation JWT builds");

    let bundle = ChainBundle {
        bundle_version: "4.0".to_string(),
        invocation: invocation_jwt,
        receipts: vec![root_jwt],
    };

    let result = verify_chain(&bundle);
    assert!(
        result.valid,
        "valid chain must verify on wasm; error: {:?}",
        result.error
    );
}

#[wasm_bindgen_test]
fn tampered_receipt_fails_on_wasm() {
    let root_sk = fixed_signing_key(7);
    let agent_sk = fixed_signing_key(8);
    let root_did = encode_did_key(&root_sk.verifying_key().to_bytes());
    let agent_did = encode_did_key(&agent_sk.verifying_key().to_bytes());

    let root_jwt = build_jwt(
        &json!({
            "iss": root_did, "sub": root_did, "aud": agent_did,
            "drs_v": "4.0", "drs_type": "delegation-receipt",
            "cmd": "/mcp/tools/call",
            "policy": {},
            "nbf": 1_000_000_000i64, "exp": 9_999_999_999i64,
            "iat": 1_700_000_000i64, "jti": "dr:wasm-test-root",
            "prev_dr_hash": null,
            "drs_root_type": "human",
            "drs_consent": {
                "method": "explicit-ui-click",
                "timestamp": "2026-01-01T00:00:00Z",
                "session_id": "sess-wasm-1",
                "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "locale": "en-GB"
            }
        }),
        &root_sk,
    )
    .expect("root JWT builds");

    // Tamper: flip the last signature character.
    let mut tampered = root_jwt.clone();
    let last = if tampered.ends_with('A') { 'B' } else { 'A' };
    tampered.pop();
    tampered.push(last);

    let invocation_jwt = build_jwt(
        &json!({
            "iss": agent_did, "sub": root_did,
            "drs_v": "4.0", "drs_type": "invocation-receipt",
            "cmd": "/mcp/tools/call",
            "args": {"tool": "web_search"},
            "dr_chain": [compute_chain_hash(&tampered)],
            "tool_server": "did:key:z6MkToolServer",
            "iat": 1_700_000_000i64, "jti": "inv:wasm-test-2"
        }),
        &agent_sk,
    )
    .expect("invocation JWT builds");

    let bundle = ChainBundle {
        bundle_version: "4.0".to_string(),
        invocation: invocation_jwt,
        receipts: vec![tampered],
    };

    let result = verify_chain(&bundle);
    assert!(!result.valid, "tampered receipt must fail on wasm");
}
