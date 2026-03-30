//! Integration tests for verify_chain.
//!
//! Builds real signed delegation chains and verifies them.
//! Mandatory security properties tested (from CLAUDE.md):
//! - Valid chain succeeds
//! - Signature forgery must fail (INVALID_SIGNATURE)
//! - Capability escalation must fail (POLICY_ESCALATION)
//! - Tampered chain must fail (CHAIN_BREAK)
//! - Expired chain must fail (EXPIRED)

use drs_core::chain::hash::compute_chain_hash;
use drs_core::chain::verify::verify_chain;
use drs_core::crypto::ed25519::generate_keypair;
use drs_core::did::key::encode_did_key;
use drs_core::jwt::decode::decode_jwt_payload;
use drs_core::jwt::encode::build_jwt;
use drs_core::types::ChainBundle;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

// ── Helpers ────────────────────────────────────────────────────────────────

fn future_ts() -> i64 {
    9_999_999_999
}

fn past_ts() -> i64 {
    1_000_000_000 // 2001 — definitely expired
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jti() -> String {
    format!(
        "dr:{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    )
}

fn inv_jti() -> String {
    format!(
        "inv:{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    )
}

/// Builds a signed root delegation receipt JWT.
///
/// `sub` is always the issuer (human). `sub` propagates unchanged through the chain.
fn make_root_dr(
    signing_key: &SigningKey,
    issuer_did: &str,
    audience_did: &str,
    cmd: &str,
    policy: Value,
    nbf: i64,
    exp: i64,
) -> String {
    let payload = json!({
        "iss": issuer_did,
        "sub": issuer_did,      // root: sub == iss (the human/org resource owner)
        "aud": audience_did,
        "drs_v": "4.0",
        "drs_type": "delegation-receipt",
        "cmd": cmd,
        "policy": policy,
        "nbf": nbf,
        "exp": exp,
        "iat": now_ts(),
        "jti": jti(),
        "prev_dr_hash": null,
        "drs_root_type": "human",
        "drs_consent": {
            "method": "explicit-ui-click",
            "timestamp": "2026-01-01T00:00:00Z",
            "session_id": "sess-001",
            // policy_hash is SHA-256 of the human-readable text shown to the user
            "policy_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "locale": "en-GB"
        }
    });
    build_jwt(&payload, signing_key).unwrap()
}

/// Builds a signed sub-delegation receipt JWT.
///
/// `sub` is taken from the parent DR and propagated unchanged — it always points
/// to the original resource owner (the human), never to the sub-delegating agent.
fn make_sub_dr(
    signing_key: &SigningKey,
    issuer_did: &str,
    audience_did: &str,
    cmd: &str,
    policy: Value,
    nbf: i64,
    exp: i64,
    parent_jwt: &str,
) -> String {
    // sub propagates from parent — spec §5.1: "sub is the resource owner,
    // propagated unchanged through every hop"
    let parent_payload = decode_jwt_payload(parent_jwt).unwrap();
    let sub = parent_payload["sub"].as_str().unwrap_or("").to_string();

    let payload = json!({
        "iss": issuer_did,
        "sub": sub,
        "aud": audience_did,
        "drs_v": "4.0",
        "drs_type": "delegation-receipt",
        "cmd": cmd,
        "policy": policy,
        "nbf": nbf,
        "exp": exp,
        "iat": now_ts(),
        "jti": jti(),
        "prev_dr_hash": compute_chain_hash(parent_jwt)
    });
    build_jwt(&payload, signing_key).unwrap()
}

/// Builds a signed invocation receipt JWT.
///
/// `sub` must be the same as DR₀.sub (the resource owner's DID).
/// `dr_chain` is a list of SHA-256 hashes of all DRs in root-first order.
/// `args` must use the canonical field names: `estimated_cost_usd`, `pii_access`,
/// `write_access`, `tool` — NOT `cost`, `pii`, `write`.
fn make_invocation(
    signing_key: &SigningKey,
    issuer_did: &str,
    subject_did: &str, // DR₀.sub — the human's DID
    cmd: &str,
    args: Value,
    dr_chain: Vec<String>,
    tool_server_did: &str,
) -> String {
    let payload = json!({
        "iss": issuer_did,
        "sub": subject_did,   // must equal DR₀.sub — the original resource owner
        "drs_v": "4.0",
        "drs_type": "invocation-receipt",
        "cmd": cmd,
        "args": args,
        "dr_chain": dr_chain,
        "tool_server": tool_server_did,
        "iat": now_ts(),
        "jti": inv_jti()
    });
    build_jwt(&payload, signing_key).unwrap()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn valid_single_receipt_chain_passes() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    let policy = json!({"max_cost_usd": 5.0, "allowed_tools": ["web_search"]});
    let dr = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", policy, now_ts() - 10, future_ts());

    let chain = vec![compute_chain_hash(&dr)];
    let inv = make_invocation(
        &agent_sk,
        &agent_did,
        &root_did, // sub = root human DID
        "/mcp/tools/call",
        json!({"tool": "web_search", "estimated_cost_usd": 0.02, "pii_access": false}),
        chain,
        &ts_did,
    );

    let bundle = ChainBundle {
        bundle_version: "4.0".into(),
        receipts: vec![dr],
        invocation: inv,
    };

    let result = verify_chain(&bundle);
    assert!(result.valid, "expected valid, got error: {:?}", result.error);
    let ctx = result.context.unwrap();
    assert_eq!(ctx.chain_depth, 1);
    assert_eq!(ctx.root_principal, root_did);
}

#[test]
fn valid_two_receipt_chain_passes() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (tool_sk, tool_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let tool_did = encode_did_key(&tool_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    let root_policy = json!({"max_cost_usd": 10.0, "allowed_tools": ["web_search"]});
    let sub_policy = json!({"max_cost_usd": 2.0, "allowed_tools": ["web_search"]}); // narrower

    let dr1 = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", root_policy, now_ts() - 10, future_ts());
    let dr2 = make_sub_dr(&agent_sk, &agent_did, &tool_did, "/mcp/tools/call", sub_policy, now_ts() - 10, future_ts(), &dr1);

    let chain = vec![compute_chain_hash(&dr1), compute_chain_hash(&dr2)];
    let inv = make_invocation(
        &tool_sk,
        &tool_did,
        &root_did, // sub = root human DID — propagated from DR₀.sub
        "/mcp/tools/call",
        json!({"tool": "web_search", "estimated_cost_usd": 1.50, "pii_access": false}),
        chain,
        &ts_did,
    );

    let bundle = ChainBundle {
        bundle_version: "4.0".into(),
        receipts: vec![dr1, dr2],
        invocation: inv,
    };

    let result = verify_chain(&bundle);
    assert!(result.valid, "expected valid, got error: {:?}", result.error);
    assert_eq!(result.context.unwrap().chain_depth, 2);
}

#[test]
fn empty_receipts_returns_empty_chain_error() {
    let bundle = ChainBundle {
        bundle_version: "4.0".into(),
        receipts: vec![],
        invocation: "x.y.z".into(),
    };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "EMPTY_CHAIN");
}

#[test]
fn missing_invocation_returns_error() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (_, agent_vk) = generate_keypair().unwrap();
    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let dr = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", json!({}), now_ts() - 10, future_ts());

    let bundle = ChainBundle {
        bundle_version: "4.0".into(),
        receipts: vec![dr],
        invocation: "".into(),
    };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "MISSING_INVOCATION");
}

#[test]
fn wrong_drs_version_returns_error() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();
    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    // Build DR with wrong drs_v
    let payload = json!({
        "iss": &root_did, "sub": &root_did, "aud": &agent_did,
        "drs_v": "3.0",   // wrong version
        "drs_type": "delegation-receipt",
        "cmd": "/mcp/tools/call",
        "policy": {},
        "nbf": now_ts() - 10, "exp": future_ts(), "iat": now_ts(),
        "jti": jti(), "prev_dr_hash": null,
        "drs_root_type": "human",
        "drs_consent": { "method": "click", "timestamp": "2026-01-01T00:00:00Z",
                         "session_id": "s1", "policy_hash": "sha256:00", "locale": "en" }
    });
    let dr = build_jwt(&payload, &root_sk).unwrap();
    let chain = vec![compute_chain_hash(&dr)];
    let inv = make_invocation(&agent_sk, &agent_did, &root_did, "/mcp/tools/call", json!({}), chain, &ts_did);

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "VERSION_MISMATCH");
}

#[test]
fn missing_consent_on_human_root_returns_error() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();
    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    // Human root without drs_consent
    let payload = json!({
        "iss": &root_did, "sub": &root_did, "aud": &agent_did,
        "drs_v": "4.0", "drs_type": "delegation-receipt",
        "cmd": "/mcp/tools/call", "policy": {},
        "nbf": now_ts() - 10, "exp": future_ts(), "iat": now_ts(),
        "jti": jti(), "prev_dr_hash": null,
        "drs_root_type": "human"
        // drs_consent intentionally absent
    });
    let dr = build_jwt(&payload, &root_sk).unwrap();
    let chain = vec![compute_chain_hash(&dr)];
    let inv = make_invocation(&agent_sk, &agent_did, &root_did, "/mcp/tools/call", json!({}), chain, &ts_did);

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "MISSING_CONSENT");
}

#[test]
fn chain_break_returns_error() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (tool_sk, tool_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let tool_did = encode_did_key(&tool_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    let dr1 = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", json!({}), now_ts() - 10, future_ts());

    // dr2 references the WRONG prev_dr_hash
    let wrong_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let payload = json!({
        "iss": &agent_did, "sub": &root_did, "aud": &tool_did,
        "drs_v": "4.0", "drs_type": "delegation-receipt",
        "cmd": "/mcp/tools/call", "policy": {},
        "nbf": now_ts() - 10, "exp": future_ts(), "iat": now_ts(),
        "jti": jti(),
        "prev_dr_hash": wrong_hash   // tampered — does not match dr1
    });
    let dr2 = build_jwt(&payload, &agent_sk).unwrap();

    let chain = vec![compute_chain_hash(&dr1), compute_chain_hash(&dr2)];
    let inv = make_invocation(&tool_sk, &tool_did, &root_did, "/mcp/tools/call", json!({}), chain, &ts_did);

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr1, dr2], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "CHAIN_BREAK");
}

#[test]
fn expired_receipt_returns_error() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    // exp is in the past
    let dr = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", json!({}), past_ts(), past_ts() + 1);
    let chain = vec![compute_chain_hash(&dr)];
    let inv = make_invocation(&agent_sk, &agent_did, &root_did, "/mcp/tools/call", json!({}), chain, &ts_did);

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "EXPIRED");
}

#[test]
fn forged_signature_is_rejected() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    let dr = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", json!({}), now_ts() - 10, future_ts());

    // Flip one character in the signature (last component)
    let parts: Vec<&str> = dr.splitn(3, '.').collect();
    let mut bad_sig = parts[2].to_string();
    let ch = bad_sig.chars().next().unwrap();
    bad_sig = bad_sig.replacen(ch, if ch == 'A' { "B" } else { "A" }, 1);
    let tampered_dr = format!("{}.{}.{}", parts[0], parts[1], bad_sig);

    let chain = vec![compute_chain_hash(&tampered_dr)];
    let inv = make_invocation(&agent_sk, &agent_did, &root_did, "/mcp/tools/call", json!({}), chain, &ts_did);

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![tampered_dr], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "INVALID_SIGNATURE");
}

#[test]
fn policy_escalation_is_rejected() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (tool_sk, tool_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let tool_did = encode_did_key(&tool_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    let root_policy = json!({"max_cost_usd": 5.0});
    let child_policy = json!({"max_cost_usd": 100.0}); // escalation: raises cost limit

    let dr1 = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", root_policy, now_ts() - 10, future_ts());
    let dr2 = make_sub_dr(&agent_sk, &agent_did, &tool_did, "/mcp/tools/call", child_policy, now_ts() - 10, future_ts(), &dr1);

    let chain = vec![compute_chain_hash(&dr1), compute_chain_hash(&dr2)];
    let inv = make_invocation(&tool_sk, &tool_did, &root_did, "/mcp/tools/call", json!({"estimated_cost_usd": 50.0}), chain, &ts_did);

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr1, dr2], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "POLICY_ESCALATION");
}

#[test]
fn policy_violation_at_invocation_is_rejected() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    let policy = json!({"max_cost_usd": 1.0});
    let dr = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", policy, now_ts() - 10, future_ts());
    let chain = vec![compute_chain_hash(&dr)];

    // Invocation exceeds the cost limit — uses correct field name "estimated_cost_usd"
    let inv = make_invocation(
        &agent_sk, &agent_did, &root_did, "/mcp/tools/call",
        json!({"estimated_cost_usd": 99.0}), // exceeds max_cost_usd: 1.0
        chain,
        &ts_did,
    );

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(!result.valid);
    assert_eq!(result.error.unwrap().code, "POLICY_VIOLATION");
}

#[test]
fn sub_path_cmd_is_accepted() {
    let (root_sk, root_vk) = generate_keypair().unwrap();
    let (agent_sk, agent_vk) = generate_keypair().unwrap();
    let (_, ts_vk) = generate_keypair().unwrap();

    let root_did = encode_did_key(&root_vk.to_bytes());
    let agent_did = encode_did_key(&agent_vk.to_bytes());
    let ts_did = encode_did_key(&ts_vk.to_bytes());

    // Root delegates "/mcp/tools/call", invocation uses sub-path "/mcp/tools/call/web_search"
    let dr = make_root_dr(&root_sk, &root_did, &agent_did, "/mcp/tools/call", json!({}), now_ts() - 10, future_ts());
    let chain = vec![compute_chain_hash(&dr)];
    let inv = make_invocation(
        &agent_sk, &agent_did, &root_did,
        "/mcp/tools/call/web_search", // sub-path of delegated cmd
        json!({}),
        chain,
        &ts_did,
    );

    let bundle = ChainBundle { bundle_version: "4.0".into(), receipts: vec![dr], invocation: inv };
    let result = verify_chain(&bundle);
    assert!(result.valid, "sub-path cmd should be valid, got: {:?}", result.error);
}
