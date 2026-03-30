use drs_core::build_jwt;
use drs_core::crypto::ed25519::{generate_keypair, verify_strict};
use drs_core::jwt::decode::{decode_jwt_payload, extract_signature, extract_signing_input};
use serde_json::json;

/// Integration tests for JWT build/decode/verify round-trips.

#[test]
fn jwt_has_three_parts() {
    let (sk, _) = generate_keypair().unwrap();
    let jwt = build_jwt(&json!({"iss": "did:key:z123"}), &sk).unwrap();
    assert_eq!(jwt.split('.').count(), 3);
}

#[test]
fn jwt_payload_round_trips() {
    let (sk, _) = generate_keypair().unwrap();
    let payload = json!({
        "iss": "did:key:zAlice",
        "aud": "did:key:zBob",
        "exp": 9_999_999_999i64
    });
    let jwt = build_jwt(&payload, &sk).unwrap();
    let decoded = decode_jwt_payload(&jwt).unwrap();
    assert_eq!(decoded["iss"], "did:key:zAlice");
    assert_eq!(decoded["aud"], "did:key:zBob");
    assert_eq!(decoded["exp"], 9_999_999_999i64);
}

#[test]
fn jwt_signature_verifies_against_signing_input() {
    let (sk, vk) = generate_keypair().unwrap();
    let jwt = build_jwt(&json!({"claim": "value"}), &sk).unwrap();
    let input = extract_signing_input(&jwt).unwrap();
    let sig = extract_signature(&jwt).unwrap();
    assert!(verify_strict(&vk, &input, &sig).is_ok());
}

#[test]
fn jwt_tampering_breaks_signature() {
    let (sk, vk) = generate_keypair().unwrap();
    let jwt = build_jwt(&json!({"claim": "original"}), &sk).unwrap();
    // Replace the payload with a different value
    let parts: Vec<&str> = jwt.split('.').collect();
    let (sk2, _) = generate_keypair().unwrap();
    let tampered_jwt = build_jwt(&json!({"claim": "tampered"}), &sk2).unwrap();
    let tampered_parts: Vec<&str> = tampered_jwt.split('.').collect();
    // Use header+tampered_payload from different JWT, original sig
    let frankenjwt = format!("{}.{}.{}", parts[0], tampered_parts[1], parts[2]);
    let input = extract_signing_input(&frankenjwt).unwrap();
    let sig = extract_signature(&frankenjwt).unwrap();
    assert!(verify_strict(&vk, &input, &sig).is_err());
}

#[test]
fn jwt_is_deterministic_for_same_key_and_payload() {
    let (sk, _) = generate_keypair().unwrap();
    let payload = json!({"iss": "did:key:z1", "nonce": 42});
    let jwt1 = build_jwt(&payload, &sk).unwrap();
    let jwt2 = build_jwt(&payload, &sk).unwrap();
    assert_eq!(jwt1, jwt2);
}

#[test]
fn key_order_in_payload_does_not_affect_jwt() {
    // JCS ensures canonical ordering: both orderings must produce the same JWT
    let (sk, _) = generate_keypair().unwrap();
    let payload_ab = json!({"a": 1, "b": 2});
    let payload_ba = json!({"b": 2, "a": 1});
    let jwt_ab = build_jwt(&payload_ab, &sk).unwrap();
    let jwt_ba = build_jwt(&payload_ba, &sk).unwrap();
    assert_eq!(jwt_ab, jwt_ba);
}
