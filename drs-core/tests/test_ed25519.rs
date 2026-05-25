use drs_core::crypto::ed25519::{generate_keypair, sign, verify_strict};
use ed25519_dalek::SigningKey;
use serde::Deserialize;

#[derive(Deserialize)]
struct Ed25519StrictFixture {
    vectors: Vec<Ed25519StrictVector>,
}

#[derive(Deserialize)]
struct Ed25519StrictVector {
    id: String,
    seed_hex: String,
    message: String,
    mutation: String,
    valid: bool,
}

fn ed25519_strict_fixture() -> Ed25519StrictFixture {
    serde_json::from_str(include_str!(
        "../../fixtures/conformance/ed25519-strict/vectors.json"
    ))
    .expect("Ed25519 strict fixture parses")
}

fn apply_ed25519_strict_mutation(mut sig: [u8; 64], mutation: &str) -> [u8; 64] {
    match mutation {
        "none" => sig,
        "s_equals_l" => {
            let group_order: [u8; 32] = [
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ];
            sig[32..].copy_from_slice(&group_order);
            sig
        }
        other => panic!("unsupported Ed25519 strict mutation {other}"),
    }
}

/// Integration tests for Ed25519 sign/verify round-trip.
/// Unit tests live in src/crypto/ed25519.rs; these exercise the public API.

#[test]
fn round_trip_sign_and_verify() {
    let (signing_key, verifying_key) = generate_keypair().unwrap();
    let msg = b"DRS delegation receipt payload";
    let sig = sign(&signing_key, msg);
    assert!(verify_strict(&verifying_key, msg, &sig).is_ok());
}

#[test]
fn tampered_payload_is_rejected() {
    let (signing_key, verifying_key) = generate_keypair().unwrap();
    let original = b"original payload";
    let tampered = b"tampered payload";
    let sig = sign(&signing_key, original);
    assert!(verify_strict(&verifying_key, tampered, &sig).is_err());
}

#[test]
fn cross_key_signature_is_rejected() {
    let (key_a, _) = generate_keypair().unwrap();
    let (_, vk_b) = generate_keypair().unwrap();
    let msg = b"signed by key A";
    let sig = sign(&key_a, msg);
    assert!(verify_strict(&vk_b, msg, &sig).is_err());
}

#[test]
fn different_keypairs_produce_different_public_keys() {
    let (_, vk1) = generate_keypair().unwrap();
    let (_, vk2) = generate_keypair().unwrap();
    assert_ne!(vk1.to_bytes(), vk2.to_bytes());
}

#[test]
fn shared_strictness_vectors_match_rust_verify_strict() {
    let fixture = ed25519_strict_fixture();
    for vector in fixture.vectors {
        let seed = hex::decode(&vector.seed_hex).expect("seed hex decodes");
        let seed: [u8; 32] = seed.try_into().expect("seed is 32 bytes");
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let sig = sign(&signing_key, vector.message.as_bytes());
        let sig = apply_ed25519_strict_mutation(sig, &vector.mutation);

        let result = verify_strict(&verifying_key, vector.message.as_bytes(), &sig);
        assert_eq!(
            result.is_ok(),
            vector.valid,
            "vector {} strictness mismatch: {:?}",
            vector.id,
            result.err()
        );
    }
}
