use drs_core::crypto::ed25519::{generate_keypair, sign, verify_strict};

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
