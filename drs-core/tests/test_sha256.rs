use drs_core::crypto::sha256::{hash_bytes, hash_jwt_string};

/// Integration tests for SHA-256 hashing functions.
/// Exercises the public API with known test vectors.

#[test]
fn sha256_empty_string_test_vector() {
    // NIST test vector: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let digest = hash_bytes(b"");
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[test]
fn sha256_abc_test_vector() {
    // NIST test vector: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    let digest = hash_bytes(b"abc");
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn hash_jwt_string_has_sha256_prefix() {
    let result = hash_jwt_string("some.jwt.token");
    assert!(result.starts_with("sha256:"), "hash must start with 'sha256:' prefix");
}

#[test]
fn hash_jwt_string_has_correct_length() {
    // "sha256:" (7) + 64 hex chars = 71
    let result = hash_jwt_string("any.jwt.value");
    assert_eq!(result.len(), 71);
}

#[test]
fn hash_jwt_string_is_deterministic() {
    let jwt = "header.payload.sig";
    assert_eq!(hash_jwt_string(jwt), hash_jwt_string(jwt));
}

#[test]
fn different_inputs_produce_different_hashes() {
    let h1 = hash_jwt_string("token.a.1");
    let h2 = hash_jwt_string("token.a.2");
    assert_ne!(h1, h2);
}
