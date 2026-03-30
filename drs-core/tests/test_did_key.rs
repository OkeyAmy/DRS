use drs_core::did::key::{encode_did_key, resolve_did_key};
use drs_core::DrsError;

/// Integration tests for did:key encoding and resolution.

#[test]
fn round_trip_for_all_zero_key() {
    let key = [0u8; 32];
    let did = encode_did_key(&key);
    let resolved = resolve_did_key(&did).unwrap();
    assert_eq!(resolved, key);
}

#[test]
fn round_trip_for_all_ones_key() {
    let key = [0xffu8; 32];
    let did = encode_did_key(&key);
    let resolved = resolve_did_key(&did).unwrap();
    assert_eq!(resolved, key);
}

#[test]
fn did_key_starts_with_correct_prefix() {
    let key = [42u8; 32];
    let did = encode_did_key(&key);
    assert!(did.starts_with("did:key:z"), "DID must start with 'did:key:z'");
}

#[test]
fn unsupported_did_method_returns_error() {
    let err = resolve_did_key("did:web:example.com").unwrap_err();
    assert!(matches!(err, DrsError::UnsupportedDidMethod(_)));
}

#[test]
fn did_key_with_wrong_multicodec_is_rejected() {
    // Use 0x12, 0x00 (sha2-256 multicodec) prefix instead of ed25519
    let mut bytes = vec![0x12u8, 0x00u8];
    bytes.extend_from_slice(&[0u8; 32]);
    let encoded = bs58::encode(&bytes).into_string();
    let did = format!("did:key:z{encoded}");
    assert!(matches!(resolve_did_key(&did).unwrap_err(), DrsError::DidUnsupportedKeyType));
}

#[test]
fn truncated_did_key_returns_length_error() {
    // Only 5 bytes total — far too short
    let short = vec![0xedu8, 0x01u8, 0x00u8, 0x01u8, 0x02u8];
    let encoded = bs58::encode(&short).into_string();
    let did = format!("did:key:z{encoded}");
    assert!(matches!(resolve_did_key(&did).unwrap_err(), DrsError::DidInvalidLength(_)));
}
