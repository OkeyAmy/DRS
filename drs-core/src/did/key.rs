use subtle::ConstantTimeEq;

use crate::error::DrsError;

const DID_KEY_PREFIX: &str = "did:key:z";

// Ed25519 multicodec prefix bytes: 0xed 0x01
const MULTICODEC_ED25519_HI: u8 = 0xed;
const MULTICODEC_ED25519_LO: u8 = 0x01;

/// Resolves a `did:key` DID to its raw Ed25519 public key bytes.
///
/// Format: `did:key:z<base58btc-encoded-multicodec-key>`
///
/// The decoded bytes are `[0xed, 0x01, <32 bytes of public key>]`.
/// The multicodec prefix check is performed in constant time using the `subtle` crate
/// to prevent timing side-channels.
pub fn resolve_did_key(did: &str) -> Result<[u8; 32], DrsError> {
    if !did.starts_with(DID_KEY_PREFIX) {
        return Err(DrsError::UnsupportedDidMethod(
            did.split(':').nth(1).unwrap_or("unknown").to_string(),
        ));
    }

    let encoded = &did[DID_KEY_PREFIX.len()..];
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| DrsError::DidDecodingFailed)?;

    if decoded.len() != 34 {
        return Err(DrsError::DidInvalidLength(decoded.len()));
    }

    // Constant-time check of multicodec prefix to prevent timing side-channels.
    let hi_ok = decoded[0].ct_eq(&MULTICODEC_ED25519_HI);
    let lo_ok = decoded[1].ct_eq(&MULTICODEC_ED25519_LO);
    let valid_prefix: bool = (hi_ok & lo_ok).into();

    if !valid_prefix {
        return Err(DrsError::DidUnsupportedKeyType);
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decoded[2..]);
    Ok(key_bytes)
}

/// Encodes a raw Ed25519 public key as a `did:key` DID string.
///
/// Inverse of `resolve_did_key`. Used in tests and key generation utilities.
pub fn encode_did_key(public_key_bytes: &[u8; 32]) -> String {
    let mut multicodec = vec![MULTICODEC_ED25519_HI, MULTICODEC_ED25519_LO];
    multicodec.extend_from_slice(public_key_bytes);
    let encoded = bs58::encode(&multicodec).into_string();
    format!("{DID_KEY_PREFIX}{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key_bytes() -> [u8; 32] {
        // A known 32-byte public key for testing
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    #[test]
    fn round_trip_encode_then_resolve() {
        let key = sample_key_bytes();
        let did = encode_did_key(&key);
        let resolved = resolve_did_key(&did).expect("should resolve");
        assert_eq!(resolved, key);
    }

    #[test]
    fn unsupported_method_returns_error() {
        let err = resolve_did_key("did:web:example.com").unwrap_err();
        assert!(matches!(err, DrsError::UnsupportedDidMethod(_)));
    }

    #[test]
    fn wrong_length_returns_error() {
        // Encode only 10 bytes (too short)
        let short = vec![0xed, 0x01, 0x00, 0x01, 0x02];
        let encoded = bs58::encode(&short).into_string();
        let did = format!("{DID_KEY_PREFIX}{encoded}");
        let err = resolve_did_key(&did).unwrap_err();
        assert!(matches!(err, DrsError::DidInvalidLength(_)));
    }

    #[test]
    fn wrong_multicodec_prefix_returns_error() {
        // Use 0x12, 0x00 (sha2-256 prefix) instead of ed25519
        let mut bytes = vec![0x12u8, 0x00u8];
        bytes.extend_from_slice(&[0u8; 32]);
        let encoded = bs58::encode(&bytes).into_string();
        let did = format!("{DID_KEY_PREFIX}{encoded}");
        let err = resolve_did_key(&did).unwrap_err();
        assert!(matches!(err, DrsError::DidUnsupportedKeyType));
    }

    #[test]
    fn non_did_key_prefix_returns_error() {
        let err = resolve_did_key("not-a-did").unwrap_err();
        assert!(matches!(err, DrsError::UnsupportedDidMethod(_)));
    }
}
