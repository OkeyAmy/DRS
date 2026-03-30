use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::crypto::ed25519::sign;
use crate::error::DrsError;
use crate::jcs::canonicalise::jcs_canonical_bytes;

// The JWT header for EdDSA is always this fixed value.
// We canonicalise it with JCS for determinism.
const HEADER_JSON: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

/// Builds a signed JWT with an EdDSA (Ed25519) signature per RFC 7515.
///
/// Algorithm:
/// 1. JCS-canonicalise the fixed header `{"alg":"EdDSA","typ":"JWT"}`
/// 2. JCS-canonicalise the payload
/// 3. Signing input = base64url(header) + "." + base64url(payload)
/// 4. Sign the signing input bytes with Ed25519
/// 5. Return base64url(header) + "." + base64url(payload) + "." + base64url(sig)
///
/// The payload is canonicalised so that two logically equivalent JSON objects
/// (same keys/values, different insertion order) produce the same JWT.
pub fn build_jwt(payload: &Value, signing_key: &SigningKey) -> Result<String, DrsError> {
    let header_value: Value =
        serde_json::from_str(HEADER_JSON).map_err(|e| DrsError::SerdeError(e.to_string()))?;

    let header_bytes = jcs_canonical_bytes(&header_value)?;
    let payload_bytes = jcs_canonical_bytes(payload)?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_bytes);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = sign(signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

    Ok(format!("{signing_input}.{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_keypair;
    use crate::jwt::decode::decode_jwt_payload;
    use serde_json::json;

    #[test]
    fn build_jwt_produces_three_part_token() {
        let (signing_key, _) = generate_keypair().unwrap();
        let payload = json!({"iss": "did:key:z123", "exp": 9999999999i64});
        let jwt = build_jwt(&payload, &signing_key).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have exactly three dot-separated parts");
    }

    #[test]
    fn build_jwt_payload_round_trips() {
        let (signing_key, _) = generate_keypair().unwrap();
        let payload = json!({"iss": "did:key:z123", "sub": "did:key:z456", "exp": 9999999999i64});
        let jwt = build_jwt(&payload, &signing_key).unwrap();
        let decoded = decode_jwt_payload(&jwt).unwrap();
        assert_eq!(decoded["iss"], "did:key:z123");
        assert_eq!(decoded["sub"], "did:key:z456");
    }

    #[test]
    fn build_jwt_is_deterministic_for_same_key_and_payload() {
        // Ed25519 signing is deterministic
        let (signing_key, _) = generate_keypair().unwrap();
        let payload = json!({"a": 1});
        let jwt1 = build_jwt(&payload, &signing_key).unwrap();
        let jwt2 = build_jwt(&payload, &signing_key).unwrap();
        assert_eq!(jwt1, jwt2);
    }
}
