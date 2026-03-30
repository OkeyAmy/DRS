use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;

use crate::error::DrsError;

/// Splits a JWT into its three components. Returns an error if the format is wrong.
fn split_jwt(jwt: &str) -> Result<(&str, &str, &str), DrsError> {
    let parts: Vec<&str> = jwt.splitn(4, '.').collect();
    if parts.len() != 3 {
        return Err(DrsError::JwtMalformed(format!(
            "expected 3 dot-separated parts, got {}",
            parts.len()
        )));
    }
    Ok((parts[0], parts[1], parts[2]))
}

/// Decodes the payload component of a JWT and parses it as JSON.
///
/// Does NOT verify the signature. Signature verification is the caller's responsibility
/// (see `crypto::ed25519::verify_strict` + `extract_signing_input` + `extract_signature`).
pub fn decode_jwt_payload(jwt: &str) -> Result<Value, DrsError> {
    let (_, payload_b64, _) = split_jwt(jwt)?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| DrsError::Base64Error(e.to_string()))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|e| DrsError::JwtMalformed(format!("payload JSON invalid: {e}")))
}

/// Returns the signing input of a JWT as UTF-8 bytes.
///
/// The signing input is `header_b64 + "." + payload_b64` — the exact bytes
/// that were signed when the JWT was created.
pub fn extract_signing_input(jwt: &str) -> Result<Vec<u8>, DrsError> {
    let (header_b64, payload_b64, _) = split_jwt(jwt)?;
    Ok(format!("{header_b64}.{payload_b64}").into_bytes())
}

/// Decodes the signature component of a JWT into a fixed 64-byte array.
pub fn extract_signature(jwt: &str) -> Result<[u8; 64], DrsError> {
    let (_, _, sig_b64) = split_jwt(jwt)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| DrsError::Base64Error(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(DrsError::JwtMalformed(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_keypair;
    use crate::jwt::encode::build_jwt;
    use serde_json::json;

    #[test]
    fn decode_payload_recovers_fields() {
        let (sk, _) = generate_keypair().unwrap();
        let payload = json!({"iss": "alice", "exp": 9999999999i64});
        let jwt = build_jwt(&payload, &sk).unwrap();
        let decoded = decode_jwt_payload(&jwt).unwrap();
        assert_eq!(decoded["iss"], "alice");
    }

    #[test]
    fn extract_signing_input_has_two_parts() {
        let (sk, _) = generate_keypair().unwrap();
        let jwt = build_jwt(&json!({"x": 1}), &sk).unwrap();
        let input = extract_signing_input(&jwt).unwrap();
        let s = std::str::from_utf8(&input).unwrap();
        assert_eq!(s.split('.').count(), 2);
    }

    #[test]
    fn extract_signature_returns_64_bytes() {
        let (sk, _) = generate_keypair().unwrap();
        let jwt = build_jwt(&json!({"x": 1}), &sk).unwrap();
        let sig = extract_signature(&jwt).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn malformed_jwt_returns_error() {
        assert!(decode_jwt_payload("notajwt").is_err());
        assert!(decode_jwt_payload("only.two").is_err());
    }
}
