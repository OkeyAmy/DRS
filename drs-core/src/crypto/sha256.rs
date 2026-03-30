use sha2::{Digest, Sha256};

/// Computes SHA-256 of `input`. Returns raw 32-byte digest.
pub fn hash_bytes(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);
    digest.into()
}

/// Computes SHA-256 of a JWT string's UTF-8 bytes.
/// Returns a prefixed lowercase hex string: `"sha256:{hex}"`.
///
/// This is the format used in `prev_dr_hash` and `dr_chain` fields.
pub fn hash_jwt_string(jwt: &str) -> String {
    let digest = hash_bytes(jwt.as_bytes());
    let hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_string() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = hash_bytes(b"");
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_of_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let result = hash_bytes(b"abc");
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn hash_jwt_string_format() {
        let result = hash_jwt_string("abc");
        assert!(result.starts_with("sha256:"));
        assert_eq!(result.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn hash_jwt_string_deterministic() {
        let jwt = "header.payload.signature";
        assert_eq!(hash_jwt_string(jwt), hash_jwt_string(jwt));
    }
}
