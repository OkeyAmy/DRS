use crate::crypto::sha256::hash_bytes;

/// Computes the chain hash of a JWT string.
///
/// Returns `"sha256:{lowercase_hex}"` — the format used in `prev_dr_hash`
/// and `dr_chain` fields to link delegation receipts into a verifiable chain.
///
/// The hash is computed over the raw JWT bytes (the full `header.payload.signature`
/// string), not over the decoded payload. This means the hash covers the signature
/// and is therefore unforgeable without the signing key.
pub fn compute_chain_hash(jwt: &str) -> String {
    let digest = hash_bytes(jwt.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_chain_hash_has_correct_format() {
        let hash = compute_chain_hash("header.payload.sig");
        assert!(hash.starts_with("sha256:"), "hash must start with 'sha256:'");
        assert_eq!(hash.len(), 7 + 64, "must be sha256: + 64 hex chars");
    }

    #[test]
    fn compute_chain_hash_is_deterministic() {
        let jwt = "a.b.c";
        assert_eq!(compute_chain_hash(jwt), compute_chain_hash(jwt));
    }

    #[test]
    fn different_jwts_produce_different_hashes() {
        assert_ne!(compute_chain_hash("a.b.c"), compute_chain_hash("a.b.d"));
    }
}
