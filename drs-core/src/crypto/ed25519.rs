use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::error::DrsError;

/// Generates a fresh Ed25519 keypair using the OS CSPRNG.
pub fn generate_keypair() -> Result<(SigningKey, VerifyingKey), DrsError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    Ok((signing_key, verifying_key))
}

/// Signs `message` with `signing_key`. Returns raw 64-byte signature.
///
/// Ed25519 signing is deterministic: same key + same message → identical signature bytes.
/// The signing key is never logged or stored by this function.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    signing_key.sign(message).to_bytes()
}

/// Verifies an Ed25519 signature using `verify_strict`.
///
/// `verify_strict` (vs `verify`) additionally:
/// - Rejects weak/low-order public keys
/// - Uses cofactored equation [8][S]B = [8]R + [8][k]A
/// - Enforces S < L (prevents signature malleability)
///
/// This is the correct function to use per RUSTSEC-2022-0093.
pub fn verify_strict(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), DrsError> {
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| DrsError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_strict_succeeds() {
        let (signing_key, verifying_key) = generate_keypair().unwrap();
        let message = b"test message for DRS";
        let sig = sign(&signing_key, message);
        assert!(verify_strict(&verifying_key, message, &sig).is_ok());
    }

    #[test]
    fn forged_signature_is_rejected() {
        let (signing_key, verifying_key) = generate_keypair().unwrap();
        let message = b"authentic message";
        let mut sig = sign(&signing_key, message);
        // Flip a bit in the signature to forge it
        sig[0] ^= 0x01;
        assert!(verify_strict(&verifying_key, message, &sig).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (signing_key, _) = generate_keypair().unwrap();
        let (_, wrong_key) = generate_keypair().unwrap();
        let message = b"signed with a different key";
        let sig = sign(&signing_key, message);
        assert!(verify_strict(&wrong_key, message, &sig).is_err());
    }

    #[test]
    fn wrong_message_is_rejected() {
        let (signing_key, verifying_key) = generate_keypair().unwrap();
        let sig = sign(&signing_key, b"original");
        assert!(verify_strict(&verifying_key, b"tampered", &sig).is_err());
    }
}
