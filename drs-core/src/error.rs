use thiserror::Error;

#[derive(Debug, Error)]
pub enum DrsError {
    #[error("unsupported DID method: {0}")]
    UnsupportedDidMethod(String),

    #[error("DID decoding failed")]
    DidDecodingFailed,

    #[error("invalid DID key length: expected 34 bytes, got {0}")]
    DidInvalidLength(usize),

    #[error("unsupported key type in DID multicodec prefix")]
    DidUnsupportedKeyType,

    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,

    #[error("base64url decoding failed: {0}")]
    Base64Error(String),

    #[error("JWT malformed: {0}")]
    JwtMalformed(String),

    #[error("JSON serialisation error: {0}")]
    SerdeError(String),

    #[error("chain verification failed: {code} — {message}")]
    ChainInvalid { code: &'static str, message: String },

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("capability escalation at index {index}: {detail}")]
    CapabilityEscalation { index: usize, detail: String },

    #[error("could not resolve public key from DID: {0}")]
    UnresolvableDid(String),
}
