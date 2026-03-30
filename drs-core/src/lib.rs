pub mod capability;
pub mod chain;
pub mod crypto;
pub mod did;
pub mod error;
pub mod jcs;
pub mod jwt;
pub mod types;

#[cfg(feature = "wasm")]
pub mod wasm;

// Public re-exports for the primary API surface
pub use chain::verify::verify_chain;
pub use error::DrsError;
pub use jwt::encode::build_jwt;
pub use types::{
    ChainBundle, ConsentRecord, DelegationReceipt, InvocationReceipt, Policy, RegulatoryMetadata,
    VerificationContext, VerificationError, VerificationResult,
};
