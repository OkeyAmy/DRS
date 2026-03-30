//! WASM bindings for drs-core.
//!
//! These are thin wrappers only. No business logic lives here.
//! All logic is in the core modules — this file only translates between
//! WASM string boundaries and the internal types.
//!
//! Build with: `wasm-pack build --target web --features wasm`

use wasm_bindgen::prelude::*;

use crate::chain::hash::compute_chain_hash;
use crate::chain::verify::verify_chain;
use crate::jcs::canonicalise::jcs_canonical_bytes;
use crate::types::ChainBundle;

/// Verifies a DRS chain bundle provided as a JSON string.
///
/// Returns a JSON-serialised `VerificationResult`.
#[wasm_bindgen]
pub fn wasm_verify_chain(bundle_json: &str) -> String {
    let bundle: ChainBundle = match serde_json::from_str(bundle_json) {
        Ok(b) => b,
        Err(e) => {
            return format!(
                r#"{{"valid":false,"error":{{"code":"MALFORMED_BUNDLE","message":"{e}","suggestion":"Provide a valid JSON ChainBundle"}}}}"#
            );
        }
    };
    let result = verify_chain(&bundle);
    serde_json::to_string(&result).unwrap_or_else(|_| {
        r#"{"valid":false,"error":{"code":"SERIALISE_ERROR","message":"failed to serialise result","suggestion":""}}"#.to_string()
    })
}

/// Computes the chain hash of a JWT string.
///
/// Returns `"sha256:{lowercase_hex}"`.
#[wasm_bindgen]
pub fn wasm_compute_chain_hash(jwt: &str) -> String {
    compute_chain_hash(jwt)
}

/// Canonicalises a JSON string per RFC 8785 JCS.
///
/// Returns the canonical UTF-8 bytes, or throws a JavaScript error on invalid JSON.
#[wasm_bindgen]
pub fn wasm_jcs_canonicalise(json: &str) -> Result<Vec<u8>, JsValue> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {e}")))?;
    jcs_canonical_bytes(&value)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}
