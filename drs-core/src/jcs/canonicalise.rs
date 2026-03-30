use serde_json::Value;
use serde_json_canonicalizer::to_vec;

use crate::error::DrsError;

/// Serialises `value` to canonical JSON per RFC 8785 (JSON Canonicalization Scheme).
///
/// Properties guaranteed by this function:
/// - All object keys sorted by Unicode code point, recursively at every nesting level
/// - Numbers in shortest representation (1.0 → 1, 1.5e10 stays as-is)
/// - No whitespace
/// - Strings use standard JSON escaping with \uXXXX for non-ASCII control characters
///
/// This is the correct function to use for CID computation and signature payloads.
/// Never use `serde_json::to_string` or `JSON.stringify` for this purpose — they
/// do not sort nested keys.
pub fn jcs_canonical_bytes(value: &Value) -> Result<Vec<u8>, DrsError> {
    to_vec(value).map_err(|e| DrsError::SerdeError(e.to_string()))
}

/// Removes the `"sig"` key from a JSON object, then returns RFC 8785 canonical bytes.
///
/// Used for CID computation and chain hash: the signed content excludes the signature
/// field itself (you cannot sign a value that includes its own signature).
pub fn jcs_canonical_without_sig(value: &Value) -> Result<Vec<u8>, DrsError> {
    match value {
        Value::Object(map) => {
            let mut stripped = map.clone();
            stripped.remove("sig");
            let v = Value::Object(stripped);
            jcs_canonical_bytes(&v)
        }
        other => jcs_canonical_bytes(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc8785_sorts_top_level_keys() {
        let input = json!({"b": 2, "a": 1});
        let bytes = jcs_canonical_bytes(&input).unwrap();
        assert_eq!(bytes, b"{\"a\":1,\"b\":2}");
    }

    #[test]
    fn rfc8785_sorts_nested_keys() {
        let input = json!({"z": {"b": 2, "a": 1}, "a": 0});
        let bytes = jcs_canonical_bytes(&input).unwrap();
        assert_eq!(bytes, b"{\"a\":0,\"z\":{\"a\":1,\"b\":2}}");
    }

    #[test]
    fn rfc8785_empty_object() {
        let input = json!({});
        let bytes = jcs_canonical_bytes(&input).unwrap();
        assert_eq!(bytes, b"{}");
    }

    #[test]
    fn rfc8785_empty_array() {
        let input = json!([]);
        let bytes = jcs_canonical_bytes(&input).unwrap();
        assert_eq!(bytes, b"[]");
    }

    #[test]
    fn rfc8785_array_preserves_order() {
        // Arrays are ordered — elements must not be sorted
        let input = json!([3, 1, 2]);
        let bytes = jcs_canonical_bytes(&input).unwrap();
        assert_eq!(bytes, b"[3,1,2]");
    }

    #[test]
    fn rfc8785_integer_representation() {
        let input = json!({"n": 1});
        let bytes = jcs_canonical_bytes(&input).unwrap();
        assert_eq!(bytes, b"{\"n\":1}");
    }

    #[test]
    fn canonical_without_sig_strips_sig_field() {
        let input = json!({"iss": "did:key:z123", "sig": "abc", "aud": "did:key:z456"});
        let bytes = jcs_canonical_without_sig(&input).unwrap();
        let result = std::str::from_utf8(&bytes).unwrap();
        assert!(!result.contains("sig"));
        assert!(result.contains("iss"));
        assert!(result.contains("aud"));
    }

    #[test]
    fn canonical_without_sig_no_sig_field_is_identity() {
        let input = json!({"a": 1, "b": 2});
        let with = jcs_canonical_bytes(&input).unwrap();
        let without = jcs_canonical_without_sig(&input).unwrap();
        assert_eq!(with, without);
    }
}
