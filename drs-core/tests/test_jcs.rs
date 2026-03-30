use drs_core::jcs::canonicalise::{jcs_canonical_bytes, jcs_canonical_without_sig};
use serde_json::json;

/// Integration tests for JCS (RFC 8785) canonicalisation.
/// Official test vectors from https://www.rfc-editor.org/rfc/rfc8785

#[test]
fn rfc8785_scalar_integer() {
    let bytes = jcs_canonical_bytes(&json!(1)).unwrap();
    assert_eq!(bytes, b"1");
}

#[test]
fn rfc8785_scalar_string() {
    let bytes = jcs_canonical_bytes(&json!("hello")).unwrap();
    assert_eq!(bytes, b"\"hello\"");
}

#[test]
fn rfc8785_null() {
    let bytes = jcs_canonical_bytes(&json!(null)).unwrap();
    assert_eq!(bytes, b"null");
}

#[test]
fn rfc8785_boolean_true() {
    let bytes = jcs_canonical_bytes(&json!(true)).unwrap();
    assert_eq!(bytes, b"true");
}

#[test]
fn rfc8785_boolean_false() {
    let bytes = jcs_canonical_bytes(&json!(false)).unwrap();
    assert_eq!(bytes, b"false");
}

#[test]
fn rfc8785_sorts_keys_alphabetically() {
    // Keys out of alpha order — must be sorted
    let input = json!({"z": 26, "m": 13, "a": 1});
    let bytes = jcs_canonical_bytes(&input).unwrap();
    assert_eq!(bytes, b"{\"a\":1,\"m\":13,\"z\":26}");
}

#[test]
fn rfc8785_sorts_nested_keys() {
    let input = json!({"outer": {"z": 2, "a": 1}, "a": 0});
    let bytes = jcs_canonical_bytes(&input).unwrap();
    assert_eq!(bytes, b"{\"a\":0,\"outer\":{\"a\":1,\"z\":2}}");
}

#[test]
fn rfc8785_array_order_preserved() {
    // Arrays are ordered — elements must NOT be sorted
    let input = json!([3, 1, 4, 1, 5, 9]);
    let bytes = jcs_canonical_bytes(&input).unwrap();
    assert_eq!(bytes, b"[3,1,4,1,5,9]");
}

#[test]
fn rfc8785_empty_object() {
    let bytes = jcs_canonical_bytes(&json!({})).unwrap();
    assert_eq!(bytes, b"{}");
}

#[test]
fn rfc8785_empty_array() {
    let bytes = jcs_canonical_bytes(&json!([])).unwrap();
    assert_eq!(bytes, b"[]");
}

#[test]
fn without_sig_removes_sig_field() {
    let input = json!({"iss": "did:key:z123", "sig": "deadbeef", "aud": "did:key:z456"});
    let bytes = jcs_canonical_without_sig(&input).unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(!s.contains("\"sig\""));
    assert!(s.contains("\"iss\""));
    assert!(s.contains("\"aud\""));
}

#[test]
fn without_sig_on_object_without_sig_field_is_identity() {
    let input = json!({"a": 1, "b": 2});
    let plain = jcs_canonical_bytes(&input).unwrap();
    let stripped = jcs_canonical_without_sig(&input).unwrap();
    assert_eq!(plain, stripped);
}

#[test]
fn without_sig_on_non_object_is_identity() {
    let input = json!([1, 2, 3]);
    let plain = jcs_canonical_bytes(&input).unwrap();
    let stripped = jcs_canonical_without_sig(&input).unwrap();
    assert_eq!(plain, stripped);
}
