use drs_core::capability::policy::{check_policy_attenuation, evaluate_policy};
use drs_core::Policy;
use serde_json::json;

fn policy(
    max_cost: Option<f64>,
    pii: Option<bool>,
    write: Option<bool>,
    tools: Option<Vec<&str>>,
    max_calls: Option<u64>,
) -> Policy {
    Policy {
        max_cost_usd: max_cost,
        pii_access: pii,
        allowed_tools: tools.map(|v| v.iter().map(|s| s.to_string()).collect()),
        max_calls,
        write_access: write,
        allowed_resources: None,
        allowed_data_classes: None,
    }
}

// ── evaluate_policy ──────────────────────────────────────────────────────────

#[test]
fn cost_within_limit_passes() {
    let p = policy(Some(10.0), None, None, None, None);
    assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": 9.99})).is_ok());
}

#[test]
fn cost_at_exact_limit_passes() {
    let p = policy(Some(10.0), None, None, None, None);
    assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": 10.0})).is_ok());
}

#[test]
fn cost_over_limit_fails() {
    let p = policy(Some(10.0), None, None, None, None);
    assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": 10.01})).is_err());
}

#[test]
fn wrong_cost_field_name_is_ignored() {
    // "cost" is not the spec field name — check must not fire
    let p = policy(Some(1.0), None, None, None, None);
    assert!(evaluate_policy(&p, &json!({"cost": 9999.0})).is_ok());
}

#[test]
fn pii_access_denied_when_policy_says_false() {
    let p = policy(None, Some(false), None, None, None);
    assert!(evaluate_policy(&p, &json!({"pii_access": true})).is_err());
}

#[test]
fn pii_access_allowed_when_not_requested() {
    let p = policy(None, Some(false), None, None, None);
    assert!(evaluate_policy(&p, &json!({"pii_access": false})).is_ok());
    assert!(evaluate_policy(&p, &json!({"query": "hello"})).is_ok());
}

#[test]
fn write_access_denied_when_policy_says_false() {
    let p = policy(None, None, Some(false), None, None);
    assert!(evaluate_policy(&p, &json!({"write_access": true})).is_err());
}

#[test]
fn write_access_allowed_when_false_requested() {
    let p = policy(None, None, Some(false), None, None);
    assert!(evaluate_policy(&p, &json!({"write_access": false})).is_ok());
}

#[test]
fn tool_in_allowlist_passes() {
    let p = policy(None, None, None, Some(vec!["web_search", "file_read"]), None);
    assert!(evaluate_policy(&p, &json!({"tool": "web_search"})).is_ok());
    assert!(evaluate_policy(&p, &json!({"tool": "file_read"})).is_ok());
}

#[test]
fn tool_not_in_allowlist_fails() {
    let p = policy(None, None, None, Some(vec!["web_search"]), None);
    assert!(evaluate_policy(&p, &json!({"tool": "delete_database"})).is_err());
}

#[test]
fn wildcard_tool_allows_any_tool() {
    let p = policy(None, None, None, Some(vec!["*"]), None);
    assert!(evaluate_policy(&p, &json!({"tool": "anything"})).is_ok());
}

#[test]
fn no_tool_in_args_skips_tool_check() {
    let p = policy(None, None, None, Some(vec!["web_search"]), None);
    // No "tool" key — check is skipped, not a violation
    assert!(evaluate_policy(&p, &json!({"query": "hello"})).is_ok());
}

// ── check_policy_attenuation ─────────────────────────────────────────────────

#[test]
fn identical_policies_pass_attenuation() {
    let p = policy(Some(10.0), Some(false), Some(false), Some(vec!["web_search"]), Some(100));
    assert!(check_policy_attenuation(&p, &p).is_ok());
}

#[test]
fn child_with_lower_cost_limit_passes() {
    let parent = policy(Some(50.0), None, None, None, None);
    let child = policy(Some(10.0), None, None, None, None);
    assert!(check_policy_attenuation(&parent, &child).is_ok());
}

#[test]
fn child_raising_cost_limit_fails() {
    let parent = policy(Some(10.0), None, None, None, None);
    let child = policy(Some(100.0), None, None, None, None);
    assert!(check_policy_attenuation(&parent, &child).is_err());
}

#[test]
fn child_granting_pii_when_parent_denies_fails() {
    let parent = policy(None, Some(false), None, None, None);
    let child = policy(None, Some(true), None, None, None);
    assert!(check_policy_attenuation(&parent, &child).is_err());
}

#[test]
fn child_granting_write_when_parent_denies_fails() {
    let parent = policy(None, None, Some(false), None, None);
    let child = policy(None, None, Some(true), None, None);
    assert!(check_policy_attenuation(&parent, &child).is_err());
}

#[test]
fn child_adding_tool_not_in_parent_fails() {
    let parent = policy(None, None, None, Some(vec!["web_search"]), None);
    let child = policy(None, None, None, Some(vec!["web_search", "delete_db"]), None);
    assert!(check_policy_attenuation(&parent, &child).is_err());
}

#[test]
fn child_with_subset_of_parent_tools_passes() {
    let parent = policy(None, None, None, Some(vec!["web_search", "file_read", "summarise"]), None);
    let child = policy(None, None, None, Some(vec!["web_search"]), None);
    assert!(check_policy_attenuation(&parent, &child).is_ok());
}

#[test]
fn child_adding_extra_restriction_passes() {
    // Child restricts pii when parent has no pii restriction — valid attenuation
    let parent = policy(Some(50.0), None, None, None, None);
    let child = policy(Some(10.0), Some(false), None, None, None);
    assert!(check_policy_attenuation(&parent, &child).is_ok());
}

#[test]
fn child_raising_max_calls_fails() {
    let parent = policy(None, None, None, None, Some(10));
    let child = policy(None, None, None, None, Some(100));
    assert!(check_policy_attenuation(&parent, &child).is_err());
}

#[test]
fn child_lowering_max_calls_passes() {
    let parent = policy(None, None, None, None, Some(100));
    let child = policy(None, None, None, None, Some(10));
    assert!(check_policy_attenuation(&parent, &child).is_ok());
}
