use crate::error::DrsError;
use crate::types::Policy;
use std::collections::HashSet;

/// Evaluates whether `args` from an invocation satisfy `policy`.
///
/// All checks are fail-closed: when a policy restricts a field, the corresponding
/// arg key MUST be present. An absent key means unknown intent — the capability
/// is denied. This matches the Go port in drs-verify/pkg/policy/evaluate.go.
///
/// `estimated_cost_usd` is only meaningful for costs known before invocation
/// (transaction amounts, fixed-fee APIs). It cannot enforce LLM inference costs —
/// those are unknowable until after the model call completes.
///
/// max_calls is not checked here; it requires session-level call-counting state.
/// Unknown fields in args are ignored (forward compatibility per §6.3).
pub fn evaluate_policy(policy: &Policy, args: &serde_json::Value) -> Result<(), DrsError> {
    // max_cost_usd: agent must declare estimated_cost_usd when policy restricts it.
    // Absent field is fail-closed — unknown cost cannot be allowed under a cost cap.
    if let Some(max_cost) = policy.max_cost_usd {
        let cost = args
            .get("estimated_cost_usd")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| {
                DrsError::PolicyViolation(
                    "estimated_cost_usd is required when max_cost_usd policy is set.".to_string(),
                )
            })?;
        if cost < 0.0 || cost.is_nan() || cost.is_infinite() {
            return Err(DrsError::PolicyViolation(format!(
                "estimated_cost_usd must be a finite non-negative number, got {cost}."
            )));
        }
        if cost > max_cost {
            return Err(DrsError::PolicyViolation(format!(
                "Cost limit exceeded. Max: ${max_cost:.2}. Provided: ${cost:.2}."
            )));
        }
    }

    // pii_access: agent must explicitly declare false when policy denies PII.
    // Absent field is fail-closed — undeclared intent cannot pass a restriction.
    if let Some(false) = policy.pii_access {
        let pii = args
            .get("pii_access")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                DrsError::PolicyViolation(
                    "pii_access is required by this delegation policy; \
                     set pii_access: false in args to confirm no PII is accessed."
                        .to_string(),
                )
            })?;
        if pii {
            return Err(DrsError::PolicyViolation(
                "PII access not permitted by this delegation.".to_string(),
            ));
        }
    }

    // write_access: agent must explicitly declare false when policy denies writes.
    if let Some(false) = policy.write_access {
        let write = args
            .get("write_access")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                DrsError::PolicyViolation(
                    "write_access is required by this delegation policy; \
                     set write_access: false in args to confirm no writes are performed."
                        .to_string(),
                )
            })?;
        if write {
            return Err(DrsError::PolicyViolation(
                "Write access not permitted.".to_string(),
            ));
        }
    }

    // allowed_tools: agent must declare tool when policy restricts it.
    // Absent key = unknown tool = capability denied.
    if let Some(allowed) = &policy.allowed_tools {
        if !allowed.iter().any(|t| t == "*") {
            let tool = args
                .get("tool")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    DrsError::PolicyViolation(format!(
                        "tool is required by this delegation policy. Allowed: [{}].",
                        allowed.join(", ")
                    ))
                })?;
            if !allowed.iter().any(|t| t == tool) {
                return Err(DrsError::PolicyViolation(format!(
                    "Tool not permitted. Allowed: [{}]. Requested: {tool}.",
                    allowed.join(", ")
                )));
            }
        }
    }

    // allowed_resources: agent must declare resource_uri when policy restricts it.
    // URI is normalized before matching to prevent ../ path traversal bypasses.
    if let Some(allowed) = &policy.allowed_resources {
        if !allowed.iter().any(|r| r == "*") {
            let uri = args
                .get("resource_uri")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    DrsError::PolicyViolation(format!(
                        "resource_uri is required by this delegation policy. Allowed: [{}].",
                        allowed.join(", ")
                    ))
                })?;
            let norm_uri = normalize_resource_uri(uri);
            if !allowed.iter().any(|pattern| {
                if pattern.as_str() == uri || pattern.as_str() == norm_uri {
                    return true;
                }
                if pattern.ends_with("/*") {
                    let prefix = &pattern[..pattern.len() - 1];
                    let norm_prefix = normalize_resource_uri(prefix);
                    return norm_uri.starts_with(&norm_prefix);
                }
                false
            }) {
                return Err(DrsError::PolicyViolation(format!(
                    "Resource not permitted. Allowed: [{}]. Requested: {uri}.",
                    allowed.join(", ")
                )));
            }
        }
    }

    // allowed_data_classes: agent must declare data_class when policy restricts it.
    if let Some(allowed) = &policy.allowed_data_classes {
        if !allowed.iter().any(|c| c == "*") {
            let class = args
                .get("data_class")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    DrsError::PolicyViolation(format!(
                        "data_class is required by this delegation policy. Allowed: [{}].",
                        allowed.join(", ")
                    ))
                })?;
            if !allowed.iter().any(|c| c == class) {
                return Err(DrsError::PolicyViolation(format!(
                    "Data class not permitted. Allowed: [{}]. Requested: {class}.",
                    allowed.join(", ")
                )));
            }
        }
    }

    Ok(())
}

/// Normalises a resource URI by resolving `..` and `.` path segments.
/// Prevents prefix-wildcard bypass via paths like `mcp://tools/../admin/delete`.
fn normalize_resource_uri(uri: &str) -> String {
    let (scheme, path) = match uri.find("://") {
        Some(i) => (&uri[..i + 3], &uri[i + 3..]),
        None => ("", uri),
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            s => parts.push(s),
        }
    }
    format!("{}{}", scheme, parts.join("/"))
}

/// Checks that `child` policy does not escalate beyond `parent` policy.
///
/// Implements §6.4 of the technical audit:
/// - For each numeric upper bound in parent: child must inherit or tighten it.
///   Omitting a parent-defined bound is escalation (implies unlimited).
/// - For each allowlist in parent: child must inherit or narrow it.
///   Omitting a parent-defined list is escalation (implies all permitted).
/// - For each boolean restriction (false) in parent: child cannot set it to true.
/// - Fields in child not in parent: always valid (child is adding restrictions).
///
/// Capability checks are fail-closed: any error means capability is denied.
pub fn check_policy_attenuation(parent: &Policy, child: &Policy) -> Result<(), DrsError> {
    // max_cost_usd: child cannot raise or omit the cost limit
    if let Some(parent_max) = parent.max_cost_usd {
        match child.max_cost_usd {
            None => {
                return Err(DrsError::PolicyViolation(format!(
                    "Child omits max_cost_usd but parent restricts it to ${parent_max:.2}; \
                     child must explicitly inherit or tighten this limit."
                )));
            }
            Some(child_max) if child_max > parent_max => {
                return Err(DrsError::PolicyViolation(format!(
                    "Child loosens upper bound for max_cost_usd. Parent: ${parent_max:.2}. Child: ${child_max:.2}."
                )));
            }
            _ => {}
        }
    }

    // pii_access: child cannot grant pii if parent denies it
    if let Some(false) = parent.pii_access {
        if let Some(true) = child.pii_access {
            return Err(DrsError::PolicyViolation(
                "Child relaxes restriction on pii_access. Parent: false. Child: true.".to_string(),
            ));
        }
    }

    // write_access: child cannot grant write if parent denies it
    if let Some(false) = parent.write_access {
        if let Some(true) = child.write_access {
            return Err(DrsError::PolicyViolation(
                "Child relaxes restriction on write_access. Parent: false. Child: true.".to_string(),
            ));
        }
    }

    // max_calls: child cannot raise or omit the call limit
    if let Some(parent_max) = parent.max_calls {
        match child.max_calls {
            None => {
                return Err(DrsError::PolicyViolation(format!(
                    "Child omits max_calls but parent restricts it to {parent_max}; \
                     child must explicitly inherit or tighten this limit."
                )));
            }
            Some(child_max) if child_max > parent_max => {
                return Err(DrsError::PolicyViolation(format!(
                    "Child loosens upper bound for max_calls. Parent: {parent_max}. Child: {child_max}."
                )));
            }
            _ => {}
        }
    }

    // allowed_tools: child must inherit or narrow the parent's list
    if let Some(parent_tools) = &parent.allowed_tools {
        if !parent_tools.iter().any(|t| t == "*") {
            let parent_tools_set: HashSet<&String> = parent_tools.iter().collect();
            match &child.allowed_tools {
                None => {
                    return Err(DrsError::PolicyViolation(
                        "Child omits allowed_tools but parent restricts it; \
                         child must explicitly list permitted tools."
                            .to_string(),
                    ));
                }
                Some(child_tools) => {
                    for tool in child_tools {
                        if tool == "*" {
                            return Err(DrsError::PolicyViolation(
                                "Child adds wildcard '*' to allowed_tools but parent does not allow all tools.".to_string(),
                            ));
                        }
                        if !parent_tools_set.contains(tool) {
                            return Err(DrsError::PolicyViolation(format!(
                                "Child adds '{tool}' to allowed_tools not permitted by parent."
                            )));
                        }
                    }
                }
            }
        }
    }

    // allowed_resources: child must inherit or narrow the parent's list
    if let Some(parent_res) = &parent.allowed_resources {
        if !parent_res.iter().any(|r| r == "*") {
            let parent_res_set: HashSet<&String> = parent_res.iter().collect();
            match &child.allowed_resources {
                None => {
                    return Err(DrsError::PolicyViolation(
                        "Child omits allowed_resources but parent restricts it; \
                         child must explicitly list permitted resources."
                            .to_string(),
                    ));
                }
                Some(child_res) => {
                    for res in child_res {
                        if res == "*" {
                            return Err(DrsError::PolicyViolation(
                                "Child adds wildcard '*' to allowed_resources but parent does not allow all.".to_string(),
                            ));
                        }
                        if !parent_res_set.contains(res) {
                            return Err(DrsError::PolicyViolation(format!(
                                "Child adds '{res}' to allowed_resources not permitted by parent."
                            )));
                        }
                    }
                }
            }
        }
    }

    // allowed_data_classes: child must inherit or narrow the parent's list
    if let Some(parent_cls) = &parent.allowed_data_classes {
        if !parent_cls.iter().any(|c| c == "*") {
            let parent_cls_set: HashSet<&String> = parent_cls.iter().collect();
            match &child.allowed_data_classes {
                None => {
                    return Err(DrsError::PolicyViolation(
                        "Child omits allowed_data_classes but parent restricts it; \
                         child must explicitly list permitted data classes."
                            .to_string(),
                    ));
                }
                Some(child_cls) => {
                    for cls in child_cls {
                        if cls == "*" || !parent_cls_set.contains(cls) {
                            return Err(DrsError::PolicyViolation(format!(
                                "Child adds '{cls}' to allowed_data_classes not permitted by parent."
                            )));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy_with(
        max_cost: Option<f64>,
        pii: Option<bool>,
        write: Option<bool>,
        tools: Option<Vec<&str>>,
    ) -> Policy {
        Policy {
            max_cost_usd: max_cost,
            pii_access: pii,
            allowed_tools: tools.map(|v| v.iter().map(|s| s.to_string()).collect()),
            max_calls: None,
            write_access: write,
            allowed_resources: None,
            allowed_data_classes: None,
        }
    }

    // ── evaluate_policy ──────────────────────────────────────────────────────

    #[test]
    fn cost_within_limit_passes() {
        let p = policy_with(Some(10.0), None, None, None);
        // Correct field name per §6.3: "estimated_cost_usd"
        assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": 5.0})).is_ok());
    }

    #[test]
    fn cost_over_limit_fails() {
        let p = policy_with(Some(10.0), None, None, None);
        assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": 15.0})).is_err());
    }

    #[test]
    fn cost_absent_field_fails_closed() {
        // When max_cost_usd is set, estimated_cost_usd must be present.
        // Wrong field name is treated the same as absent — both fail.
        let p = policy_with(Some(10.0), None, None, None);
        assert!(evaluate_policy(&p, &json!({})).is_err());
        assert!(evaluate_policy(&p, &json!({"cost": 999.0})).is_err()); // wrong field name
    }

    #[test]
    fn cost_invalid_value_fails() {
        let p = policy_with(Some(10.0), None, None, None);
        assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": -1.0})).is_err());
    }

    #[test]
    fn pii_access_denied_with_correct_field_name() {
        let p = policy_with(None, Some(false), None, None);
        assert!(evaluate_policy(&p, &json!({"pii_access": true})).is_err());
        assert!(evaluate_policy(&p, &json!({"pii_access": false})).is_ok());
    }

    #[test]
    fn pii_access_absent_fails_closed() {
        // When policy restricts pii_access, agent must explicitly declare false.
        let p = policy_with(None, Some(false), None, None);
        assert!(evaluate_policy(&p, &json!({})).is_err());
        assert!(evaluate_policy(&p, &json!({"query": "hello"})).is_err());
    }

    #[test]
    fn write_access_denied_with_correct_field_name() {
        let p = policy_with(None, None, Some(false), None);
        assert!(evaluate_policy(&p, &json!({"write_access": true})).is_err());
        assert!(evaluate_policy(&p, &json!({"write_access": false})).is_ok());
    }

    #[test]
    fn write_access_absent_fails_closed() {
        let p = policy_with(None, None, Some(false), None);
        assert!(evaluate_policy(&p, &json!({})).is_err());
    }

    #[test]
    fn allowed_tool_passes() {
        let p = policy_with(None, None, None, Some(vec!["web_search"]));
        assert!(evaluate_policy(&p, &json!({"tool": "web_search"})).is_ok());
    }

    #[test]
    fn disallowed_tool_fails() {
        let p = policy_with(None, None, None, Some(vec!["web_search"]));
        assert!(evaluate_policy(&p, &json!({"tool": "delete_database"})).is_err());
    }

    #[test]
    fn tool_absent_fails_closed() {
        // When policy restricts tools, agent must declare which tool it's calling.
        let p = policy_with(None, None, None, Some(vec!["web_search"]));
        assert!(evaluate_policy(&p, &json!({})).is_err());
        assert!(evaluate_policy(&p, &json!({"query": "hello"})).is_err());
    }

    #[test]
    fn wildcard_tool_policy_skips_check() {
        // Wildcard parent = all tools allowed; tool key not required.
        let p = policy_with(None, None, None, Some(vec!["*"]));
        assert!(evaluate_policy(&p, &json!({})).is_ok());
        assert!(evaluate_policy(&p, &json!({"tool": "anything"})).is_ok());
    }

    #[test]
    fn resource_path_traversal_blocked() {
        let p = Policy {
            max_cost_usd: None,
            pii_access: None,
            write_access: None,
            allowed_tools: None,
            max_calls: None,
            allowed_resources: Some(vec!["mcp://tools/*".to_string()]),
            allowed_data_classes: None,
        };
        // Normal URI inside allowed prefix — passes
        assert!(evaluate_policy(&p, &json!({"resource_uri": "mcp://tools/web_search"})).is_ok());
        // Path traversal via ../ — blocked after normalization
        assert!(evaluate_policy(&p, &json!({"resource_uri": "mcp://tools/../admin/delete"})).is_err());
        assert!(evaluate_policy(&p, &json!({"resource_uri": "mcp://tools/../../etc/passwd"})).is_err());
    }

    #[test]
    fn resource_absent_fails_closed() {
        let p = Policy {
            max_cost_usd: None,
            pii_access: None,
            write_access: None,
            allowed_tools: None,
            max_calls: None,
            allowed_resources: Some(vec!["mcp://tools/*".to_string()]),
            allowed_data_classes: None,
        };
        assert!(evaluate_policy(&p, &json!({})).is_err());
    }

    // ── check_policy_attenuation ─────────────────────────────────────────────

    #[test]
    fn same_policy_passes_attenuation() {
        let p = policy_with(Some(10.0), Some(false), Some(false), Some(vec!["web_search"]));
        assert!(check_policy_attenuation(&p, &p).is_ok());
    }

    #[test]
    fn cost_escalation_fails() {
        let parent = policy_with(Some(10.0), None, None, None);
        let child = policy_with(Some(20.0), None, None, None);
        assert!(check_policy_attenuation(&parent, &child).is_err());
    }

    #[test]
    fn cost_reduction_passes() {
        let parent = policy_with(Some(10.0), None, None, None);
        let child = policy_with(Some(5.0), None, None, None);
        assert!(check_policy_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn pii_escalation_fails() {
        let parent = policy_with(None, Some(false), None, None);
        let child = policy_with(None, Some(true), None, None);
        assert!(check_policy_attenuation(&parent, &child).is_err());
    }

    #[test]
    fn write_escalation_fails() {
        let parent = policy_with(None, None, Some(false), None);
        let child = policy_with(None, None, Some(true), None);
        assert!(check_policy_attenuation(&parent, &child).is_err());
    }

    #[test]
    fn tool_escalation_fails() {
        let parent = policy_with(None, None, None, Some(vec!["web_search"]));
        let child = policy_with(None, None, None, Some(vec!["web_search", "delete_database"]));
        assert!(check_policy_attenuation(&parent, &child).is_err());
    }

    #[test]
    fn subset_of_tools_passes() {
        let parent = policy_with(None, None, None, Some(vec!["web_search", "file_read", "summarise"]));
        let child = policy_with(None, None, None, Some(vec!["web_search"]));
        assert!(check_policy_attenuation(&parent, &child).is_ok());
    }

    #[test]
    fn child_adding_extra_restriction_passes() {
        // Child adds pii_access: false when parent has no pii restriction — valid
        let parent = policy_with(Some(50.0), None, None, None);
        let child = policy_with(Some(10.0), Some(false), None, None);
        assert!(check_policy_attenuation(&parent, &child).is_ok());
    }
}
