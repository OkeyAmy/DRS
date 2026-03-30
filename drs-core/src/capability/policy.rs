use crate::error::DrsError;
use crate::types::Policy;

/// Evaluates whether `args` from an invocation satisfy `policy`.
///
/// Field names in `args` are the canonical DRS argument names from §6.3 of
/// the technical audit. Using the wrong field name produces a false pass —
/// the spec is explicit: `estimated_cost_usd`, `pii_access`, `write_access`.
///
/// max_calls is not checked here (requires session-level state outside this function).
/// Unknown fields in args are ignored (forward compatibility per §6.3).
pub fn evaluate_policy(policy: &Policy, args: &serde_json::Value) -> Result<(), DrsError> {
    // max_cost_usd: args.estimated_cost_usd must not exceed the limit
    // Field name is "estimated_cost_usd", not "cost" — see technical_audit §6.3
    if let Some(max_cost) = policy.max_cost_usd {
        if let Some(cost) = args.get("estimated_cost_usd").and_then(|v| v.as_f64()) {
            if cost > max_cost {
                return Err(DrsError::PolicyViolation(format!(
                    "Cost limit exceeded. Max: ${max_cost:.2}. Provided: ${cost:.2}."
                )));
            }
        }
    }

    // pii_access: false means pii must not be requested
    // Field name is "pii_access", not "pii" — see technical_audit §6.3
    if let Some(false) = policy.pii_access {
        if let Some(true) = args.get("pii_access").and_then(|v| v.as_bool()) {
            return Err(DrsError::PolicyViolation(
                "PII access not permitted by this delegation.".to_string(),
            ));
        }
    }

    // write_access: false means write operations are not permitted
    // Field name is "write_access", not "write" — see technical_audit §6.3
    if let Some(false) = policy.write_access {
        if let Some(true) = args.get("write_access").and_then(|v| v.as_bool()) {
            return Err(DrsError::PolicyViolation(
                "Write access not permitted.".to_string(),
            ));
        }
    }

    // allowed_tools: args.tool must be in the permitted list
    if let Some(allowed) = &policy.allowed_tools {
        if let Some(tool) = args.get("tool").and_then(|v| v.as_str()) {
            if !allowed.iter().any(|t| t == tool || t == "*") {
                return Err(DrsError::PolicyViolation(format!(
                    "Tool not permitted. Allowed: [{}]. Requested: {tool}.",
                    allowed.join(", ")
                )));
            }
        }
    }

    // allowed_resources: args.resource_uri must match at least one permitted pattern
    // Field name is "resource_uri" — see technical_audit §6.3
    if let Some(allowed) = &policy.allowed_resources {
        if let Some(uri) = args.get("resource_uri").and_then(|v| v.as_str()) {
            if !allowed.iter().any(|pattern| {
                pattern == "*"
                    || pattern == uri
                    || (pattern.ends_with("/*") && uri.starts_with(&pattern[..pattern.len() - 1]))
            }) {
                return Err(DrsError::PolicyViolation(format!(
                    "Resource not permitted. Allowed: [{}]. Requested: {uri}.",
                    allowed.join(", ")
                )));
            }
        }
    }

    // allowed_data_classes: args.data_class must be in the permitted list
    if let Some(allowed) = &policy.allowed_data_classes {
        if let Some(class) = args.get("data_class").and_then(|v| v.as_str()) {
            if !allowed.iter().any(|c| c == class || c == "*") {
                return Err(DrsError::PolicyViolation(format!(
                    "Data class not permitted. Allowed: [{}]. Requested: {class}.",
                    allowed.join(", ")
                )));
            }
        }
    }

    Ok(())
}

/// Checks that `child` policy does not escalate beyond `parent` policy.
///
/// Implements §6.4 of the technical audit:
/// - For each numeric upper bound in parent: if child has the same field,
///   child[field] <= parent[field]. POLA — child cannot loosen an upper bound.
/// - For each allowlist in parent: if child has the same field,
///   child's list must be a subset of parent's list.
/// - For each boolean restriction (false) in parent: child cannot set it to true.
/// - Fields in child not in parent: always valid (child is adding restrictions).
///
/// Capability checks are fail-closed: any error means capability is denied.
pub fn check_policy_attenuation(parent: &Policy, child: &Policy) -> Result<(), DrsError> {
    // max_cost_usd: child cannot raise the cost limit above parent's
    if let (Some(parent_max), Some(child_max)) = (parent.max_cost_usd, child.max_cost_usd) {
        if child_max > parent_max {
            return Err(DrsError::PolicyViolation(format!(
                "Child loosens upper bound for max_cost_usd. Parent: ${parent_max:.2}. Child: ${child_max:.2}."
            )));
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

    // max_calls: child cannot raise the call limit above parent's
    if let (Some(parent_max), Some(child_max)) = (parent.max_calls, child.max_calls) {
        if child_max > parent_max {
            return Err(DrsError::PolicyViolation(format!(
                "Child loosens upper bound for max_calls. Parent: {parent_max}. Child: {child_max}."
            )));
        }
    }

    // allowed_tools: child's list must be a subset of parent's list
    if let (Some(parent_tools), Some(child_tools)) = (&parent.allowed_tools, &child.allowed_tools)
    {
        // If parent has a wildcard, any child list is a subset
        if !parent_tools.iter().any(|t| t == "*") {
            for tool in child_tools {
                if tool != "*" && !parent_tools.contains(tool) {
                    return Err(DrsError::PolicyViolation(format!(
                        "Child adds '{tool}' to allowed_tools not permitted by parent."
                    )));
                }
                // Child wildcard is only valid if parent has a wildcard (checked above)
                if tool == "*" {
                    return Err(DrsError::PolicyViolation(
                        "Child adds wildcard '*' to allowed_tools but parent does not allow all tools.".to_string(),
                    ));
                }
            }
        }
    }

    // allowed_resources: child's list must be a subset of parent's list
    if let (Some(parent_res), Some(child_res)) =
        (&parent.allowed_resources, &child.allowed_resources)
    {
        if !parent_res.iter().any(|r| r == "*") {
            for res in child_res {
                if res != "*" && !parent_res.contains(res) {
                    return Err(DrsError::PolicyViolation(format!(
                        "Child adds '{res}' to allowed_resources not permitted by parent."
                    )));
                }
                if res == "*" {
                    return Err(DrsError::PolicyViolation(
                        "Child adds wildcard '*' to allowed_resources but parent does not allow all.".to_string(),
                    ));
                }
            }
        }
    }

    // allowed_data_classes: child's list must be a subset of parent's list
    if let (Some(parent_cls), Some(child_cls)) =
        (&parent.allowed_data_classes, &child.allowed_data_classes)
    {
        if !parent_cls.iter().any(|c| c == "*") {
            for cls in child_cls {
                if cls != "*" && !parent_cls.contains(cls) {
                    return Err(DrsError::PolicyViolation(format!(
                        "Child adds '{cls}' to allowed_data_classes not permitted by parent."
                    )));
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
    fn wrong_cost_field_name_does_not_trigger_check() {
        // Using "cost" instead of "estimated_cost_usd" means the policy is not evaluated.
        // This verifies we're using the correct field name from the spec.
        let p = policy_with(Some(10.0), None, None, None);
        // "cost" is the WRONG field — policy check is skipped (unknown field)
        assert!(evaluate_policy(&p, &json!({"cost": 999.0})).is_ok());
        // "estimated_cost_usd" is the RIGHT field — policy check fires
        assert!(evaluate_policy(&p, &json!({"estimated_cost_usd": 999.0})).is_err());
    }

    #[test]
    fn pii_access_denied_with_correct_field_name() {
        let p = policy_with(None, Some(false), None, None);
        // Correct field name per §6.3: "pii_access"
        assert!(evaluate_policy(&p, &json!({"pii_access": true})).is_err());
        assert!(evaluate_policy(&p, &json!({"pii_access": false})).is_ok());
        // Without the field — passes (not applicable)
        assert!(evaluate_policy(&p, &json!({"query": "hello"})).is_ok());
    }

    #[test]
    fn write_access_denied_with_correct_field_name() {
        let p = policy_with(None, None, Some(false), None);
        // Correct field name per §6.3: "write_access"
        assert!(evaluate_policy(&p, &json!({"write_access": true})).is_err());
        assert!(evaluate_policy(&p, &json!({"write_access": false})).is_ok());
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
