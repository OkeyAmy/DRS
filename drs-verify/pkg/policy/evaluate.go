// Package policy implements DRS capability policy evaluation and attenuation checks.
// This is a Go port of drs-core/src/capability/policy.rs.
// Field names must match §6.3 of the technical audit exactly.
package policy

import (
	"fmt"

	"github.com/drs-protocol/drs-verify/pkg/types"
)

// Evaluate checks whether args from an invocation satisfy policy.
// Returns nil on success, an error describing the violation otherwise.
// Capability checks are fail-closed: any error means the capability is denied.
func Evaluate(pol types.Policy, args map[string]interface{}) error {
	// max_cost_usd: args["estimated_cost_usd"] must not exceed the limit
	if pol.MaxCostUSD != nil {
		if costRaw, ok := args["estimated_cost_usd"]; ok {
			cost, ok := toFloat64(costRaw)
			if !ok {
				return fmt.Errorf("estimated_cost_usd must be a number")
			}
			if cost > *pol.MaxCostUSD {
				return fmt.Errorf("cost limit exceeded: max $%.2f, provided $%.2f", *pol.MaxCostUSD, cost)
			}
		}
	}

	// pii_access: false means pii must not be requested
	if pol.PIIAccess != nil && !*pol.PIIAccess {
		if piiRaw, ok := args["pii_access"]; ok {
			if pii, ok := piiRaw.(bool); ok && pii {
				return fmt.Errorf("PII access not permitted by this delegation")
			}
		}
	}

	// write_access: false means write operations are not permitted
	if pol.WriteAccess != nil && !*pol.WriteAccess {
		if writeRaw, ok := args["write_access"]; ok {
			if write, ok := writeRaw.(bool); ok && write {
				return fmt.Errorf("write access not permitted")
			}
		}
	}

	// allowed_tools: args["tool"] must be in the permitted list
	if len(pol.AllowedTools) > 0 {
		if toolRaw, ok := args["tool"]; ok {
			tool, ok := toolRaw.(string)
			if !ok {
				return fmt.Errorf("tool must be a string")
			}
			if !toolCovered(tool, pol.AllowedTools) {
				return fmt.Errorf("tool not permitted: allowed [%v], requested %q",
					pol.AllowedTools, tool)
			}
		}
	}

	// allowed_resources: args["resource_uri"] must match at least one pattern
	if len(pol.AllowedResources) > 0 {
		if uriRaw, ok := args["resource_uri"]; ok {
			uri, ok := uriRaw.(string)
			if !ok {
				return fmt.Errorf("resource_uri must be a string")
			}
			if !resourceCovered(uri, pol.AllowedResources) {
				return fmt.Errorf("resource not permitted: allowed [%v], requested %q",
					pol.AllowedResources, uri)
			}
		}
	}

	// allowed_data_classes: args["data_class"] must be in the permitted list
	if len(pol.AllowedDataClasses) > 0 {
		if classRaw, ok := args["data_class"]; ok {
			class, ok := classRaw.(string)
			if !ok {
				return fmt.Errorf("data_class must be a string")
			}
			if !classCovered(class, pol.AllowedDataClasses) {
				return fmt.Errorf("data class not permitted: allowed [%v], requested %q",
					pol.AllowedDataClasses, class)
			}
		}
	}

	return nil
}

// CheckAttenuation verifies that child policy does not escalate beyond parent policy.
// Implements §6.4 of the technical audit.
// Fail-closed: any attenuation violation denies the capability.
func CheckAttenuation(parent, child types.Policy) error {
	// max_cost_usd: child cannot raise the cost limit
	if parent.MaxCostUSD != nil && child.MaxCostUSD != nil {
		if *child.MaxCostUSD > *parent.MaxCostUSD {
			return fmt.Errorf("child loosens max_cost_usd: parent $%.2f, child $%.2f",
				*parent.MaxCostUSD, *child.MaxCostUSD)
		}
	}

	// pii_access: child cannot grant pii if parent denies it
	if parent.PIIAccess != nil && !*parent.PIIAccess {
		if child.PIIAccess != nil && *child.PIIAccess {
			return fmt.Errorf("child relaxes pii_access restriction: parent false, child true")
		}
	}

	// write_access: child cannot grant write if parent denies it
	if parent.WriteAccess != nil && !*parent.WriteAccess {
		if child.WriteAccess != nil && *child.WriteAccess {
			return fmt.Errorf("child relaxes write_access restriction: parent false, child true")
		}
	}

	// max_calls: child cannot raise the call limit
	if parent.MaxCalls != nil && child.MaxCalls != nil {
		if *child.MaxCalls > *parent.MaxCalls {
			return fmt.Errorf("child loosens max_calls: parent %d, child %d",
				*parent.MaxCalls, *child.MaxCalls)
		}
	}

	// allowed_tools: child's list must be a subset of parent's list
	if len(parent.AllowedTools) > 0 && len(child.AllowedTools) > 0 {
		if !hasWildcard(parent.AllowedTools) {
			for _, tool := range child.AllowedTools {
				if tool == "*" {
					return fmt.Errorf("child adds wildcard '*' to allowed_tools but parent does not allow all tools")
				}
				if !contains(parent.AllowedTools, tool) {
					return fmt.Errorf("child adds %q to allowed_tools not permitted by parent", tool)
				}
			}
		}
	}

	// allowed_resources: child's list must be a subset of parent's list
	if len(parent.AllowedResources) > 0 && len(child.AllowedResources) > 0 {
		if !hasWildcard(parent.AllowedResources) {
			for _, res := range child.AllowedResources {
				if res == "*" {
					return fmt.Errorf("child adds wildcard '*' to allowed_resources but parent does not allow all")
				}
				if !contains(parent.AllowedResources, res) {
					return fmt.Errorf("child adds %q to allowed_resources not permitted by parent", res)
				}
			}
		}
	}

	// allowed_data_classes: child's list must be a subset of parent's list
	if len(parent.AllowedDataClasses) > 0 && len(child.AllowedDataClasses) > 0 {
		if !hasWildcard(parent.AllowedDataClasses) {
			for _, cls := range child.AllowedDataClasses {
				if cls == "*" || !contains(parent.AllowedDataClasses, cls) {
					return fmt.Errorf("child adds %q to allowed_data_classes not permitted by parent", cls)
				}
			}
		}
	}

	return nil
}

func toolCovered(tool string, allowed []string) bool {
	for _, t := range allowed {
		if t == "*" || t == tool {
			return true
		}
	}
	return false
}

func resourceCovered(uri string, patterns []string) bool {
	for _, p := range patterns {
		if p == "*" || p == uri {
			return true
		}
		// Prefix wildcard: "mcp://tools/*" covers "mcp://tools/web_search"
		if len(p) > 1 && p[len(p)-1] == '*' && p[len(p)-2] == '/' {
			prefix := p[:len(p)-1]
			if len(uri) >= len(prefix) && uri[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

func classCovered(class string, allowed []string) bool {
	for _, c := range allowed {
		if c == "*" || c == class {
			return true
		}
	}
	return false
}

func hasWildcard(list []string) bool {
	for _, v := range list {
		if v == "*" {
			return true
		}
	}
	return false
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
