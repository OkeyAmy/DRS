// Package policy implements DRS capability policy evaluation and attenuation checks.
// This is a Go port of drs-core/src/capability/policy.rs.
// Field names must match §6.3 of the technical audit exactly.
package policy

import (
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
)

// Evaluate checks whether args from an invocation satisfy policy.
// Returns nil on success, an error describing the violation otherwise.
// Capability checks are fail-closed: any error means the capability is denied.
//
// max_calls is intentionally NOT evaluated here. It is informational-only in
// the stateless verifier because enforcement requires session-aware call
// counting with durable state and race-safe decrements. Integrators who need
// call-count enforcement must implement it in their session layer using the
// max_calls value from the leaf policy returned in VerificationContext.
func Evaluate(pol types.Policy, args map[string]interface{}) error {
	// max_cost_usd: args["estimated_cost_usd"] must not exceed the limit
	if pol.MaxCostUSD != nil {
		costRaw, ok := args["estimated_cost_usd"]
		if !ok {
			return fmt.Errorf("estimated_cost_usd is required by this delegation policy")
		}
		cost, ok := toFloat64(costRaw)
		if !ok {
			return fmt.Errorf("estimated_cost_usd must be a finite non-negative number")
		}
		if cost < 0 {
			return fmt.Errorf("estimated_cost_usd must be non-negative, got %v", cost)
		}
		if cost > *pol.MaxCostUSD {
			return fmt.Errorf("cost limit exceeded: max $%.2f, provided $%.2f", *pol.MaxCostUSD, cost)
		}
	}

	// pii_access: false means pii must not be requested
	if pol.PIIAccess != nil && !*pol.PIIAccess {
		piiRaw, ok := args["pii_access"]
		if !ok {
			return fmt.Errorf("pii_access is required by this delegation policy")
		}
		pii, ok := piiRaw.(bool)
		if !ok {
			return fmt.Errorf("pii_access must be a boolean")
		}
		if pii {
			return fmt.Errorf("PII access not permitted by this delegation")
		}
	}

	// write_access: false means write operations are not permitted
	if pol.WriteAccess != nil && !*pol.WriteAccess {
		writeRaw, ok := args["write_access"]
		if !ok {
			return fmt.Errorf("write_access is required by this delegation policy")
		}
		write, ok := writeRaw.(bool)
		if !ok {
			return fmt.Errorf("write_access must be a boolean")
		}
		if write {
			return fmt.Errorf("write access not permitted")
		}
	}

	// allowed_tools: args["tool"] must be in the permitted list
	if len(pol.AllowedTools) > 0 && !hasWildcard(pol.AllowedTools) {
		toolRaw, ok := args["tool"]
		if !ok {
			return fmt.Errorf("tool is required by this delegation policy")
		}
		tool, ok := toolRaw.(string)
		if !ok {
			return fmt.Errorf("tool must be a string")
		}
		if !toolCovered(tool, pol.AllowedTools) {
			return fmt.Errorf("tool not permitted: allowed [%v], requested %q",
				pol.AllowedTools, tool)
		}
	}

	// allowed_resources: args["resource_uri"] must match at least one pattern
	if len(pol.AllowedResources) > 0 && !hasWildcard(pol.AllowedResources) {
		uriRaw, ok := args["resource_uri"]
		if !ok {
			return fmt.Errorf("resource_uri is required by this delegation policy")
		}
		uri, ok := uriRaw.(string)
		if !ok {
			return fmt.Errorf("resource_uri must be a string")
		}
		if !resourceCovered(uri, pol.AllowedResources) {
			return fmt.Errorf("resource not permitted: allowed [%v], requested %q",
				pol.AllowedResources, uri)
		}
	}

	// allowed_data_classes: args["data_class"] must be in the permitted list
	if len(pol.AllowedDataClasses) > 0 && !hasWildcard(pol.AllowedDataClasses) {
		classRaw, ok := args["data_class"]
		if !ok {
			return fmt.Errorf("data_class is required by this delegation policy")
		}
		class, ok := classRaw.(string)
		if !ok {
			return fmt.Errorf("data_class must be a string")
		}
		if !classCovered(class, pol.AllowedDataClasses) {
			return fmt.Errorf("data class not permitted: allowed [%v], requested %q",
				pol.AllowedDataClasses, class)
		}
	}

	return nil
}

// CheckAttenuation verifies that child policy does not escalate beyond parent policy.
// Implements §6.4 of the technical audit.
// Fail-closed: any attenuation violation denies the capability.
func CheckAttenuation(parent, child types.Policy) error {
	// max_cost_usd: child cannot raise the cost limit; cannot omit if parent defines it
	if parent.MaxCostUSD != nil {
		if child.MaxCostUSD == nil {
			return fmt.Errorf("child omits max_cost_usd but parent restricts it to $%.2f; child must explicitly inherit or tighten this limit", *parent.MaxCostUSD)
		}
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

	// max_calls: child cannot raise the call limit; cannot omit if parent defines it
	if parent.MaxCalls != nil {
		if child.MaxCalls == nil {
			return fmt.Errorf("child omits max_calls but parent restricts it to %d; child must explicitly inherit or tighten this limit", *parent.MaxCalls)
		}
		if *child.MaxCalls > *parent.MaxCalls {
			return fmt.Errorf("child loosens max_calls: parent %d, child %d",
				*parent.MaxCalls, *child.MaxCalls)
		}
	}

	// allowed_tools: child's list must be a subset of parent's list;
	// cannot omit if parent restricts (omitting implies all tools, which escalates)
	if len(parent.AllowedTools) > 0 && !hasWildcard(parent.AllowedTools) {
		if len(child.AllowedTools) == 0 {
			return fmt.Errorf("child omits allowed_tools but parent restricts it; child must explicitly list permitted tools")
		}
		for _, tool := range child.AllowedTools {
			if tool == "*" {
				return fmt.Errorf("child adds wildcard '*' to allowed_tools but parent does not allow all tools")
			}
			if !contains(parent.AllowedTools, tool) {
				return fmt.Errorf("child adds %q to allowed_tools not permitted by parent", tool)
			}
		}
	}

	// allowed_resources: child's list must be a subset of parent's list;
	// cannot omit if parent restricts
	if len(parent.AllowedResources) > 0 && !hasWildcard(parent.AllowedResources) {
		if len(child.AllowedResources) == 0 {
			return fmt.Errorf("child omits allowed_resources but parent restricts it; child must explicitly list permitted resources")
		}
		for _, res := range child.AllowedResources {
			if res == "*" {
				return fmt.Errorf("child adds wildcard '*' to allowed_resources but parent does not allow all")
			}
			if !contains(parent.AllowedResources, res) {
				return fmt.Errorf("child adds %q to allowed_resources not permitted by parent", res)
			}
		}
	}

	// allowed_data_classes: child's list must be a subset of parent's list;
	// cannot omit if parent restricts
	if len(parent.AllowedDataClasses) > 0 && !hasWildcard(parent.AllowedDataClasses) {
		if len(child.AllowedDataClasses) == 0 {
			return fmt.Errorf("child omits allowed_data_classes but parent restricts it; child must explicitly list permitted data classes")
		}
		for _, cls := range child.AllowedDataClasses {
			if cls == "*" || !contains(parent.AllowedDataClasses, cls) {
				return fmt.Errorf("child adds %q to allowed_data_classes not permitted by parent", cls)
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
	normURI := normalizeResourceURI(uri)
	for _, p := range patterns {
		if p == "*" || p == uri || p == normURI {
			return true
		}
		// Prefix wildcard: "mcp://tools/*" covers "mcp://tools/web_search".
		// Both the requested URI and the pattern prefix are normalized before
		// comparison to block "../" traversal. The prefix is required to end
		// with "/" so that "mcp://tools/*" does not match "mcp://toolsadmin".
		if len(p) > 1 && p[len(p)-1] == '*' && p[len(p)-2] == '/' {
			normPrefix := normalizeResourceURI(p[:len(p)-1])
			if !strings.HasSuffix(normPrefix, "/") {
				normPrefix += "/"
			}
			if strings.HasPrefix(normURI, normPrefix) {
				return true
			}
		}
	}
	return false
}

// normalizeResourceURI resolves percent-encoded dots, ".." and "." path segments
// in a resource URI so that prefix-wildcard checks cannot be bypassed via traversal.
// Each path segment is percent-decoded independently (split on "/" first) so that
// a "%2F" inside a segment cannot be confused with a path separator.
// Example: "mcp://tools/../admin/delete"  → "mcp://admin/delete"
// Example: "mcp://tools/%2e%2e/admin"     → "mcp://admin"
func normalizeResourceURI(uri string) string {
	const sep = "://"
	scheme := ""
	path := uri
	if idx := strings.Index(uri, sep); idx >= 0 {
		scheme = uri[:idx+len(sep)]
		path = uri[idx+len(sep):]
	}
	var parts []string
	for _, seg := range strings.Split(path, "/") {
		// Decode percent-encoding within each segment so %2e%2e → ..
		decoded := seg
		if d, err := url.PathUnescape(seg); err == nil {
			decoded = d
		}
		switch decoded {
		case "..":
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
		case ".", "":
			// drop
		default:
			parts = append(parts, decoded)
		}
	}
	return scheme + strings.Join(parts, "/")
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
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}
