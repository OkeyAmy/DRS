package policy

import (
	"math"
	"testing"

	"github.com/drs-protocol/drs-verify/pkg/types"
)

func boolPtr(b bool) *bool    { return &b }
func f64Ptr(f float64) *float64 { return &f }
func u64Ptr(n uint64) *uint64   { return &n }

func pol(maxCost *float64, pii, write *bool, tools []string) types.Policy {
	return types.Policy{
		MaxCostUSD:   maxCost,
		PIIAccess:    pii,
		WriteAccess:  write,
		AllowedTools: tools,
	}
}

// ── Evaluate ─────────────────────────────────────────────────────────────────

func TestCostWithinLimitPasses(t *testing.T) {
	p := pol(f64Ptr(10.0), nil, nil, nil)
	if err := Evaluate(p, map[string]interface{}{"estimated_cost_usd": 9.99}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCostOverLimitFails(t *testing.T) {
	p := pol(f64Ptr(10.0), nil, nil, nil)
	if err := Evaluate(p, map[string]interface{}{"estimated_cost_usd": 10.01}); err == nil {
		t.Error("expected cost limit error, got nil")
	}
}

func TestWrongCostFieldNameIsIgnored(t *testing.T) {
	// "cost" is not the spec field — check must not fire
	p := pol(f64Ptr(1.0), nil, nil, nil)
	if err := Evaluate(p, map[string]interface{}{"cost": 9999.0}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEvaluateCostSpecialValues(t *testing.T) {
	limit := 100.0
	pol := types.Policy{MaxCostUSD: &limit}

	cases := []struct {
		name    string
		cost    interface{}
		wantErr bool
	}{
		{"NaN float64", math.NaN(), true},
		{"positive Inf", math.Inf(1), true},
		{"negative Inf", math.Inf(-1), true},
		{"negative cost", -1.0, true},
		{"zero cost", 0.0, false},
		{"within limit", 50.0, false},
		{"at limit", 100.0, false},
		{"over limit", 100.01, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{"estimated_cost_usd": tc.cost}
			err := Evaluate(pol, args)
			if tc.wantErr && err == nil {
				t.Errorf("Evaluate(%v): expected error, got nil", tc.cost)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Evaluate(%v): expected nil error, got %v", tc.cost, err)
			}
		})
	}
}

func TestPIIAccessDenied(t *testing.T) {
	p := pol(nil, boolPtr(false), nil, nil)
	if err := Evaluate(p, map[string]interface{}{"pii_access": true}); err == nil {
		t.Error("expected PII access error, got nil")
	}
}

func TestPIIAccessAllowedWhenFalse(t *testing.T) {
	p := pol(nil, boolPtr(false), nil, nil)
	if err := Evaluate(p, map[string]interface{}{"pii_access": false}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWriteAccessDenied(t *testing.T) {
	p := pol(nil, nil, boolPtr(false), nil)
	if err := Evaluate(p, map[string]interface{}{"write_access": true}); err == nil {
		t.Error("expected write access error, got nil")
	}
}

func TestToolInAllowlistPasses(t *testing.T) {
	p := pol(nil, nil, nil, []string{"web_search", "file_read"})
	if err := Evaluate(p, map[string]interface{}{"tool": "web_search"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestToolNotInAllowlistFails(t *testing.T) {
	p := pol(nil, nil, nil, []string{"web_search"})
	if err := Evaluate(p, map[string]interface{}{"tool": "delete_database"}); err == nil {
		t.Error("expected tool allowlist error, got nil")
	}
}

func TestWildcardToolAllowsAny(t *testing.T) {
	p := pol(nil, nil, nil, []string{"*"})
	if err := Evaluate(p, map[string]interface{}{"tool": "anything_at_all"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoToolArgSkipsCheck(t *testing.T) {
	p := pol(nil, nil, nil, []string{"web_search"})
	if err := Evaluate(p, map[string]interface{}{"query": "hello"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── CheckAttenuation ─────────────────────────────────────────────────────────

func TestIdenticalPoliciesPassAttenuation(t *testing.T) {
	p := pol(f64Ptr(10.0), boolPtr(false), boolPtr(false), []string{"web_search"})
	if err := CheckAttenuation(p, p); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCostEscalationFails(t *testing.T) {
	parent := pol(f64Ptr(10.0), nil, nil, nil)
	child := pol(f64Ptr(100.0), nil, nil, nil)
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected cost escalation error, got nil")
	}
}

func TestCostReductionPasses(t *testing.T) {
	parent := pol(f64Ptr(100.0), nil, nil, nil)
	child := pol(f64Ptr(10.0), nil, nil, nil)
	if err := CheckAttenuation(parent, child); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPIIEscalationFails(t *testing.T) {
	parent := pol(nil, boolPtr(false), nil, nil)
	child := pol(nil, boolPtr(true), nil, nil)
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected PII escalation error, got nil")
	}
}

func TestWriteEscalationFails(t *testing.T) {
	parent := pol(nil, nil, boolPtr(false), nil)
	child := pol(nil, nil, boolPtr(true), nil)
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected write escalation error, got nil")
	}
}

func TestToolEscalationFails(t *testing.T) {
	parent := pol(nil, nil, nil, []string{"web_search"})
	child := pol(nil, nil, nil, []string{"web_search", "delete_db"})
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected tool escalation error, got nil")
	}
}

func TestToolSubsetPasses(t *testing.T) {
	parent := pol(nil, nil, nil, []string{"web_search", "file_read", "summarise"})
	child := pol(nil, nil, nil, []string{"web_search"})
	if err := CheckAttenuation(parent, child); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMaxCallsEscalationFails(t *testing.T) {
	parent := types.Policy{MaxCalls: u64Ptr(10)}
	child := types.Policy{MaxCalls: u64Ptr(100)}
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected max_calls escalation error, got nil")
	}
}

func TestMaxCallsReductionPasses(t *testing.T) {
	parent := types.Policy{MaxCalls: u64Ptr(100)}
	child := types.Policy{MaxCalls: u64Ptr(10)}
	if err := CheckAttenuation(parent, child); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestChildAddingExtraRestrictionPasses(t *testing.T) {
	parent := pol(f64Ptr(50.0), nil, nil, nil)
	child := pol(f64Ptr(10.0), boolPtr(false), nil, nil)
	if err := CheckAttenuation(parent, child); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ── Omission-as-escalation ────────────────────────────────────────────────────
// A child that silently drops a parent-defined constraint is broadening scope,
// which is an escalation. Each test below confirms that omitting a field the
// parent set is rejected — not silently permitted.

func TestCostOmissionIsEscalation(t *testing.T) {
	// Parent restricts cost; child provides no max_cost_usd → escalation.
	parent := pol(f64Ptr(10.0), nil, nil, nil)
	child := pol(nil, nil, nil, nil)
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected error when child omits max_cost_usd that parent restricts, got nil")
	}
}

func TestMaxCallsOmissionIsEscalation(t *testing.T) {
	// Parent restricts call count; child provides no max_calls → escalation.
	parent := types.Policy{MaxCalls: u64Ptr(5)}
	child := types.Policy{}
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected error when child omits max_calls that parent restricts, got nil")
	}
}

func TestAllowedToolsOmissionIsEscalation(t *testing.T) {
	// Parent permits only [web_search]; child with no allowed_tools implies all tools → escalation.
	parent := pol(nil, nil, nil, []string{"web_search"})
	child := pol(nil, nil, nil, nil)
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected error when child omits allowed_tools that parent restricts, got nil")
	}
}

func TestAllowedResourcesOmissionIsEscalation(t *testing.T) {
	// Parent restricts resources; child with no list implies all resources → escalation.
	parent := types.Policy{AllowedResources: []string{"mcp://tools/web_search"}}
	child := types.Policy{}
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected error when child omits allowed_resources that parent restricts, got nil")
	}
}

func TestAllowedDataClassesOmissionIsEscalation(t *testing.T) {
	// Parent restricts data classes; child with no list implies all classes → escalation.
	parent := types.Policy{AllowedDataClasses: []string{"public"}}
	child := types.Policy{}
	if err := CheckAttenuation(parent, child); err == nil {
		t.Error("expected error when child omits allowed_data_classes that parent restricts, got nil")
	}
}
