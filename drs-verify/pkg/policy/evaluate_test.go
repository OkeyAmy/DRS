package policy

import (
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
