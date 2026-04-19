package types

import (
	"encoding/json"
	"testing"
)

func TestVerificationResultStoreWarningsOmitEmpty(t *testing.T) {
	r := VerificationResult{Valid: true}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) == "" {
		t.Fatal("empty marshal")
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["store_warnings"]; ok {
		t.Error("store_warnings must be omitted when nil")
	}
}

func TestVerificationResultStoreWarningsPresent(t *testing.T) {
	r := VerificationResult{
		Valid:         true,
		StoreWarnings: []string{"receipt sha256:abc could not be persisted: disk full"},
	}
	b, _ := json.Marshal(r)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if _, ok := m["store_warnings"]; !ok {
		t.Error("store_warnings must be present when non-nil")
	}
}

func TestDelegationReceiptCorrelationIDRoundTrip(t *testing.T) {
	id := "session:abc-123"
	dr := DelegationReceipt{
		Iss:           "did:key:z6Mk...",
		CorrelationID: &id,
	}
	b, err := json.Marshal(dr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if got, ok := m["correlation_id"]; !ok || got != id {
		t.Errorf("correlation_id: got %v, want %q", got, id)
	}
}

func TestDelegationReceiptCorrelationIDOmitEmpty(t *testing.T) {
	dr := DelegationReceipt{Iss: "did:key:z6Mk..."}
	b, _ := json.Marshal(dr)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if _, ok := m["correlation_id"]; ok {
		t.Error("correlation_id must be absent when nil")
	}
}

func TestDelegationReceiptBudgetRoundTrip(t *testing.T) {
	dr := DelegationReceipt{
		Iss:    "did:key:z6Mk...",
		Budget: json.RawMessage(`{"max_tokens":1000,"max_cost_usd":5.0}`),
	}
	b, err := json.Marshal(dr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if _, ok := m["budget"]; !ok {
		t.Error("budget must be present when non-nil")
	}
}

func TestInvocationReceiptCorrelationIDRoundTrip(t *testing.T) {
	id := "session:abc-123"
	ir := InvocationReceipt{
		Iss:           "did:key:z6Mk...",
		CorrelationID: &id,
	}
	b, _ := json.Marshal(ir)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	if got, ok := m["correlation_id"]; !ok || got != id {
		t.Errorf("InvocationReceipt correlation_id: got %v, want %q", got, id)
	}
}
