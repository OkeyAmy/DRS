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
