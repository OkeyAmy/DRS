package operator_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/drs-protocol/drs-verify/pkg/operator"
	"github.com/drs-protocol/drs-verify/pkg/types"
)

func validConfig() operator.OperatorConfig {
	return operator.OperatorConfig{
		DrsRootType:           "automated-system",
		OperatorDID:           "did:key:z6Mkq1234",
		OperatorKeyManagement: "file",
		OperatorKeyPath:       "/secrets/operator.key",
		StandingPolicy: types.Policy{
			MaxCostUSD:  float64Ptr(10.0),
			WriteAccess: boolPtr(false),
		},
		RenewalRules: operator.RenewalRules{
			AutoRenew:       true,
			SessionTTLHours: 8,
			MaxRenewalCount: 3,
		},
		Escalation: operator.Escalation{
			TargetType:    "human",
			SupervisorDID: "did:key:zSupervisor",
			Fallback:      "deny",
		},
		StorageTier: 1,
	}
}

func TestValidConfigPasses(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid config failed validation: %v", err)
	}
}

func TestOrganisationRootTypeIsValid(t *testing.T) {
	cfg := validConfig()
	cfg.DrsRootType = "organisation"
	if err := cfg.Validate(); err != nil {
		t.Errorf("organisation root type should be valid: %v", err)
	}
}

func TestHumanRootTypeIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.DrsRootType = "human"
	if err := cfg.Validate(); err == nil {
		t.Error("human root type in operator config should be rejected")
	}
}

func TestUnknownRootTypeIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.DrsRootType = "service"
	if err := cfg.Validate(); err == nil {
		t.Error("unknown root type 'service' should be rejected")
	}
}

func TestMissingOperatorDIDIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.OperatorDID = ""
	if err := cfg.Validate(); err == nil {
		t.Error("empty operator_did should be rejected")
	}
}

func TestFileMgmtWithoutKeyPathIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.OperatorKeyPath = ""
	if err := cfg.Validate(); err == nil {
		t.Error("file key management without key path should be rejected")
	}
}

func TestInvalidStorageTierIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.StorageTier = 5
	if err := cfg.Validate(); err == nil {
		t.Error("storage_tier > 4 should be rejected")
	}
}

func TestLoadFromFile(t *testing.T) {
	cfg := validConfig()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	f, err := os.CreateTemp(t.TempDir(), "operator-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	f.Close()

	loaded, err := operator.LoadFromFile(f.Name())
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loaded.OperatorDID != cfg.OperatorDID {
		t.Errorf("operator_did mismatch: got %q, want %q", loaded.OperatorDID, cfg.OperatorDID)
	}
	if loaded.RenewalRules.SessionTTLHours != cfg.RenewalRules.SessionTTLHours {
		t.Errorf("session_ttl_hours mismatch: got %d, want %d",
			loaded.RenewalRules.SessionTTLHours, cfg.RenewalRules.SessionTTLHours)
	}
}

func TestLoadFromEnvReturnsNilWhenUnset(t *testing.T) {
	t.Setenv("DRS_OPERATOR_CONFIG", "")
	cfg, err := operator.LoadFromEnv()
	if err != nil {
		t.Errorf("LoadFromEnv with unset var should return nil error: %v", err)
	}
	if cfg != nil {
		t.Error("LoadFromEnv with unset var should return nil config")
	}
}

func float64Ptr(v float64) *float64 { return &v }
func boolPtr(v bool) *bool          { return &v }
