package operator_test

import (
	"encoding/json"
	"os"
	"strings"
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
	cfg.StorageTier = 6
	if err := cfg.Validate(); err == nil {
		t.Error("storage_tier 6 (above max) should be rejected")
	}
}

func TestImplementedStorageTiersAreAccepted(t *testing.T) {
	for _, tier := range []int{0, 1, 3, 4} {
		cfg := validConfig()
		cfg.StorageTier = tier
		if err := cfg.Validate(); err != nil {
			t.Errorf("tier %d: unexpected error: %v", tier, err)
		}
	}
}

func TestRoadmapStorageTiersAreRejected(t *testing.T) {
	for _, tier := range []int{2, 5} {
		cfg := validConfig()
		cfg.StorageTier = tier
		err := cfg.Validate()
		if err == nil {
			t.Errorf("tier %d (roadmap): expected error, got nil", tier)
			continue
		}
		if !strings.Contains(err.Error(), "roadmap") {
			t.Errorf("tier %d: error should mention roadmap, got: %v", tier, err)
		}
	}
}

func TestNegativeStorageTierIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.StorageTier = -1
	if err := cfg.Validate(); err == nil {
		t.Error("negative storage_tier should be rejected")
	}
}

func TestEnvKeyManagementIsAccepted(t *testing.T) {
	cfg := validConfig()
	cfg.OperatorKeyManagement = "env"
	cfg.OperatorKeyPath = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("env key management should be valid: %v", err)
	}
}

func TestAwsKmsIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.OperatorKeyManagement = "aws-kms"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("aws-kms should be rejected (not yet implemented)")
	}
	if !strings.Contains(err.Error(), "aws-kms") {
		t.Errorf("error should mention aws-kms, got: %v", err)
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error should say 'not implemented', got: %v", err)
	}
}

func TestGcpKmsIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.OperatorKeyManagement = "gcp-kms"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("gcp-kms should be rejected (not yet implemented)")
	}
	if !strings.Contains(err.Error(), "gcp-kms") {
		t.Errorf("error should mention gcp-kms, got: %v", err)
	}
}

func TestUnknownKeyManagementIsRejected(t *testing.T) {
	cfg := validConfig()
	cfg.OperatorKeyManagement = "vault"
	if err := cfg.Validate(); err == nil {
		t.Error("unknown key management backend should be rejected")
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
