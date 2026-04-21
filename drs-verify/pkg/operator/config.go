// Package operator provides the machine-to-machine operator configuration
// for automated-system and organisation-rooted DRS deployments.
//
// Human-rooted delegations require per-session consent from a live human.
// Machine-rooted delegations use a standing OperatorConfig loaded once at
// startup that governs auto-renewal, escalation paths, and storage tier.
package operator

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/drs-protocol/drs-verify/pkg/types"
)

// ValidRootTypes lists the accepted values for DrsRootType.
var ValidRootTypes = map[string]bool{
	"human":            true,
	"organisation":     true,
	"automated-system": true,
}

// ValidKeyManagements lists the implemented key-management backends.
// "aws-kms" and "gcp-kms" are planned but not yet implemented — they are
// intentionally absent so the validator fails fast instead of silently
// accepting a config that cannot actually load a key at runtime.
var ValidKeyManagements = map[string]bool{
	"file": true,
	"env":  true,
}

// ImplementedStorageTiers lists the storage tiers that have a working runtime
// implementation. Tiers 2 (S3/durable) and 5 (on-chain/Ethereum) are roadmap
// items — accepting them would let the server start and then fail at first use.
var ImplementedStorageTiers = map[int]bool{
	0: true, // session (memory)
	1: true, // ephemeral (filesystem)
	3: true, // compliant (WORM + RFC 3161)
	4: true, // timestamped (per-DR TSToken)
}

// OperatorConfig holds the runtime configuration for a machine-rooted DRS deployment.
// It is loaded from a JSON file whose path is given by the DRS_OPERATOR_CONFIG env var,
// or built programmatically for testing.
type OperatorConfig struct {
	// DrsRootType identifies the trust anchor type. Must be "organisation" or
	// "automated-system" for operator-managed deployments.
	DrsRootType string `json:"drs_root_type"`

	// OperatorDID is the DID of the machine/organisation issuing root delegations.
	OperatorDID string `json:"operator_did"`

	// OperatorKeyPath is the path to the raw 32-byte Ed25519 signing key file.
	// If blank, OperatorKeyManagement must be set to an external KMS provider.
	OperatorKeyPath string `json:"operator_key_path,omitempty"`

	// OperatorKeyManagement identifies the key management backend.
	// Implemented values: "file", "env".
	// Planned (not yet available): "aws-kms", "gcp-kms".
	OperatorKeyManagement string `json:"operator_key_management"`

	// StandingPolicy is the capability constraint applied to all root delegations
	// issued by this operator. Agent sub-delegations may only attenuate this.
	StandingPolicy types.Policy `json:"standing_policy"`

	// RenewalRules governs automatic session renewal for standing delegations.
	RenewalRules RenewalRules `json:"renewal_rules"`

	// Escalation defines what happens when an agent requests capabilities
	// beyond the StandingPolicy.
	Escalation Escalation `json:"escalation"`

	// StorageTier selects the DR Store tier for receipts issued by this operator.
	// Implemented: 0 = session (memory), 1 = ephemeral (filesystem),
	//              3 = compliant (WORM + RFC 3161), 4 = timestamped (per-DR TSToken).
	// Roadmap (not yet available): 2 = durable (S3), 5 = on-chain (Ethereum).
	StorageTier int `json:"storage_tier"`
}

// RenewalRules controls how the operator runtime handles session TTL and renewal.
type RenewalRules struct {
	// AutoRenew enables automatic issuance of a new root delegation before
	// the current one expires. Only valid when DrsRootType is "automated-system".
	AutoRenew bool `json:"auto_renew"`

	// SessionTTLHours is the validity window for each session delegation.
	// Ignored when AutoRenew is false.
	SessionTTLHours int `json:"session_ttl_hours"`

	// MaxRenewalCount caps the number of automatic renewals per session.
	// 0 means unlimited. Used to prevent runaway agent loops.
	MaxRenewalCount int `json:"max_renewal_count"`
}

// Escalation defines the fallback path when an agent requests out-of-policy capabilities.
type Escalation struct {
	// TargetType is "human" or "organisation" — who must approve the escalation.
	TargetType string `json:"target_type"`

	// SupervisorDID is the DID that should receive the escalation notification.
	SupervisorDID string `json:"supervisor_did"`

	// Fallback is the action taken if the supervisor does not respond.
	// Supported values: "deny", "allow-degraded".
	Fallback string `json:"fallback"`
}

// Validate returns an error if the config contains invalid or missing fields.
func (c *OperatorConfig) Validate() error {
	if !ValidRootTypes[c.DrsRootType] {
		return fmt.Errorf("operator: invalid drs_root_type %q (must be human, organisation, or automated-system)", c.DrsRootType)
	}
	if c.DrsRootType == "human" {
		return fmt.Errorf("operator: drs_root_type 'human' is not valid for operator configs — use per-session consent instead")
	}
	if c.OperatorDID == "" {
		return fmt.Errorf("operator: operator_did must not be empty")
	}
	if c.OperatorKeyManagement == "" {
		return fmt.Errorf("operator: operator_key_management must not be empty")
	}
	if !ValidKeyManagements[c.OperatorKeyManagement] {
		return fmt.Errorf("operator: operator_key_management %q is not implemented; supported values are \"file\" and \"env\" (\"aws-kms\" and \"gcp-kms\" are planned but not yet available)", c.OperatorKeyManagement)
	}
	if c.OperatorKeyManagement == "file" && c.OperatorKeyPath == "" {
		return fmt.Errorf("operator: operator_key_path is required when key_management is 'file'")
	}
	if c.RenewalRules.SessionTTLHours < 0 {
		return fmt.Errorf("operator: session_ttl_hours must be >= 0")
	}
	if !ImplementedStorageTiers[c.StorageTier] {
		return fmt.Errorf("operator: storage_tier %d is not implemented (implemented tiers: 0, 1, 3, 4 — tiers 2 and 5 are roadmap)", c.StorageTier)
	}
	return nil
}

// LoadFromFile parses and validates an OperatorConfig from a JSON file.
func LoadFromFile(path string) (*OperatorConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("operator: reading config file: %w", err)
	}
	var cfg OperatorConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("operator: parsing config JSON: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadFromEnv loads the config file path from the DRS_OPERATOR_CONFIG environment
// variable and delegates to LoadFromFile. Returns nil without error if the variable
// is not set (no operator config is required for human-rooted deployments).
func LoadFromEnv() (*OperatorConfig, error) {
	path := os.Getenv("DRS_OPERATOR_CONFIG")
	if path == "" {
		return nil, nil
	}
	return LoadFromFile(path)
}
