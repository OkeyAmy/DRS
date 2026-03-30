// Package types defines the Go structs that mirror the DRS JSON schema.
// Field names and JSON tags must exactly match the Rust types in drs-core/src/types.rs.
package types

// Policy represents capability constraints attached to a delegation receipt.
type Policy struct {
	MaxCostUSD       *float64 `json:"max_cost_usd,omitempty"`
	PIIAccess        *bool    `json:"pii_access,omitempty"`
	WriteAccess      *bool    `json:"write_access,omitempty"`
	MaxCalls         *uint64  `json:"max_calls,omitempty"`
	AllowedTools     []string `json:"allowed_tools,omitempty"`
	AllowedResources []string `json:"allowed_resources,omitempty"`
	AllowedDataClasses []string `json:"allowed_data_classes,omitempty"`
}

// ConsentRecord captures evidence of explicit human consent.
type ConsentRecord struct {
	Method     string `json:"method"`
	Timestamp  string `json:"timestamp"`
	SessionID  string `json:"session_id"`
	PolicyHash string `json:"policy_hash"`
	Locale     string `json:"locale"`
}

// RegulatoryMetadata carries compliance annotation for auditors.
type RegulatoryMetadata struct {
	Frameworks    []string `json:"frameworks"`
	RiskLevel     string   `json:"risk_level"`
	RetentionDays uint64   `json:"retention_days"`
}

// DelegationReceipt is a signed JWT payload representing one hop in a chain.
type DelegationReceipt struct {
	Iss     string `json:"iss"`
	Sub     string `json:"sub"`
	Aud     string `json:"aud"`
	DrsV    string `json:"drs_v"`
	DrsType string `json:"drs_type"`
	Cmd     string `json:"cmd"`
	Policy  Policy `json:"policy"`
	Nbf     int64  `json:"nbf"`
	Exp     *int64 `json:"exp"`
	Iat     int64  `json:"iat"`
	Jti     string `json:"jti"`

	PrevDRHash         *string             `json:"prev_dr_hash,omitempty"`
	DrsConsent         *ConsentRecord      `json:"drs_consent,omitempty"`
	DrsRootType        *string             `json:"drs_root_type,omitempty"`
	DrsRegulatory      *RegulatoryMetadata `json:"drs_regulatory,omitempty"`
	DrsStatusListIndex *uint64             `json:"drs_status_list_index,omitempty"`
}

// InvocationReceipt is a signed JWT payload representing the agent's action.
type InvocationReceipt struct {
	Iss        string                 `json:"iss"`
	Sub        string                 `json:"sub"`
	DrsV       string                 `json:"drs_v"`
	DrsType    string                 `json:"drs_type"`
	Cmd        string                 `json:"cmd"`
	Args       map[string]interface{} `json:"args"`
	DrChain    []string               `json:"dr_chain"`
	ToolServer string                 `json:"tool_server"`
	Iat        int64                  `json:"iat"`
	Jti        string                 `json:"jti"`

	ResultHash       *string `json:"result_hash,omitempty"`
	PolicyEvaluation *string `json:"policy_evaluation,omitempty"`
}

// ChainBundle is the input to the verifier — all JWTs in a delegation chain.
type ChainBundle struct {
	BundleVersion string   `json:"bundle_version"`
	Invocation    string   `json:"invocation"`
	Receipts      []string `json:"receipts"`
}

// VerificationContext is returned on successful verification.
type VerificationContext struct {
	RootPrincipal string              `json:"root_principal"`
	RootType      *string             `json:"root_type,omitempty"`
	ConsentRecord *ConsentRecord      `json:"consent_record,omitempty"`
	Regulatory    *RegulatoryMetadata `json:"regulatory,omitempty"`
	LeafPolicy    Policy              `json:"leaf_policy"`
	ChainDepth    int                 `json:"chain_depth"`
	SessionID     *string             `json:"session_id,omitempty"`
}

// VerificationError carries a machine-readable error code and human suggestion.
type VerificationError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion"`
}

// VerificationResult is always returned by verifyChain — never panics.
type VerificationResult struct {
	Valid    bool                 `json:"valid"`
	Context  *VerificationContext `json:"context,omitempty"`
	Error    *VerificationError   `json:"error,omitempty"`
}

// Valid constructs a successful VerificationResult.
func Valid(ctx VerificationContext) VerificationResult {
	return VerificationResult{Valid: true, Context: &ctx}
}

// Invalid constructs a failed VerificationResult.
func Invalid(code, message, suggestion string) VerificationResult {
	return VerificationResult{
		Valid: false,
		Error: &VerificationError{Code: code, Message: message, Suggestion: suggestion},
	}
}
