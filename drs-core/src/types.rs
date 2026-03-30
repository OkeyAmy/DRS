use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_access: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_access: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_resources: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_data_classes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub method: String,
    pub timestamp: String,
    pub session_id: String,
    pub policy_hash: String,
    pub locale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryMetadata {
    pub frameworks: Vec<String>,
    pub risk_level: String,
    pub retention_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationReceipt {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub drs_v: String,
    pub drs_type: String,
    pub cmd: String,
    pub policy: Policy,
    pub nbf: i64,
    /// `exp` is nullable for machine-rooted standing delegations
    /// (`drs_root_type == "automated-system"` with auto-renewal).
    /// When `None`, the delegation does not expire on its own.
    pub exp: Option<i64>,
    pub iat: i64,
    pub jti: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_dr_hash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub drs_consent: Option<ConsentRecord>,

    /// Root type: `"human"`, `"organisation"`, or `"automated-system"`.
    /// Determines trust model, renewal rules, and escalation path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drs_root_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub drs_regulatory: Option<RegulatoryMetadata>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub drs_status_list_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationReceipt {
    pub iss: String,
    pub sub: String,
    pub drs_v: String,
    pub drs_type: String,
    pub cmd: String,
    pub args: serde_json::Value,
    pub dr_chain: Vec<String>,
    pub tool_server: String,
    pub iat: i64,
    pub jti: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_hash: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evaluation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBundle {
    pub bundle_version: String,
    pub invocation: String,
    pub receipts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationContext {
    pub root_principal: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_record: Option<ConsentRecord>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub regulatory: Option<RegulatoryMetadata>,

    pub leaf_policy: Policy,
    pub chain_depth: usize,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationError {
    pub code: String,
    pub message: String,
    pub suggestion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<VerificationContext>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<VerificationError>,
}

impl VerificationResult {
    pub fn valid(context: VerificationContext) -> Self {
        Self { valid: true, context: Some(context), error: None }
    }

    pub fn invalid(code: &str, message: impl Into<String>, suggestion: impl Into<String>) -> Self {
        Self {
            valid: false,
            context: None,
            error: Some(VerificationError {
                code: code.to_string(),
                message: message.into(),
                suggestion: suggestion.into(),
            }),
        }
    }
}
