/**
 * TypeScript interfaces for DRS 4.0 data structures.
 * These mirror the Rust types in drs-core/src/types.rs and Go types in
 * drs-verify/pkg/types/types.go exactly. Field names are authoritative —
 * do not rename them.
 */

export interface Policy {
  max_cost_usd?: number;
  pii_access?: boolean;
  write_access?: boolean;
  max_calls?: number;
  allowed_tools?: string[];
  allowed_resources?: string[];
  allowed_data_classes?: string[];
}

export interface ConsentRecord {
  method: string;
  timestamp: string;
  session_id: string;
  policy_hash: string;
  locale: string;
}

export interface RegulatoryMetadata {
  frameworks: string[];
  risk_level: string;
  retention_days: number;
}

export interface DelegationReceiptPayload {
  iss: string;
  sub: string;
  aud: string;
  drs_v: "4.0";
  drs_type: "delegation-receipt";
  cmd: string;
  policy: Policy;
  nbf: number;
  exp: number | null;
  iat: number;
  jti: string;
  prev_dr_hash?: string;
  drs_consent?: ConsentRecord;
  drs_root_type?: "human" | "organisation" | "automated-system";
  drs_regulatory?: RegulatoryMetadata;
  drs_status_list_index?: number;
}

export interface InvocationReceiptPayload {
  iss: string;
  sub: string;
  drs_v: "4.0";
  drs_type: "invocation-receipt";
  cmd: string;
  args: Record<string, unknown>;
  dr_chain: string[];
  tool_server: string;
  iat: number;
  jti: string;
  result_hash?: string;
  policy_evaluation?: string;
}

export interface ChainBundle {
  bundle_version: "4.0";
  invocation: string;
  receipts: string[];
}

export interface VerificationContext {
  root_principal: string;
  root_type?: string;
  consent_record?: ConsentRecord;
  regulatory?: RegulatoryMetadata;
  leaf_policy: Policy;
  chain_depth: number;
  session_id?: string;
}

export interface VerificationError {
  code: string;
  message: string;
  suggestion: string;
}

export interface VerificationResult {
  valid: boolean;
  context?: VerificationContext;
  error?: VerificationError;
}

/** Typed error class for DRS SDK operations. */
export class DrsError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "DrsError";
  }
}
