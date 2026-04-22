/**
 * TypeScript interfaces for DRS 4.0 data structures.
 * These mirror the Rust types in drs-core/src/types.rs and Go types in
 * drs-verify/pkg/types/types.go exactly. Field names are authoritative —
 * do not rename them.
 */

/**
 * Capability constraints attached to a delegation receipt.
 *
 * `max_calls` is INFORMATIONAL ONLY — it is carried in the policy and validated
 * during attenuation checks (child ≤ parent), but is NOT enforced at runtime by
 * the stateless verifier. Enforcement requires session-aware call counting with
 * durable state and race-safe updates. Integrators who need call-count
 * enforcement must implement it in their own session layer and use `max_calls`
 * as the authoritative limit.
 */
export interface Policy {
  max_cost_usd?: number;
  pii_access?: boolean;
  write_access?: boolean;
  /** Informational only — not enforced at runtime. See Policy JSDoc. */
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

export interface TimestampResult {
  index: number;
  valid: boolean;
  /** RFC 3339 time from the TSA token; present on success. */
  time?: string;
  /** Error detail; present on failure. */
  error?: string;
}

/**
 * Result of the body↔invocation.args binding check on /verify.
 *
 * Only populated when the caller passed a `body` to `VerifyClient.verify`.
 * Undefined / absent when no body was sent.
 *
 * - "match"        — body JCS-equals invocation.args (bound to signed intent)
 * - "mismatch"     — chain valid but body diverges from signed args
 * - "invalid_body" — body present but not parseable as JSON
 * - "empty_match"  — both body and args empty (pkg/middleware path only)
 */
export type BindingResult = "match" | "mismatch" | "invalid_body" | "empty_match";

export interface VerificationResult {
  valid: boolean;
  context?: VerificationContext;
  error?: VerificationError;
  /** Per-receipt RFC 3161 timestamp verification results; present when include_timestamps was requested. */
  timestamps?: TimestampResult[];
  /**
   * Result of the optional body↔invocation.args binding check. Present only
   * when the caller passed a `body` to VerifyClient.verify; undefined
   * otherwise. `valid` remains cryptographic truth — the tool server
   * decides whether to reject on `binding === "mismatch"`.
   */
  binding?: BindingResult;
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
