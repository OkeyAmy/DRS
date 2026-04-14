/**
 * Machine-to-machine operator configuration for DRS 4.0.
 *
 * Human-rooted delegations require per-session consent from a live human.
 * Machine-rooted deployments use an OperatorConfig loaded once at startup
 * that governs auto-renewal, escalation paths, and storage tier.
 */

import type { Policy } from "./types.js";
import { DrsError } from "./types.js";

/** Valid values for drs_root_type. */
export type DrsRootType = "human" | "organisation" | "automated-system";

export interface RenewalRules {
  /** Enable automatic session renewal before the current delegation expires. */
  auto_renew: boolean;
  /** Validity window in hours for each session delegation. */
  session_ttl_hours: number;
  /** Max number of automatic renewals per session. 0 = unlimited. */
  max_renewal_count: number;
}

export interface Escalation {
  /** Who must approve out-of-policy requests: "human" or "organisation". */
  target_type: string;
  /** DID of the supervisor that receives escalation notifications. */
  supervisor_did: string;
  /** What to do if the supervisor does not respond: "deny" | "allow-degraded". */
  fallback: "deny" | "allow-degraded";
}

export interface OperatorConfig {
  /** Trust anchor type. Must be "organisation" or "automated-system" for operators. */
  drs_root_type: Exclude<DrsRootType, "human">;
  /** DID of the machine/organisation issuing root delegations. */
  operator_did: string;
  /** Key management backend: "file" | "env" | "aws-kms" | "gcp-kms". */
  operator_key_management: string;
  /** Path to the raw 32-byte Ed25519 signing key (required when key_management is "file"). */
  operator_key_path?: string;
  /** Capability constraint applied to all root delegations from this operator. */
  standing_policy: Policy;
  /** Rules governing automatic session renewal. */
  renewal_rules: RenewalRules;
  /** Escalation path for out-of-policy requests. */
  escalation: Escalation;
  /** DR Store tier: 0=Session(memory), 1=Ephemeral(filesystem), 2=Durable(S3), 3=Compliant(WORM+RFC3161), 4=Timestamped(Tier3+TSToken), 5=On-Chain(Ethereum). See docs/storage-tiers.md. */
  storage_tier: 0 | 1 | 2 | 3 | 4 | 5;
}

/**
 * Validates an OperatorConfig object.
 * Throws DrsError with code INVALID_OPERATOR_CONFIG if any field is invalid.
 */
export function validateOperatorConfig(cfg: OperatorConfig): void {
  if (cfg.drs_root_type !== "organisation" && cfg.drs_root_type !== "automated-system") {
    throw new DrsError(
      "INVALID_OPERATOR_CONFIG",
      `drs_root_type must be 'organisation' or 'automated-system', got '${cfg.drs_root_type}'.`,
    );
  }
  if (!cfg.operator_did) {
    throw new DrsError("INVALID_OPERATOR_CONFIG", "operator_did must not be empty.");
  }
  if (!cfg.operator_key_management) {
    throw new DrsError("INVALID_OPERATOR_CONFIG", "operator_key_management must not be empty.");
  }
  if (cfg.operator_key_management === "file" && !cfg.operator_key_path) {
    throw new DrsError(
      "INVALID_OPERATOR_CONFIG",
      "operator_key_path is required when operator_key_management is 'file'.",
    );
  }
  if (cfg.renewal_rules.session_ttl_hours < 0) {
    throw new DrsError("INVALID_OPERATOR_CONFIG", "session_ttl_hours must be >= 0.");
  }
  if (![0, 1, 2, 3, 4, 5].includes(cfg.storage_tier)) {
    throw new DrsError("INVALID_OPERATOR_CONFIG", `storage_tier must be 0–5, got ${cfg.storage_tier}.`);
  }
}

/**
 * Parses and validates an OperatorConfig from a plain JSON object.
 * Throws DrsError if the object is missing required fields or contains invalid values.
 */
export function parseOperatorConfig(raw: unknown): OperatorConfig {
  if (typeof raw !== "object" || raw === null) {
    throw new DrsError("INVALID_OPERATOR_CONFIG", "Operator config must be a JSON object.");
  }

  // Cast with partial checking — validateOperatorConfig will catch missing fields
  const cfg = raw as OperatorConfig;
  validateOperatorConfig(cfg);
  return cfg;
}
