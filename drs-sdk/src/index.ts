/**
 * @drs/sdk — Delegation Receipt Standard SDK, issuance path.
 *
 * Public API surface. Import from "@drs/sdk".
 */

// Types
export type {
  Policy,
  ConsentRecord,
  RegulatoryMetadata,
  DelegationReceiptPayload,
  InvocationReceiptPayload,
  ChainBundle,
  VerificationContext,
  VerificationError,
  VerificationResult,
} from "./sdk/types.js";
export { DrsError } from "./sdk/types.js";

// Issuance
export {
  issueRootDelegation,
  issueSubDelegation,
  issueInvocation,
  buildJwt,
  computeChainHash,
  derivePublicKey,
} from "./sdk/issue.js";
export type { RootDelegationParams, SubDelegationParams, InvocationParams } from "./sdk/issue.js";

// Bundle assembly
export { buildBundle, serialiseBundle, parseBundle } from "./sdk/bundle.js";

// JCS canonicalization
export { jcsSerialise } from "./sdk/jcs.js";

// Policy
export { checkPolicyAttenuation, translatePolicy } from "./sdk/policy.js";

// Verification client
export { VerifyClient } from "./verify/client.js";
export type { VerifyClientOptions } from "./verify/client.js";

// WASM loader
export { initWasm, getWasmModule, isWasmReady } from "./wasm/loader.js";

// Operator config (machine-to-machine trust model)
export { validateOperatorConfig, parseOperatorConfig } from "./sdk/operator.js";
export type { OperatorConfig, RenewalRules, Escalation, DrsRootType } from "./sdk/operator.js";
