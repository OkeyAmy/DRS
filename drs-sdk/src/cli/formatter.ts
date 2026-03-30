/**
 * CLI output formatting utilities.
 * Keeps display logic out of command handlers.
 */

import type { VerificationResult } from "../sdk/types.js";

export const formatter = {
  usage(): string {
    return [
      "Usage: drs <command> [args]",
      "",
      "Commands:",
      "  verify   <bundle.json>    Verify a chain bundle against drs-verify",
      "  policy   <receipt.json>   Display the policy from a delegation receipt",
      "  translate <policy.json>   Translate a policy to plain English",
      "  audit    <bundle.json>    Print a full audit trail for a bundle",
      "  keygen                    Generate a new Ed25519 keypair",
    ].join("\n");
  },

  verificationResult(result: VerificationResult): string {
    if (result.valid) {
      const ctx = result.context!;
      return [
        "✓ Chain verified",
        `  Root principal : ${ctx.root_principal}`,
        `  Chain depth    : ${ctx.chain_depth}`,
        ...(ctx.root_type ? [`  Root type      : ${ctx.root_type}`] : []),
        ...(ctx.session_id ? [`  Session ID     : ${ctx.session_id}`] : []),
      ].join("\n");
    } else {
      const err = result.error!;
      return [
        "✗ Verification failed",
        `  Code       : ${err.code}`,
        `  Message    : ${err.message}`,
        `  Suggestion : ${err.suggestion}`,
      ].join("\n");
    }
  },
};
