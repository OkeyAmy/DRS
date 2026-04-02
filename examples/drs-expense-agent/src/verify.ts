/**
 * Shared verification result printer.
 *
 * Used by the expense tool server to display drs-verify results for each
 * incoming bundle. The tool server calls drs-verify (the Go service) and
 * then calls printVerificationResult to show what happened.
 */

import type { VerificationResult } from "@okeyamy/drs-sdk";

/**
 * Prints a structured VerificationResult to stdout.
 *
 * @param toolName - The tool name (for console labelling only)
 * @param result   - The VerificationResult returned by drs-verify
 */
export function printVerificationResult(
  toolName: string,
  result: VerificationResult,
): void {
  if (result.valid && result.context) {
    const ctx = result.context;
    console.log(`  [DRS] ✓ VALID — ${toolName}`);
    console.log(`        root_principal : ${ctx.root_principal}`);
    console.log(`        root_type      : ${ctx.root_type ?? "n/a"}`);
    console.log(`        chain_depth    : ${ctx.chain_depth}`);
    if (ctx.leaf_policy.allowed_tools !== undefined) {
      console.log(
        `        allowed_tools  : ${ctx.leaf_policy.allowed_tools.join(", ")}`,
      );
    }
    if (ctx.consent_record) {
      console.log(
        `        consent        : session=${ctx.consent_record.session_id} method=${ctx.consent_record.method}`,
      );
    }
  } else if (result.error) {
    console.log(`  [DRS] ✗ INVALID — ${toolName}`);
    console.log(`        code       : ${result.error.code}`);
    console.log(`        message    : ${result.error.message}`);
    console.log(`        suggestion : ${result.error.suggestion}`);
  }
}
