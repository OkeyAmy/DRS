/**
 * Issues the root delegation receipt: Amara → ExpenseAgent.
 *
 * The delegation is a signed JWT (EdDSA/Ed25519) containing:
 * - iss: Amara's did:key
 * - aud: Agent's did:key
 * - cmd: "/mcp/tools/call"  ← the MCP command namespace
 * - policy: { allowed_tools: ["read_expenses", "categorize_transaction"] }
 * - drs_root_type: "human"
 * - drs_consent: real ConsentRecord with session_id and policy_hash
 *
 * Amara deliberately does NOT grant "approve_payment".
 * Payment approval requires a separate, explicit delegation — it is not
 * part of a routine read-and-categorize session.
 *
 * When the agent calls approve_payment, drs-verify Block D1 evaluates
 * invocation.args["tool"] against policy.allowed_tools and returns
 * POLICY_VIOLATION.
 */

import { issueRootDelegation, translatePolicy } from "@okeyamy/drs-sdk";
import type { Policy, ConsentRecord } from "@okeyamy/drs-sdk";
import { sha256 } from "@noble/hashes/sha256";
import type { DrsKeypair } from "./keys.js";

/**
 * The policy Amara grants to the expense agent.
 *
 * allowed_tools controls which tool names the agent may call.
 * drs-verify Block D1 checks: invocation.args["tool"] ∈ policy.allowed_tools.
 *
 * "approve_payment" is intentionally absent. The tool server will reject any
 * approve_payment call with POLICY_VIOLATION — exactly as designed.
 */
export const DELEGATION_POLICY: Policy = {
  allowed_tools: ["read_expenses", "categorize_transaction"],
};

/**
 * Issues a human-rooted delegation receipt from Amara to the expense agent.
 *
 * @param amara      - Amara's keypair (signs the JWT)
 * @param agent      - The agent's keypair (becomes the audience)
 * @param sessionId  - UUID identifying this consent session
 * @returns          - Signed JWT string
 */
export async function issueAgentDelegation(
  amara: DrsKeypair,
  agent: DrsKeypair,
  sessionId: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + 3600; // valid for 1 hour

  const consent: ConsentRecord = {
    method: "explicit-click",
    timestamp: new Date().toISOString(),
    session_id: sessionId,
    policy_hash: computePolicyHash(DELEGATION_POLICY),
    locale: "en-US",
  };

  return issueRootDelegation({
    signingKey: amara.privateKey,
    issuerDid: amara.did,
    subjectDid: amara.did, // Amara is the original resource owner
    audienceDid: agent.did,
    cmd: "/mcp/tools/call",
    policy: DELEGATION_POLICY,
    nbf: now,
    exp,
    rootType: "human",
    consent,
  });
}

/**
 * Returns a human-readable description of the delegation policy.
 * Uses translatePolicy() from the DRS SDK.
 */
export function describePolicy(): string {
  return translatePolicy(DELEGATION_POLICY);
}

/**
 * Computes SHA-256 of the JCS-serialized policy.
 * Returns "sha256:{hex}" — the format expected in ConsentRecord.policy_hash.
 */
function computePolicyHash(policy: Policy): string {
  const sorted = Object.fromEntries(
    Object.entries(policy as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    ),
  );
  const bytes = new TextEncoder().encode(JSON.stringify(sorted));
  const digest = sha256(bytes);
  const hex = Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}
