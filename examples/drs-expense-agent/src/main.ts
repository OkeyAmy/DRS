/**
 * DRS Expense Agent — Entry Point
 *
 * What this demo shows:
 *
 * 1. Amara generates a real Ed25519 keypair and derives her did:key
 * 2. The agent and tool server each generate their own keypair
 * 3. Amara issues a root delegation receipt (signed JWT) granting the agent
 *    permission to call two tools:
 *      allowed_tools: ["read_expenses", "categorize_transaction"]
 *    Payment approval is intentionally excluded from this delegation.
 * 4. The expense tool server starts on :3001. It verifies every X-DRS-Bundle
 *    header before executing any tool — this is the DRS trust boundary.
 * 5. The Gemini agent calls tools via HTTP. For every call:
 *      a. Issues a signed DRS invocation receipt recording the tool name
 *      b. Builds a ChainBundle (delegation + invocation)
 *      c. Sends X-DRS-Bundle header to the tool server
 *      d. Tool server calls drs-verify (Block A–F) before executing
 * 6. read_expenses and categorize_transaction pass — they are in allowed_tools.
 *    Every approve_payment call is rejected with POLICY_VIOLATION because
 *    "approve_payment" is not in the delegation's allowed_tools list.
 *
 * Architecture:
 *
 *   Amara (did:key)  →  signs Root DR  →  Agent (did:key)
 *                                              │
 *                    For each Gemini tool call:│
 *                                              ▼
 *                              Agent issues Invocation Receipt
 *                              Agent builds ChainBundle
 *                              Agent sends HTTP POST:
 *                                POST /mcp/tools/call
 *                                X-DRS-Bundle: base64url(bundle)
 *                                              │
 *                                              ▼
 *                              Expense Tool Server (:3001)
 *                              ├── calls POST /verify → drs-verify (:8080)
 *                              ├── VALID  → executes tool, returns 200
 *                              └── INVALID → returns 403 (no execution)
 *
 * Setup:
 *   cp .env.example .env    # add your GEMINI_API_KEY
 *   docker-compose up -d    # starts drs-verify on :8080
 *   pnpm install
 *   pnpm start
 */

import { config } from "dotenv";
config();

import { randomUUID } from "node:crypto";
import { generateKeypair } from "./keys.js";
import {
  issueAgentDelegation,
  describePolicy,
  DELEGATION_POLICY,
} from "./delegation.js";
import { startToolServer } from "./tool-server.js";
import { runExpenseAgent } from "./agent.js";

const TOOL_SERVER_PORT = parseInt(
  process.env.TOOL_SERVER_PORT ?? "3001",
  10,
);

async function main(): Promise<void> {
  console.log(
    "╔══════════════════════════════════════════════════════════╗",
  );
  console.log(
    "║         DRS Expense Agent — Live Demo                    ║",
  );
  console.log(
    "║  Delegation Receipt Standard + Gemini Function Calling   ║",
  );
  console.log(
    "╚══════════════════════════════════════════════════════════╝",
  );
  console.log();

  // ── Step 1: Generate keypairs ─────────────────────────────────────────────
  console.log("[DRS] Generating Ed25519 keypairs...");
  const amara = generateKeypair();
  const agent = generateKeypair();
  const toolServer = generateKeypair();
  console.log(`  Amara (human)  : ${amara.did}`);
  console.log(`  Agent          : ${agent.did}`);
  console.log(`  Tool Server    : ${toolServer.did}`);

  // ── Step 2: Issue root delegation receipt ─────────────────────────────────
  //
  // Amara signs a JWT that says:
  //   "I, Amara, authorise this agent to call /mcp/tools/call
  //    but only for tools: read_expenses, categorize_transaction."
  //
  // The consent record records how Amara gave this authorisation (explicit
  // click in the UI), which session it belongs to, and a hash of the policy
  // she agreed to. This is the evidence chain for regulatory audits.
  const sessionId = randomUUID();
  console.log();
  console.log("[DRS] Issuing root delegation receipt (Amara → Agent)...");
  console.log(`  Session ID : ${sessionId}`);
  console.log(`  Command    : /mcp/tools/call`);
  console.log(`  Policy     :`);
  describePolicy()
    .split("\n")
    .forEach((line) => console.log(`    ${line}`));

  const rootDelegation = await issueAgentDelegation(amara, agent, sessionId);
  console.log(`  JWT issued ✓  (${rootDelegation.length} chars, EdDSA/Ed25519)`);
  console.log();

  // ── Step 3: Start the expense tool server ────────────────────────────────
  //
  // The tool server is the DRS enforcement point. It accepts
  // POST /mcp/tools/call requests from the agent and verifies the
  // X-DRS-Bundle header before executing any tool. Tools never run
  // without a valid delegation chain.
  console.log(`[Tool Server] Starting on :${TOOL_SERVER_PORT}...`);
  const server = await startToolServer(TOOL_SERVER_PORT);
  console.log(
    `[Tool Server] Ready — POST /mcp/tools/call verifies X-DRS-Bundle before executing`,
  );
  console.log();

  // ── Step 4: Run the Gemini agent ─────────────────────────────────────────
  //
  // The agent issues one DRS invocation receipt per tool call and sends it
  // in the X-DRS-Bundle header. The tool server calls drs-verify (Go) to
  // check the full chain before executing.
  await runExpenseAgent(
    agent,
    amara.did,
    toolServer.did,
    rootDelegation,
  );

  console.log();
  console.log("[DRS] Demo complete.");
  console.log(
    "      The tool server verified every DRS bundle at POST /mcp/tools/call.",
  );
  console.log(
    `      Delegation policy: allowed_tools=${JSON.stringify(DELEGATION_POLICY.allowed_tools)}`,
  );
  console.log(
    "      approve_payment is not in allowed_tools → POLICY_VIOLATION on every approve_payment call.",
  );
  console.log(
    "      read_expenses and categorize_transaction are in allowed_tools → VALID.",
  );

  // Close the tool server so the process exits cleanly
  server.close();
  process.exit(0);
}

main().catch((err: unknown) => {
  console.error(
    "[FATAL]",
    err instanceof Error ? err.message : String(err),
  );
  process.exit(1);
});
