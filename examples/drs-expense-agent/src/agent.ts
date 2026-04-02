/**
 * Gemini-powered expense agent with DRS integration.
 *
 * For every tool call Gemini requests, the agent:
 *
 *   1. Issues a DRS invocation receipt (signed JWT) recording:
 *      - which tool was called (args["tool"])
 *      - the call arguments
 *      - the delegation chain reference (dr_chain)
 *   2. Builds a ChainBundle: { receipts: [rootDelegation], invocation }
 *   3. Serialises the bundle to base64url
 *   4. Sends an HTTP POST to the expense tool server:
 *        POST http://localhost:3001/mcp/tools/call
 *        X-DRS-Bundle: <base64url bundle>
 *        Content-Type: application/json
 *        { "tool": "<name>", ...args }
 *   5. The tool server calls drs-verify before executing.
 *      If drs-verify returns VALID → tool executes, 200 returned.
 *      If drs-verify returns INVALID → tool server returns 403, no execution.
 *   6. The response (success or 403 error) is returned to Gemini.
 *
 * Policy enforcement happens entirely inside the Go verifier at Block D1.
 * The agent does not self-enforce anything — it just records what it intends
 * to do in the invocation receipt and lets the tool server decide.
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import type { FunctionDeclaration, Part, Tool } from "@google/generative-ai";
import {
  issueInvocation,
  computeChainHash,
  buildBundle,
  serialiseBundle,
} from "@okeyamy/drs-sdk";
import type { DrsKeypair } from "./keys.js";

const TOOL_SERVER_URL =
  process.env.TOOL_SERVER_URL ?? "http://localhost:3001";

/**
 * Runs the Gemini expense agent for one full session.
 * Issues one DRS invocation receipt per tool call, sends each as an
 * X-DRS-Bundle HTTP header to the expense tool server.
 *
 * @param agent          - The agent's keypair (signs invocation receipts)
 * @param amaraDid       - Amara's DID (sub in every invocation receipt)
 * @param toolServerDid  - The tool server's DID (tool_server field)
 * @param rootDelegation - The signed root delegation JWT (Amara → Agent)
 */
export async function runExpenseAgent(
  agent: DrsKeypair,
  amaraDid: string,
  toolServerDid: string,
  rootDelegation: string,
): Promise<void> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("GEMINI_API_KEY environment variable is not set.");
  }

  const genAI = new GoogleGenerativeAI(apiKey);
  const model = genAI.getGenerativeModel({
    model: "gemini-2.5-flash",
    tools: [EXPENSE_TOOLS],
  });

  const initialPrompt = `You are a financial assistant processing company expense reports.

Your tasks (in order):
1. Call read_expenses to load all current transactions from the expense file.
2. For each transaction whose category is "uncategorized", call categorize_transaction and set one of: infrastructure, api-services, development, consulting, or other.
3. For every transaction returned by read_expenses, call approve_payment to submit a payment approval (ensure the delegation permits approvals).

Important rules:
- Process all five transactions; do not skip any.
- Use the exact function names and parameter names defined in the tool declarations.
- Each tool invocation must be a single, well-formed function call (no free-text responses).
`;

  console.log("[Gemini] Starting expense processing session...\n");

  const chat = model.startChat();
  let response = await chat.sendMessage(initialPrompt);

  // Agentic loop: keep processing function calls until Gemini gives final text
  while (true) {
    const candidate = response.response.candidates?.[0];
    if (!candidate) break;

    const functionCallParts = candidate.content.parts.filter(
      (p: Part) => "functionCall" in p && p.functionCall !== undefined,
    );

    if (functionCallParts.length === 0) {
      // No more function calls — Gemini has finished
      const text = response.response.text();
      if (text) {
        console.log("\n[Gemini] Session summary:");
        console.log(text);
      }
      break;
    }

    const functionResponseParts: Part[] = [];

    for (const part of functionCallParts) {
      const fc = (
        part as {
          functionCall: { name: string; args: Record<string, unknown> };
        }
      ).functionCall;
      const { name, args } = fc;

      console.log(`\n[Gemini → Tool Server] ${name}(${JSON.stringify(args)})`);

      // Issue a DRS invocation receipt for this specific tool call.
      // args["tool"] is the field drs-verify Block D1 checks against
      // policy.allowed_tools. If it is not permitted, the tool server
      // returns 403 without executing the tool.
      const drChain = [computeChainHash(rootDelegation)];
      const invocationJwt = await issueInvocation({
        signingKey: agent.privateKey,
        issuerDid: agent.did,
        subjectDid: amaraDid,
        cmd: "/mcp/tools/call",
        args: { tool: name, ...args },
        drChain,
        toolServer: toolServerDid,
      });

      // Build and serialise the ChainBundle for the X-DRS-Bundle header
      const bundle = buildBundle([rootDelegation], invocationJwt);
      const bundleHeader = serialiseBundle(bundle);

      // POST to the tool server — it verifies the bundle before executing
      const toolResult = await callToolServer(name, args, bundleHeader);
      console.log(`[Tool Server] ${JSON.stringify(toolResult)}`);

      functionResponseParts.push({
        functionResponse: {
          name,
          response:
            typeof toolResult === "object" && toolResult !== null
              ? (toolResult as Record<string, unknown>)
              : { result: String(toolResult) },
        },
      } as Part);
    }

    // Return all tool results to Gemini so it can continue reasoning
    response = await chat.sendMessage(functionResponseParts);
  }
}

/**
 * Sends one tool call to the expense tool server.
 *
 * The X-DRS-Bundle header carries the full ChainBundle. The server verifies
 * it against drs-verify before the tool executes. A 403 means the bundle
 * was rejected (POLICY_VIOLATION, INVALID_SIGNATURE, etc.).
 */
async function callToolServer(
  toolName: string,
  args: Record<string, unknown>,
  bundleHeader: string,
): Promise<unknown> {
  const res = await fetch(`${TOOL_SERVER_URL}/mcp/tools/call`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-DRS-Bundle": bundleHeader,
    },
    body: JSON.stringify({ tool: toolName, ...args }),
  });

  // Both 200 and 403 return JSON. Return the body either way so Gemini
  // can see the error and understand what happened.
  return res.json() as Promise<unknown>;
}

/**
 * Gemini function declarations for the three expense tools.
 * These tell Gemini what functions are available and how to call them.
 */
const EXPENSE_TOOLS: Tool = {
  functionDeclarations: [
    {
      name: "read_expenses",
      description:
        "Reads all current expense records from the expense report file. Call this first to load the data.",
      parameters: {
        type: "object" as const,
        properties: {},
        required: [],
      },
    } as FunctionDeclaration,
    {
      name: "categorize_transaction",
      description:
        "Assigns a spending category to a specific expense transaction. Valid categories: infrastructure, api-services, development, consulting, other.",
      parameters: {
        type: "object" as const,
        properties: {
          transaction_id: {
            type: "string" as const,
            description: "The transaction ID to categorize (e.g. TXN-001)",
          },
          category: {
            type: "string" as const,
            description:
              "The category: infrastructure, api-services, development, consulting, or other",
          },
        },
        required: ["transaction_id", "category"],
      },
    } as FunctionDeclaration,
    {
      name: "approve_payment",
      description:
        "Submits a payment approval request for a transaction. Note: this tool requires explicit payment authorization in the delegation — read-only sessions will receive a DRS policy violation.",
      parameters: {
        type: "object" as const,
        properties: {
          transaction_id: {
            type: "string" as const,
            description: "The transaction ID to approve (e.g. TXN-001)",
          },
        },
        required: ["transaction_id"],
      },
    } as FunctionDeclaration,
  ],
};
