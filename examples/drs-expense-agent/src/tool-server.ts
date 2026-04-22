/**
 * Expense Tool Server — the DRS trust boundary.
 *
 * This is a plain Node.js HTTP server that exposes one endpoint:
 *
 *   POST /mcp/tools/call
 *
 * Every request MUST carry an X-DRS-Bundle header containing a base64url-
 * encoded ChainBundle (delegation receipts + invocation receipt). The server:
 *
 *   1. Parses the X-DRS-Bundle header into a ChainBundle
 *   2. POSTs the bundle + request body to drs-verify (the Go service) for
 *      six-block chain verification AND body↔invocation.args binding check
 *   3. If the bundle is VALID and binding is "match": executes the tool, 200
 *   4. If the bundle is INVALID: returns 403 with the VerificationError
 *   5. If binding is "mismatch": returns 403 BINDING_MISMATCH
 *
 * The tool code never runs until DRS says the invocation is authorised AND
 * the body matches what was signed. This is the correct DRS integration
 * pattern — verification happens at the tool server boundary, not inside
 * the agent, and the body must equal the signed intent.
 *
 * Port:  process.env.TOOL_SERVER_PORT (default 3001)
 * Verify: process.env.DRS_VERIFY_URL   (default http://localhost:8080)
 */

import { createServer } from "node:http";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { VerifyClient, parseBundle } from "@okeyamy/drs-sdk";
import { readExpenses, categorizeTransaction, approvePayment } from "./tools.js";
import { printVerificationResult } from "./verify.js";

const verifyUrl = process.env.DRS_VERIFY_URL ?? "http://localhost:8080";
const client = new VerifyClient({ baseUrl: verifyUrl, timeoutMs: 10_000 });

/**
 * Creates and starts the expense tool server.
 * Returns a Promise that resolves once the server is listening.
 * Returns the Server so the caller can close it gracefully.
 */
export function startToolServer(port: number): Promise<Server> {
  const server = createServer((req, res) => {
    handleRequest(req, res).catch((err: unknown) => {
      console.error("[Tool Server] Unhandled error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(port, () => resolve(server));
  });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  if (req.method === "POST" && req.url === "/mcp/tools/call") {
    await handleToolCall(req, res);
  } else {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }
}

async function handleToolCall(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  // ── Step 1: Read the request body ──────────────────────────────────────
  const body = await readBody(req);
  let requestData: Record<string, unknown>;
  try {
    requestData = JSON.parse(body) as Record<string, unknown>;
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Request body must be valid JSON" }));
    return;
  }

  const toolName = typeof requestData["tool"] === "string"
    ? requestData["tool"]
    : "unknown";

  // ── Step 2: Extract X-DRS-Bundle header ────────────────────────────────
  const bundleHeader = req.headers["x-drs-bundle"];
  if (!bundleHeader || typeof bundleHeader !== "string") {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "X-DRS-Bundle header is required" }));
    return;
  }

  // ── Step 3: Parse the bundle ────────────────────────────────────────────
  let bundle: ReturnType<typeof parseBundle>;
  try {
    bundle = parseBundle(bundleHeader);
  } catch (err: unknown) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: `Malformed X-DRS-Bundle: ${err instanceof Error ? err.message : String(err)}`,
    }));
    return;
  }

  // ── Step 4: Verify the bundle (all 6 blocks, done by the Go service) ────
  //
  // This is the DRS trust boundary. drs-verify checks:
  //   Block A: bundle is complete
  //   Block B: chain structure and hash linkage are intact
  //   Block C: Ed25519 signatures are valid (no tampering)
  //   Block D: invocation.args["tool"] is in policy.allowed_tools
  //   Block E: delegation has not expired
  //   Block F: delegation has not been revoked
  //
  // Pass the parsed request body so drs-verify also runs the body↔args
  // binding check (JCS equality). Without this, a caller could sign a
  // policy-compliant args value and POST a different body — the bundle
  // would verify but the tool would execute against the tampered body.
  //
  // Tools do not execute until this returns valid=true AND binding!=mismatch.
  const result = await client.verify(bundle, { body: requestData });
  printVerificationResult(toolName, result);

  if (!result.valid) {
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ drs_error: result.error }));
    return;
  }

  if (result.binding === "mismatch") {
    // Chain verified but the request body diverges from the signed args.
    // In production this is a refuse-to-execute condition — the caller's
    // signed intent does not authorise the body we are about to execute.
    res.writeHead(403, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      error: "BINDING_MISMATCH",
      detail: "Request body does not match invocation.args after JCS canonicalisation.",
    }));
    return;
  }

  // ── Step 5: Execute the tool ────────────────────────────────────────────
  const toolResult = executeTool(toolName, requestData);
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(toolResult));
}

/**
 * Dispatches to the real tool implementation.
 * These functions do actual file I/O — no mocks.
 */
function executeTool(
  tool: string,
  request: Record<string, unknown>,
): unknown {
  switch (tool) {
    case "read_expenses": {
      const expenses = readExpenses();
      return { expenses, count: expenses.length };
    }

    case "categorize_transaction": {
      const id = request["transaction_id"] as string;
      const category = request["category"] as string;
      return categorizeTransaction(id, category);
    }

    case "approve_payment": {
      const id = request["transaction_id"] as string;
      return approvePayment(id);
    }

    default:
      return { error: `Unknown tool: ${tool}` };
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}
