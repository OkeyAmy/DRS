import type { IncomingMessage, ServerResponse } from "node:http";
import type { DrsGate, VerificationContext } from "./gate.js";

const MAX_BODY_BYTES = 64 * 1024;

export interface GatedRequest extends IncomingMessage {
  drs?: VerificationContext;
}

/**
 * Wraps a Node `(req, res, parsedBody?)` handler — the shape of the official
 * MCP SDK's `toNodeHandler` and NodeStreamableHTTPServerTransport.handleRequest
 * — with a DRS gate. The body is read once and handed to the handler parsed.
 */
export function withDrsGate(
  gate: DrsGate,
  handler: (
    req: GatedRequest,
    res: ServerResponse,
    parsedBody?: unknown,
  ) => unknown,
) {
  return async (
    req: GatedRequest,
    res: ServerResponse,
    parsedBody?: unknown,
  ): Promise<void> => {
    let body = parsedBody;
    if (body === undefined && req.method === "POST") {
      const read = await readJson(req);
      if (!read.ok) {
        reply(res, read.status, { error: read.error });
        return;
      }
      body = read.value;
    }
    const decision = await gate.check({
      method: req.method ?? "GET",
      headers: req.headers,
      body,
    });
    if (!decision.allow) {
      reply(res, decision.status, decision.response ?? { error: "DRS_DENIED" });
      return;
    }
    if (decision.context) req.drs = decision.context;
    await handler(req, res, body);
  };
}

type ReadResult =
  | { ok: true; value: unknown }
  | { ok: false; status: number; error: string };

async function readJson(req: IncomingMessage): Promise<ReadResult> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES)
      return { ok: false, status: 413, error: "BODY_TOO_LARGE" };
    chunks.push(chunk as Buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text.trim() === "") return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(text) };
  } catch {
    return { ok: false, status: 400, error: "INVALID_JSON" };
  }
}

function reply(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}
