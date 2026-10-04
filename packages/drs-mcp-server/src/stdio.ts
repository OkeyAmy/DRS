import type { DrsGate } from "./gate.js";

/** The subset of the MCP SDK `Transport` interface this wrapper relies on. */
export interface McpTransport {
  start(): Promise<void>;
  send(message: JsonRpcMessage, options?: unknown): Promise<void>;
  close(): Promise<void>;
  onmessage?: (message: JsonRpcMessage, extra?: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  sessionId?: string;
  setProtocolVersion?: (version: string) => void;
}

export interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: string | number | null;
  method?: string;
  [key: string]: unknown;
}

/**
 * Gates an MCP *server* transport that has no HTTP layer (stdio). Every
 * inbound message is decided by drs-verify; refused requests are answered
 * with the JSON-RPC error the verifier produced and never reach the server.
 * Messages are processed strictly in arrival order.
 */
export class DrsGatedServerTransport implements McpTransport {
  onmessage?: (message: JsonRpcMessage, extra?: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  private queue: Promise<void> = Promise.resolve();

  constructor(
    private readonly inner: McpTransport,
    private readonly gate: DrsGate,
  ) {
    inner.onmessage = (message, extra) => {
      this.queue = this.queue.then(() => this.admit(message, extra));
    };
    inner.onclose = () => this.onclose?.();
    inner.onerror = (error) => this.onerror?.(error);
  }

  get sessionId(): string | undefined {
    return this.inner.sessionId;
  }

  setProtocolVersion(version: string): void {
    this.inner.setProtocolVersion?.(version);
  }

  start(): Promise<void> {
    return this.inner.start();
  }

  send(message: JsonRpcMessage, options?: unknown): Promise<void> {
    return this.inner.send(message, options);
  }

  close(): Promise<void> {
    return this.inner.close();
  }

  private async admit(message: JsonRpcMessage, extra: unknown): Promise<void> {
    const decision = await this.gate.check({
      method: "POST",
      headers: {},
      body: message,
    });
    if (decision.allow) {
      this.onmessage?.(message, extra);
      return;
    }
    if (message.id === undefined || message.id === null) return; // notifications get no reply
    await this.inner.send(
      asJsonRpcError(message.id, decision.response, decision.status),
    );
  }
}

function asJsonRpcError(
  id: string | number,
  response: unknown,
  status: number,
): JsonRpcMessage {
  const r = response as { jsonrpc?: string; error?: unknown } | undefined;
  if (r?.jsonrpc === "2.0" && r.error) return { ...(r as JsonRpcMessage), id };
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32010,
      message: "DRS: request refused",
      data: { status, response },
    },
  };
}
