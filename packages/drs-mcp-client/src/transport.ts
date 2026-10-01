import { embed } from "./fetch.js";
import { callFor, type Signer } from "./signer.js";

/** The subset of the MCP SDK `Transport` interface this wrapper implements. */
export interface McpTransport {
  start(): Promise<void>;
  send(message: Record<string, unknown>, options?: unknown): Promise<void>;
  close(): Promise<void>;
  onmessage?: (message: unknown, extra?: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  sessionId?: string;
  setProtocolVersion?: (version: string) => void;
}

/**
 * Wraps any MCP client transport (stdio, Streamable HTTP, in-memory) and
 * embeds a freshly signed bundle in params._meta of every tools/call.
 * Use it where there is no HTTP header to carry the bundle — notably stdio.
 */
export class DrsClientTransport implements McpTransport {
  constructor(
    private readonly inner: McpTransport,
    private readonly signer: Signer,
  ) {}

  set onmessage(handler: McpTransport["onmessage"]) {
    this.inner.onmessage = handler;
  }
  get onmessage(): McpTransport["onmessage"] {
    return this.inner.onmessage;
  }
  set onclose(handler: McpTransport["onclose"]) {
    this.inner.onclose = handler;
  }
  get onclose(): McpTransport["onclose"] {
    return this.inner.onclose;
  }
  set onerror(handler: McpTransport["onerror"]) {
    this.inner.onerror = handler;
  }
  get onerror(): McpTransport["onerror"] {
    return this.inner.onerror;
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

  close(): Promise<void> {
    return this.inner.close();
  }

  async send(
    message: Record<string, unknown>,
    options?: unknown,
  ): Promise<void> {
    const call = callFor("mcp", message);
    if (!call) return this.inner.send(message, options);
    return this.inner.send(embed(message, await this.signer(call)), options);
  }
}
