/**
 * DRS MCP client transport wrapper.
 *
 * Wraps an MCP transport to inject DRS delegation bundles into outgoing
 * tool-call requests via the `_meta["X-DRS-Bundle"]` field (Shape 2
 * transport binding — see docs/drs-source-of-truth.md).
 *
 * The bundle is encoded as base64url(JSON.stringify(bundle)), matching
 * the same encoding the Go HTTP middleware (Shape 1) expects in the
 * X-DRS-Bundle header. A bridge between Shape 1 and Shape 2 only needs
 * to copy the string between HTTP header and _meta field.
 */

export interface McpTransport {
  send(message: McpMessage): Promise<void>;
  onMessage?: (handler: (message: McpMessage) => void) => void;
}

export interface McpMessage {
  jsonrpc: string;
  method?: string;
  params?: Record<string, unknown>;
  id?: string | number;
  result?: unknown;
  error?: unknown;
  [key: string]: unknown;
}

export interface BundleProvider {
  getBundle(): Promise<string | null>;
}

export interface DrsClientConfig {
  transport: McpTransport;
  bundleProvider: BundleProvider;
  headerName?: string;
}

const DEFAULT_HEADER = "X-DRS-Bundle";

const TOOL_CALL_METHODS = new Set(["tools/call"]);

export class DrsTransportWrapper implements McpTransport {
  private readonly inner: McpTransport;
  private readonly bundleProvider: BundleProvider;
  private readonly headerName: string;

  constructor(config: DrsClientConfig) {
    this.inner = config.transport;
    this.bundleProvider = config.bundleProvider;
    this.headerName = config.headerName ?? DEFAULT_HEADER;
  }

  async send(message: McpMessage): Promise<void> {
    const enriched = await this.maybeInjectBundle(message);
    return this.inner.send(enriched);
  }

  get onMessage(): McpTransport["onMessage"] {
    return this.inner.onMessage?.bind(this.inner);
  }

  private async maybeInjectBundle(message: McpMessage): Promise<McpMessage> {
    if (!message.method || !TOOL_CALL_METHODS.has(message.method)) {
      return message;
    }

    const bundle = await this.bundleProvider.getBundle();
    if (!bundle) {
      return message;
    }

    const encoded = stringToBase64Url(bundle);

    const meta =
      (message.params?._meta as Record<string, unknown> | undefined) ?? {};

    return {
      ...message,
      params: {
        ...message.params,
        _meta: {
          ...meta,
          [this.headerName]: encoded,
        },
      },
    };
  }
}

/**
 * Encodes a UTF-8 string to base64url without padding (RFC 4648 §5).
 * This matches the encoding Go's `base64.RawURLEncoding` produces.
 */
export function stringToBase64Url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes a base64url string (no padding) back to a UTF-8 string.
 */
export function base64UrlToString(encoded: string): string {
  let b64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}
