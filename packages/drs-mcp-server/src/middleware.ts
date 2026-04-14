/**
 * DRS MCP server middleware (Shape 2 transport binding).
 *
 * Extracts the X-DRS-Bundle from incoming MCP `_meta`, decodes from
 * base64url, validates the bundle against a drs-verify endpoint, and
 * returns a typed VerificationResult.
 *
 * Encoding: base64url(JSON.stringify(bundle)) — same as Go Shape 1.
 * Fail-closed: missing, malformed, or unverifiable bundles reject.
 *
 * See docs/drs-source-of-truth.md for the full transport binding spec.
 */

export interface VerificationError {
  code: string;
  message: string;
  suggestion: string;
}

export interface VerificationContext {
  root_principal: string;
  root_type?: string;
  leaf_policy: Record<string, unknown>;
  chain_depth: number;
  session_id?: string;
}

export interface VerificationResult {
  valid: boolean;
  context?: VerificationContext;
  error?: VerificationError;
}

export interface DrsVerifiedRequest {
  verified: boolean;
  result: VerificationResult;
}

export interface DrsServerConfig {
  verifyUrl: string;
  headerName?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

interface McpMessage {
  jsonrpc: string;
  method?: string;
  params?: Record<string, unknown>;
  id?: string | number;
  [key: string]: unknown;
}

const DEFAULT_HEADER = "X-DRS-Bundle";
const DEFAULT_TIMEOUT_MS = 5000;

const TOOL_CALL_METHODS = new Set(["tools/call"]);

function failClosed(code: string, message: string, suggestion: string): DrsVerifiedRequest {
  return {
    verified: false,
    result: {
      valid: false,
      error: { code, message, suggestion },
    },
  };
}

function base64UrlDecode(encoded: string): string {
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

function isVerificationResult(v: unknown): v is VerificationResult {
  if (typeof v !== "object" || v === null) return false;
  return typeof (v as Record<string, unknown>).valid === "boolean";
}

/**
 * Creates a middleware function that verifies DRS bundles on incoming
 * MCP tool-call messages.
 *
 * Non-tool-call methods are passed through without verification (the
 * returned result has `verified: true` with no context).
 */
export function drsMcpMiddleware(config: DrsServerConfig) {
  const headerName = config.headerName ?? DEFAULT_HEADER;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = config.fetchFn ?? globalThis.fetch;

  return async function verify(message: McpMessage): Promise<DrsVerifiedRequest> {
    if (!message.method || !TOOL_CALL_METHODS.has(message.method)) {
      return { verified: true, result: { valid: true } };
    }

    const meta = message.params?._meta as Record<string, unknown> | undefined;
    const bundleRaw = meta?.[headerName];

    if (!bundleRaw || typeof bundleRaw !== "string") {
      return failClosed(
        "MISSING_BUNDLE",
        `No ${headerName} found in message._meta.`,
        "The MCP client must attach a base64url-encoded DRS chain bundle to tool-call requests.",
      );
    }

    let bundleJson: string;
    try {
      bundleJson = base64UrlDecode(bundleRaw);
    } catch {
      return failClosed(
        "MALFORMED_BUNDLE",
        `${headerName} value is not valid base64url.`,
        "Ensure the bundle is base64url(JSON.stringify(chainBundle)).",
      );
    }

    let bundle: unknown;
    try {
      bundle = JSON.parse(bundleJson);
    } catch {
      return failClosed(
        "MALFORMED_BUNDLE",
        `${headerName} decoded base64url is not valid JSON.`,
        "Ensure the bundle is base64url(JSON.stringify(chainBundle)).",
      );
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetchImpl(config.verifyUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bundle),
        signal: controller.signal,
      });

      if (!response.ok) {
        return failClosed(
          "VERIFICATION_FAILED",
          `Verifier returned HTTP ${response.status}.`,
          "The DRS verification endpoint rejected the request. Check bundle format and verifier logs.",
        );
      }

      let body: unknown;
      try {
        body = await response.json();
      } catch {
        return failClosed(
          "VERIFICATION_FAILED",
          "Verifier returned non-JSON response.",
          "The DRS verification endpoint must return a JSON VerificationResult.",
        );
      }

      if (!isVerificationResult(body)) {
        return failClosed(
          "VERIFICATION_FAILED",
          "Verifier response does not contain a 'valid' boolean field.",
          "The DRS verification endpoint must return {valid: boolean, ...}.",
        );
      }

      return {
        verified: body.valid,
        result: body,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Verification request failed";
      return failClosed(
        "VERIFICATION_UNAVAILABLE",
        msg,
        "The DRS verification service is not reachable. Check the verifyUrl configuration.",
      );
    } finally {
      clearTimeout(timer);
    }
  };
}
