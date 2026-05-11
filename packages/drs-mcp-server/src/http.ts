import type {
  VerificationContext,
  VerificationError,
  VerificationResult,
} from "./middleware.js";

const DEFAULT_HEADER = "x-drs-bundle";
const DEFAULT_TIMEOUT_MS = 5000;

export interface DrsHttpRequest {
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  drs?: VerificationContext;
}

export interface DrsHttpConfig {
  verifyUrl: string;
  headerName?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

export interface DrsHttpPass {
  ok: true;
  status: 200;
  context?: VerificationContext;
}

export interface DrsHttpReject {
  ok: false;
  status: 400 | 401 | 403 | 502 | 503;
  error: VerificationError;
}

export type DrsHttpResult = DrsHttpPass | DrsHttpReject;
export type DrsHttpNext<T extends DrsHttpRequest = DrsHttpRequest> = (
  request: T,
) => unknown | Promise<unknown>;

export function createDrsHttpMiddleware(config: DrsHttpConfig) {
  const headerName = (config.headerName ?? DEFAULT_HEADER).toLowerCase();
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = config.fetchFn ?? globalThis.fetch;

  return async function drsHttpMiddleware<T extends DrsHttpRequest>(
    request: T,
    next: DrsHttpNext<T>,
  ): Promise<DrsHttpResult> {
    const bundleHeader = readHeader(request.headers, headerName);
    if (!bundleHeader) {
      return reject(
        401,
        "MISSING_BUNDLE",
        "Missing X-DRS-Bundle header.",
        "Attach a base64url-encoded DRS ChainBundle before calling this endpoint.",
      );
    }

    const bundle = parseBundleHeader(bundleHeader);
    if (!bundle.ok) {
      return bundle;
    }

    const result = await verifyBundle(fetchImpl, config.verifyUrl, timeoutMs, {
      ...bundle.value,
      body: request.body ?? null,
    });
    if (!result.ok) {
      return result;
    }

    if (!result.value.valid) {
      return {
        ok: false,
        status: 403,
        error: result.value.error ?? {
          code: "VERIFICATION_FAILED",
          message: "DRS verification failed without a structured error.",
          suggestion: "Check drs-verify logs for the rejected bundle.",
        },
      };
    }

    if (result.value.binding !== "match") {
      return reject(
        403,
        "BINDING_MISMATCH",
        `Request body does not match invocation.args (binding=${result.value.binding ?? "missing"}).`,
        "Pass the exact request body to drs-verify and execute only when binding is 'match'.",
      );
    }

    request.drs = result.value.context;
    await next(request);
    return { ok: true, status: 200, context: result.value.context };
  };
}

function readHeader(
  headers: DrsHttpRequest["headers"],
  headerName: string,
): string | undefined {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== headerName) continue;
    if (Array.isArray(value)) return value[0];
    return value;
  }
  return undefined;
}

function parseBundleHeader(
  encoded: string,
): { ok: true; value: Record<string, unknown> } | DrsHttpReject {
  try {
    const json = base64UrlDecode(encoded);
    const parsed = JSON.parse(json);
    if (typeof parsed !== "object" || parsed === null) {
      return reject(
        400,
        "MALFORMED_BUNDLE",
        "X-DRS-Bundle decoded to a non-object value.",
        "Encode a ChainBundle JSON object.",
      );
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch (error) {
    return reject(
      400,
      "MALFORMED_BUNDLE",
      `X-DRS-Bundle is not valid base64url JSON: ${error instanceof Error ? error.message : String(error)}`,
      "Encode the ChainBundle as base64url(JSON.stringify(bundle)).",
    );
  }
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

async function verifyBundle(
  fetchImpl: typeof fetch,
  verifyUrl: string,
  timeoutMs: number,
  payload: Record<string, unknown>,
): Promise<{ ok: true; value: VerificationResult } | DrsHttpReject> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(verifyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!response.ok) {
      return reject(
        502,
        "VERIFICATION_FAILED",
        `drs-verify returned HTTP ${response.status}.`,
        "Check the verifier endpoint and logs.",
      );
    }

    const body = await response.json();
    if (!isVerificationResult(body)) {
      return reject(
        502,
        "VERIFICATION_FAILED",
        "drs-verify returned an invalid response shape.",
        "Verifier responses must include a boolean 'valid' field.",
      );
    }
    return { ok: true, value: body };
  } catch (error) {
    return reject(
      503,
      "VERIFICATION_UNAVAILABLE",
      error instanceof Error ? error.message : "drs-verify is unavailable.",
      "Check DRS_VERIFY_URL, network access, and verifier health.",
    );
  } finally {
    clearTimeout(timer);
  }
}

function isVerificationResult(value: unknown): value is VerificationResult {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as Record<string, unknown>).valid === "boolean"
  );
}

function reject(
  status: DrsHttpReject["status"],
  code: string,
  message: string,
  suggestion: string,
): DrsHttpReject {
  return {
    ok: false,
    status,
    error: { code, message, suggestion },
  };
}
