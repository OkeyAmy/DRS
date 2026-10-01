/**
 * Thin DRS enforcement point. Every protocol rule (which MCP/A2A messages are
 * gated, how arguments bind, error formats) lives in drs-verify's
 * POST /v1/gate — this module forwards the request and applies the decision.
 */

export type GateProtocol = "mcp" | "a2a" | "http";

/** The only request headers drs-verify consults. Credentials are never sent. */
export const FORWARDED_HEADERS = [
  "x-drs-bundle",
  "mcp-method",
  "mcp-name",
  "mcp-protocol-version",
  "a2a-version",
  "a2a-extensions",
] as const;

export interface VerificationContext {
  root_principal: string;
  root_type?: string;
  leaf_policy: Record<string, unknown>;
  chain_depth: number;
  session_id?: string;
}

export interface GateDecision {
  allow: boolean;
  gated: boolean;
  /** HTTP status to answer with when allow is false. */
  status: number;
  /** Protocol-native error body (JSON-RPC error for mcp/a2a) when allow is false. */
  response?: unknown;
  context?: VerificationContext;
}

export interface GateRequest {
  method: string;
  headers: Record<string, string | string[] | undefined>;
  /** The parsed JSON body (or undefined for body-less requests such as GET). */
  body?: unknown;
}

export interface DrsGateConfig {
  /** drs-verify base URL, e.g. "http://127.0.0.1:8080". */
  verifyUrl: string;
  protocol: GateProtocol;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

export interface DrsGate {
  check(request: GateRequest): Promise<GateDecision>;
}

const DEFAULT_TIMEOUT_MS = 5000;

export function createDrsGate(config: DrsGateConfig): DrsGate {
  const fetchImpl = config.fetchFn ?? globalThis.fetch;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const endpoint = new URL("/v1/gate", config.verifyUrl).toString();

  return {
    async check(request: GateRequest): Promise<GateDecision> {
      const payload = {
        protocol: config.protocol,
        method: request.method,
        headers: pickForwardedHeaders(request.headers),
        body: request.body ?? null,
      };
      try {
        const res = await fetchImpl(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok) {
          return unavailable(`drs-verify answered HTTP ${res.status}`);
        }
        const decision = (await res.json()) as Partial<GateDecision>;
        if (
          typeof decision.allow !== "boolean" ||
          typeof decision.status !== "number"
        ) {
          return unavailable("drs-verify returned a malformed decision");
        }
        return decision as GateDecision;
      } catch (error: unknown) {
        return unavailable(
          error instanceof Error ? error.message : "gate request failed",
        );
      }
    },
  };
}

/**
 * Lower-cases names and keeps only FORWARDED_HEADERS. Repeated values are
 * joined with ",", which drs-verify refuses as a malformed bundle.
 */
export function pickForwardedHeaders(
  headers: Record<string, string | string[] | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const key = name.toLowerCase();
    if (
      !(FORWARDED_HEADERS as readonly string[]).includes(key) ||
      value === undefined
    )
      continue;
    out[key] = Array.isArray(value) ? value.join(",") : value;
  }
  return out;
}

/** Fail closed: an unreachable or misbehaving verifier denies the request. */
function unavailable(detail: string): GateDecision {
  return {
    allow: false,
    gated: true,
    status: 503,
    response: { error: "DRS_UNAVAILABLE", detail },
  };
}
