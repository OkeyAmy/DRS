/**
 * HTTP client for the drs-verify service.
 *
 * Sends a ChainBundle to drs-verify and returns a VerificationResult.
 * The base URL is configured via the DRS_VERIFY_URL environment variable
 * or the constructor parameter.
 */

import { serialiseBundle } from "../sdk/bundle.js";
import type { ChainBundle, VerificationResult } from "../sdk/types.js";
import { DrsError } from "../sdk/types.js";

export interface VerifyClientOptions {
  /** Base URL of the drs-verify service, e.g. "http://localhost:8080". */
  baseUrl: string;
  /** Fetch timeout in milliseconds. Default: 5000. */
  timeoutMs?: number;
}

export class VerifyClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: VerifyClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 5000;
  }

  /**
   * Verifies a ChainBundle against the remote drs-verify service.
   * Returns a VerificationResult — never throws for verification failures
   * (only throws for network errors or invalid server responses).
   *
   * When `options.includeTimestamps` is true, the server retrieves and verifies
   * the RFC 3161 timestamp token for each receipt and includes the results
   * in `VerificationResult.timestamps`.
   *
   * When `options.body` is provided, drs-verify canonicalises it via RFC 8785
   * (JCS) and compares with `invocation.args`. The outcome is reported in
   * `result.binding` — "match" | "mismatch" | "invalid_body" (or "empty_match"
   * from the middleware path). `valid` stays cryptographic truth; the caller
   * decides whether to reject on `binding === "mismatch"`.
   *
   * Pass the parsed request body the tool server received from its client —
   * e.g. the result of `JSON.parse(rawHttpBody)`. drs-verify canonicalises
   * both sides, so key order and numeric form do not affect equality.
   */
  async verify(
    bundle: ChainBundle,
    options?: { includeTimestamps?: boolean; body?: unknown },
  ): Promise<VerificationResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    const payload: Record<string, unknown> = { ...bundle };
    if (options?.includeTimestamps) {
      payload["include_timestamps"] = true;
    }
    if (options && "body" in options) {
      payload["body"] = options.body;
    }
    const body = JSON.stringify(payload);

    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-DRS-Bundle": serialiseBundle(bundle),
        },
        body,
        signal: controller.signal,
      });
    } catch (error: unknown) {
      clearTimeout(timeout);
      throw new DrsError(
        "NETWORK_ERROR",
        `Failed to reach drs-verify at ${this.baseUrl}: ${error instanceof Error ? error.message : String(error)}`,
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok && response.status !== 403) {
      throw new DrsError(
        "VERIFY_SERVICE_ERROR",
        `drs-verify returned unexpected status ${response.status}.`,
      );
    }

    let result: unknown;
    try {
      result = await response.json();
    } catch (error: unknown) {
      throw new DrsError(
        "VERIFY_RESPONSE_INVALID",
        `drs-verify response is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    if (
      typeof result !== "object" ||
      result === null ||
      typeof (result as Record<string, unknown>)["valid"] !== "boolean"
    ) {
      throw new DrsError(
        "VERIFY_RESPONSE_INVALID",
        "drs-verify response does not match VerificationResult schema.",
      );
    }

    return result as VerificationResult;
  }
}
