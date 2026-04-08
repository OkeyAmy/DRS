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
   * When options.includeTimestamps is true, the server retrieves and verifies
   * the RFC 3161 timestamp token for each receipt and includes the results
   * in VerificationResult.timestamps.
   */
  async verify(
    bundle: ChainBundle,
    options?: { includeTimestamps?: boolean },
  ): Promise<VerificationResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    const body = options?.includeTimestamps
      ? JSON.stringify({ ...bundle, include_timestamps: true })
      : JSON.stringify(bundle);

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
