/**
 * Assembles a ChainBundle from a list of delegation JWT strings and an invocation JWT.
 *
 * The bundle is the unit of input to drs-verify. It contains all delegation
 * receipts in root-first order plus the invocation receipt.
 *
 * Transport encoding: bundles are serialised as base64url(JSON.stringify(bundle))
 * and sent in the X-DRS-Bundle HTTP header.
 */

import { base64url, decodeBase64url } from "./base64url.js";
import type { ChainBundle } from "./types.js";
import { DrsError } from "./types.js";

/**
 * Builds a ChainBundle from delegation JWTs and an invocation JWT.
 *
 * @param receipts - Delegation receipt JWTs, root first.
 * @param invocation - The invocation receipt JWT.
 */
export function buildBundle(receipts: string[], invocation: string): ChainBundle {
  if (receipts.length === 0) {
    throw new DrsError("EMPTY_CHAIN", "At least one delegation receipt is required.");
  }
  if (!invocation) {
    throw new DrsError("MISSING_INVOCATION", "An invocation receipt is required.");
  }

  return {
    bundle_version: "4.0",
    invocation,
    receipts,
  };
}

/**
 * Serialises a ChainBundle to a base64url string suitable for use as the
 * X-DRS-Bundle HTTP header value (per DRS 4.0 §9).
 */
export function serialiseBundle(bundle: ChainBundle): string {
  return base64url(JSON.stringify(bundle));
}

/**
 * Parses a base64url-encoded bundle string back into a ChainBundle.
 * Throws DrsError if the input cannot be decoded or is missing required fields.
 */
export function parseBundle(encoded: string): ChainBundle {
  let json: string;
  try {
    const bytes = decodeBase64url(encoded);
    json = new TextDecoder().decode(bytes);
  } catch (error: unknown) {
    throw new DrsError(
      "MALFORMED_BUNDLE",
      `Bundle base64url decode failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error: unknown) {
    throw new DrsError(
      "MALFORMED_BUNDLE",
      `Bundle JSON parse failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !("receipts" in parsed) ||
    !("invocation" in parsed) ||
    !("bundle_version" in parsed)
  ) {
    throw new DrsError(
      "MALFORMED_BUNDLE",
      "Bundle must have bundle_version, receipts, and invocation fields.",
    );
  }

  return parsed as ChainBundle;
}
