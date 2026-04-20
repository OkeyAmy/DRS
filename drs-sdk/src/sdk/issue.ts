/**
 * Issuance functions for DRS 4.0 delegation receipts.
 *
 * Security properties:
 * - All Ed25519 operations use @noble/ed25519 (audited, no WebCrypto dependency)
 * - Policy attenuation is checked at issuance to prevent invalid sub-delegations
 *   from being created and rejected later at verification time
 * - Signing keys are never logged or stored by this module
 */

import * as ed from "@noble/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { base64url, base64urlBytes } from "./base64url.js";
import { jcsSerialise } from "./jcs.js";
import { checkPolicyAttenuation } from "./policy.js";
import type {
  ChainBundle,
  ConsentRecord,
  DelegationReceiptPayload,
  InvocationReceiptPayload,
  Policy,
  RegulatoryMetadata,
} from "./types.js";
import { DrsError } from "./types.js";

// @noble/ed25519 v3 requires SHA-512 to be supplied — moved from
// ed.etc.sha512Sync (v2) to ed.hashes.sha512 (v3).
ed.hashes.sha512 = sha512;

/** Parameters for issuing the root delegation receipt. */
export interface RootDelegationParams {
  /** The delegator's private key (raw 32 bytes). */
  signingKey: Uint8Array;
  /** The delegator's DID (did:key). */
  issuerDid: string;
  /** The original resource owner's DID. */
  subjectDid: string;
  /** The immediate recipient's DID. */
  audienceDid: string;
  /** The command being delegated (e.g. "/mcp/tools/call"). */
  cmd: string;
  /** Capability constraints. */
  policy: Policy;
  /** Unix timestamp: not-before. */
  nbf: number;
  /** Unix timestamp: expiry. Null for machine-rooted standing delegations that auto-renew. */
  exp: number | null;
  /** Human consent record (required when rootType is "human"). */
  consent?: ConsentRecord;
  /** Root trust type. Default: "automated-system". */
  rootType?: "human" | "organisation" | "automated-system";
  /** Optional compliance metadata. */
  regulatory?: RegulatoryMetadata;
}

/** Parameters for issuing a sub-delegation receipt. */
export interface SubDelegationParams {
  /** The sub-delegator's private key. */
  signingKey: Uint8Array;
  /** The sub-delegator's DID. */
  issuerDid: string;
  /** The original resource owner's DID (must match parent). */
  subjectDid: string;
  /** The new audience's DID. */
  audienceDid: string;
  /** The command being sub-delegated. */
  cmd: string;
  /** Capability constraints — must not escalate beyond parent policy. */
  policy: Policy;
  /** Unix timestamp: not-before. */
  nbf: number;
  /** Unix timestamp: expiry. Null for standing delegations. */
  exp: number | null;
  /** The parent delegation receipt JWT (used to compute prev_dr_hash). */
  parentJwt: string;
  /** The parent's policy (checked for attenuation before signing). */
  parentPolicy: Policy;
  /** The parent's nbf — child nbf must be >= parentNbf. */
  parentNbf: number;
  /** The parent's exp — child exp must be <= parentExp when both are set. */
  parentExp: number | null;
}

export interface InvocationParams {
  signingKey: Uint8Array;
  issuerDid: string;
  subjectDid: string;
  cmd: string;
  args: Record<string, unknown>;
  drChain: string[];
  toolServer: string;
}

/**
 * Issues the root delegation receipt (chain index 0).
 * If rootType is "human", consent is required.
 */
export async function issueRootDelegation(params: RootDelegationParams): Promise<string> {
  const rootType = params.rootType ?? "automated-system";
  if (rootType === "human" && !params.consent) {
    throw new DrsError(
      "MISSING_CONSENT",
      "Human-rooted delegations require a consent record.",
    );
  }

  const now = unixNow();
  const payload: DelegationReceiptPayload = {
    iss: params.issuerDid,
    sub: params.subjectDid,
    aud: params.audienceDid,
    drs_v: "4.0",
    drs_type: "delegation-receipt",
    cmd: params.cmd,
    policy: params.policy,
    nbf: params.nbf,
    exp: params.exp,
    iat: now,
    jti: generateDrJti(),
    drs_root_type: rootType,
    ...(params.consent !== undefined ? { drs_consent: params.consent } : {}),
    ...(params.regulatory !== undefined ? { drs_regulatory: params.regulatory } : {}),
  };

  return buildJwt(payload, params.signingKey);
}

/**
 * Issues a sub-delegation receipt (chain index ≥ 1).
 * Throws DrsError with code POLICY_ESCALATION if child policy exceeds parent.
 */
export async function issueSubDelegation(params: SubDelegationParams): Promise<string> {
  // Parse the parent JWT to extract and validate chain linkage.
  // This prevents callers from constructing sub-delegations that would fail
  // verification, catching linkage errors at issuance time.
  const parentPayload = decodeJwtPayload<DelegationReceiptPayload>(params.parentJwt);

  // The parent's aud must equal our issuerDid — we must be the intended recipient.
  if (parentPayload.aud !== params.issuerDid) {
    throw new DrsError(
      "CHAIN_LINKAGE_ERROR",
      `Parent DR was issued to "${parentPayload.aud}" but issuerDid is "${params.issuerDid}". ` +
        `The sub-delegator must be the audience of the parent delegation.`,
    );
  }

  // Our cmd must equal or be a sub-path of the parent's cmd (POLA).
  if (!isCmdSubPath(params.cmd, parentPayload.cmd)) {
    throw new DrsError(
      "CMD_ESCALATION",
      `Sub-delegation cmd "${params.cmd}" is not equal to or a sub-path of parent cmd "${parentPayload.cmd}".`,
    );
  }

  const attenuationError = checkPolicyAttenuation(params.parentPolicy, params.policy);
  if (attenuationError !== null) {
    throw new DrsError("POLICY_ESCALATION", attenuationError);
  }

  // Temporal bounds: child nbf must be >= parent nbf
  if (params.nbf < params.parentNbf) {
    throw new DrsError(
      "TEMPORAL_BOUNDS_VIOLATION",
      `Sub-delegation nbf (${params.nbf}) must be >= parent nbf (${params.parentNbf}).`,
    );
  }
  // Temporal bounds: child exp must be <= parent exp when both are set
  if (params.exp !== null && params.parentExp !== null && params.exp > params.parentExp) {
    throw new DrsError(
      "TEMPORAL_BOUNDS_VIOLATION",
      `Sub-delegation exp (${params.exp}) must be <= parent exp (${params.parentExp}).`,
    );
  }

  const prevDrHash = computeChainHash(params.parentJwt);
  const now = unixNow();

  const payload: DelegationReceiptPayload = {
    iss: params.issuerDid,
    sub: params.subjectDid,
    aud: params.audienceDid,
    drs_v: "4.0",
    drs_type: "delegation-receipt",
    cmd: params.cmd,
    policy: params.policy,
    nbf: params.nbf,
    exp: params.exp,
    iat: now,
    jti: generateDrJti(),
    prev_dr_hash: prevDrHash,
  };

  return buildJwt(payload, params.signingKey);
}

/** Issues an invocation receipt tying together the chain and the actual tool call. */
export async function issueInvocation(params: InvocationParams): Promise<string> {
  const now = unixNow();
  const payload: InvocationReceiptPayload = {
    iss: params.issuerDid,
    sub: params.subjectDid,
    drs_v: "4.0",
    drs_type: "invocation-receipt",
    cmd: params.cmd,
    args: params.args,
    dr_chain: params.drChain,
    tool_server: params.toolServer,
    iat: now,
    jti: generateInvJti(),
  };

  return buildJwt(payload, params.signingKey);
}

/** Builds a signed JWT with EdDSA (Ed25519) per RFC 7515.
 *
 * Both the header and the payload are serialised with RFC 8785 JCS
 * (jcsSerialise) so that two logically equivalent objects always produce
 * identical JWTs — matching the Rust encoder's jcs_canonical_bytes behaviour.
 */
export async function buildJwt(payload: unknown, signingKey: Uint8Array): Promise<string> {
  const header = { alg: "EdDSA", typ: "JWT" };
  const headerB64 = base64url(jcsSerialise(header));
  const payloadB64 = base64url(jcsSerialise(payload));
  const signingInput = `${headerB64}.${payloadB64}`;

  const sig = await ed.signAsync(new TextEncoder().encode(signingInput), signingKey);
  return `${signingInput}.${base64urlBytes(sig)}`;
}

// jcsSerialise imported from ./jcs.ts — single canonical implementation across
// the SDK (issuance + conformance tests). See that module for RFC 8785 rules.

/** Computes SHA-256 of a JWT string and returns "sha256:{hex}". */
export function computeChainHash(jwt: string): string {
  const bytes = new TextEncoder().encode(jwt);
  const digest = sha256(bytes);
  const hex = Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}

/** Derives the Ed25519 public key from a raw 32-byte private key. */
export function derivePublicKey(signingKey: Uint8Array): Uint8Array {
  return ed.getPublicKey(signingKey);
}

/**
 * Decodes the payload of a JWT without verifying the signature.
 * Used at issuance time to validate chain linkage before signing.
 * Never use this for verification — the Go verifier validates signatures.
 */
function decodeJwtPayload<T>(jwt: string): T {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new DrsError("MALFORMED_JWT", `JWT must have exactly three parts, got ${parts.length}.`);
  }
  const b64 = parts[1]!.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  let json: string;
  try {
    json = atob(padded);
  } catch {
    throw new DrsError("MALFORMED_JWT", "JWT payload is not valid base64url.");
  }
  try {
    return JSON.parse(json) as T;
  } catch {
    throw new DrsError("MALFORMED_JWT", "JWT payload is not valid JSON.");
  }
}

/** Returns true if cmd equals parentCmd or is a direct sub-path (parentCmd + "/..."). */
function isCmdSubPath(cmd: string, parentCmd: string): boolean {
  if (cmd === parentCmd) return true;
  return cmd.startsWith(parentCmd + "/");
}

function unixNow(): number {
  return Math.floor(Date.now() / 1000);
}

/** JTI for delegation receipts — "dr:" + UUID v4 per DRS 4.0 §5. */
function generateDrJti(): string {
  return `dr:${globalThis.crypto.randomUUID()}`;
}

/** JTI for invocation receipts — "inv:" + UUID v4 per DRS 4.0 §5. */
function generateInvJti(): string {
  return `inv:${globalThis.crypto.randomUUID()}`;
}

// Re-export ChainBundle type so bundle.ts can use it without creating a circular dep
export type { ChainBundle };
