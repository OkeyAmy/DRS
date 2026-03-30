import { describe, it, expect } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import {
  buildJwt,
  computeChainHash,
  derivePublicKey,
  issueInvocation,
  issueRootDelegation,
  issueSubDelegation,
} from "./issue.js";
import { DrsError } from "./types.js";

// @noble/ed25519 v2 requires SHA-512 to be set (set here in case vitest runs before issue.ts)
ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

function generateKey(): Uint8Array {
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  return key;
}

function didFromKey(privKey: Uint8Array): string {
  const pub = derivePublicKey(privKey);
  const multicodec = new Uint8Array([0xed, 0x01, ...pub]);
  const encoded = base58Encode(multicodec);
  return `did:key:z${encoded}`;
}

function base58Encode(bytes: Uint8Array): string {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = digits.length - 1; j >= 0; j--) {
      carry += 256 * (digits[j] ?? 0);
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.unshift(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    result += "1";
  }
  for (const d of digits) result += ALPHABET[d];
  return result;
}

const now = Math.floor(Date.now() / 1000);

describe("buildJwt", () => {
  it("produces a three-part JWT", async () => {
    const key = generateKey();
    const jwt = await buildJwt({ iss: "did:key:z1" }, key);
    expect(jwt.split(".")).toHaveLength(3);
  });

  it("is deterministic for the same key and payload", async () => {
    const key = generateKey();
    const payload = { a: 1, b: 2 };
    const jwt1 = await buildJwt(payload, key);
    const jwt2 = await buildJwt(payload, key);
    expect(jwt1).toBe(jwt2);
  });
});

describe("computeChainHash", () => {
  it("starts with sha256: prefix", () => {
    const hash = computeChainHash("some.jwt.token");
    expect(hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    const jwt = "header.payload.sig";
    expect(computeChainHash(jwt)).toBe(computeChainHash(jwt));
  });

  it("differs for different inputs", () => {
    expect(computeChainHash("token.a.1")).not.toBe(computeChainHash("token.a.2"));
  });
});

describe("issueRootDelegation", () => {
  it("produces a valid JWT", async () => {
    const key = generateKey();
    const did = didFromKey(key);
    const audienceKey = generateKey();
    const audienceDid = didFromKey(audienceKey);

    const jwt = await issueRootDelegation({
      signingKey: key,
      issuerDid: did,
      subjectDid: did,
      audienceDid,
      cmd: "/mcp/tools/call",
      policy: {},
      nbf: now - 60,
      exp: now + 3600,
    });

    expect(jwt.split(".")).toHaveLength(3);
  });

  it("throws MISSING_CONSENT for human root without consent", async () => {
    const key = generateKey();
    const did = didFromKey(key);
    await expect(
      issueRootDelegation({
        signingKey: key,
        issuerDid: did,
        subjectDid: did,
        audienceDid: did,
        cmd: "/mcp/tools/call",
        policy: {},
        nbf: now,
        exp: now + 3600,
        rootType: "human",
        // no consent
      }),
    ).rejects.toMatchObject({ code: "MISSING_CONSENT" });
  });

  it("succeeds for human root with consent", async () => {
    const key = generateKey();
    const did = didFromKey(key);
    const jwt = await issueRootDelegation({
      signingKey: key,
      issuerDid: did,
      subjectDid: did,
      audienceDid: did,
      cmd: "/mcp/tools/call",
      policy: {},
      nbf: now,
      exp: now + 3600,
      rootType: "human",
      consent: {
        method: "explicit-button",
        timestamp: new Date().toISOString(),
        session_id: "sess-123",
        policy_hash: "sha256:abc",
        locale: "en-US",
      },
    });
    expect(jwt).toBeTruthy();
  });
});

describe("issueSubDelegation", () => {
  it("throws POLICY_ESCALATION when child raises cost limit", async () => {
    const key = generateKey();
    const did = didFromKey(key);
    const parentJwt = await buildJwt({ dummy: true }, key);

    await expect(
      issueSubDelegation({
        signingKey: key,
        issuerDid: did,
        subjectDid: did,
        audienceDid: did,
        cmd: "/mcp/tools/call",
        policy: { max_cost_usd: 100.0 },
        parentPolicy: { max_cost_usd: 10.0 },
        nbf: now,
        exp: now + 3600,
        parentNbf: now - 60,
        parentExp: now + 7200,
        parentJwt,
      }),
    ).rejects.toMatchObject({ code: "POLICY_ESCALATION" });
  });

  it("includes prev_dr_hash in the payload", async () => {
    const key = generateKey();
    const did = didFromKey(key);
    const parentJwt = await buildJwt({ dummy: true }, key);
    const expectedHash = computeChainHash(parentJwt);

    const jwt = await issueSubDelegation({
      signingKey: key,
      issuerDid: did,
      subjectDid: did,
      audienceDid: did,
      cmd: "/mcp/tools/call",
      policy: {},
      parentPolicy: {},
      nbf: now,
      exp: now + 3600,
      parentNbf: now - 60,
      parentExp: now + 7200,
      parentJwt,
    });

    // Decode payload and check prev_dr_hash
    const payloadB64 = jwt.split(".")[1]!;
    const payloadJson = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(payloadJson) as { prev_dr_hash?: string };
    expect(payload.prev_dr_hash).toBe(expectedHash);
  });
});

describe("issueInvocation", () => {
  it("produces a JWT with invocation-receipt drs_type", async () => {
    const key = generateKey();
    const did = didFromKey(key);
    const jwt = await issueInvocation({
      signingKey: key,
      issuerDid: did,
      subjectDid: did,
      cmd: "/mcp/tools/call",
      args: { tool: "web_search" },
      drChain: ["sha256:abc"],
      toolServer: "mcp://tools/server",
    });

    const payloadB64 = jwt.split(".")[1]!;
    const payloadJson = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(payloadJson) as { drs_type: string };
    expect(payload.drs_type).toBe("invocation-receipt");
  });
});
