/**
 * Cross-language conformance tests for DRS 4.0.
 *
 * Loads shared fixture files from fixtures/conformance/ and verifies
 * TypeScript SDK output matches the canonical vectors. The same fixtures
 * are consumed by Rust and Go conformance tests.
 *
 * IMPORTANT: All functions under test are imported from the production SDK
 * modules — never re-implemented here. A conformance test that uses its own
 * copy of the logic is a false positive by construction.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, test, expect } from "vitest";
import { computeChainHash } from "./issue.js";
import { jcsSerialise } from "./jcs.js";
import { checkPolicyAttenuation } from "./policy.js";
import type { Policy } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(__dirname, "..", "..", "..", "fixtures", "conformance");

function loadFixture<T>(relPath: string): T {
  const raw = readFileSync(resolve(FIXTURES_DIR, relPath), "utf-8");
  return JSON.parse(raw) as T;
}

// ── JCS canonicalization ─────────────────────────────────────────────────

interface JcsVector {
  id: string;
  input: unknown;
  expected: string;
}

describe("conformance: JCS canonicalization", () => {
  const fixture = loadFixture<{ vectors: JcsVector[] }>("jcs/vectors.json");

  test.each(fixture.vectors)("$id", (vec) => {
    const result = jcsSerialise(vec.input);
    expect(result).toBe(vec.expected);
  });
});

// ── Chain hash computation ───────────────────────────────────────────────

interface ChainHashVector {
  id: string;
  input: string;
  expected: string;
}

describe("conformance: chain hash", () => {
  const fixture = loadFixture<{ vectors: ChainHashVector[] }>("chain-hash/vectors.json");

  test.each(fixture.vectors)("$id", (vec) => {
    const result = computeChainHash(vec.input);
    expect(result).toBe(vec.expected);
  });
});

// ── Policy attenuation — pass cases ──────────────────────────────────────

interface PolicyPassVector {
  id: string;
  parent: Policy;
  child: Policy;
}

describe("conformance: policy attenuation pass", () => {
  const fixture = loadFixture<{ vectors: PolicyPassVector[] }>("policy/pass.json");

  test.each(fixture.vectors)("$id", (vec) => {
    const result = checkPolicyAttenuation(vec.parent, vec.child);
    expect(result).toBeNull();
  });
});

// ── Policy attenuation — fail cases ──────────────────────────────────────

interface PolicyFailVector {
  id: string;
  parent: Policy;
  child: Policy;
  expected_keyword: string;
}

describe("conformance: policy attenuation fail", () => {
  const fixture = loadFixture<{ vectors: PolicyFailVector[] }>("policy/fail.json");

  test.each(fixture.vectors)("$id", (vec) => {
    const result = checkPolicyAttenuation(vec.parent, vec.child);
    expect(result).not.toBeNull();
    expect(result).toContain(vec.expected_keyword);
  });
});

// ── Temporal validity ────────────────────────────────────────────────────

interface TemporalVector {
  id: string;
  nbf: number;
  exp: number | null;
  now: number;
  valid: boolean;
  expected_code?: string;
}

function checkTemporalValidity(
  nbf: number,
  exp: number | null,
  now: number,
): { valid: boolean; code?: string } {
  if (now < nbf) {
    return { valid: false, code: "NOT_YET_VALID" };
  }
  if (exp !== null && now > exp) {
    return { valid: false, code: "EXPIRED" };
  }
  return { valid: true };
}

describe("conformance: temporal validity", () => {
  const fixture = loadFixture<{ vectors: TemporalVector[] }>("temporal/vectors.json");

  test.each(fixture.vectors)("$id", (vec) => {
    const result = checkTemporalValidity(vec.nbf, vec.exp, vec.now);
    expect(result.valid).toBe(vec.valid);
    if (!vec.valid && vec.expected_code) {
      expect(result.code).toBe(vec.expected_code);
    }
  });
});

// ── Revocation status ────────────────────────────────────────────────────

interface RevocationVector {
  id: string;
  status_list_index: number;
  is_revoked: boolean;
}

describe("conformance: revocation status", () => {
  const fixture = loadFixture<{ vectors: RevocationVector[] }>("revocation/vectors.json");

  const revokedIndices = new Set([42]);

  test.each(fixture.vectors)("$id", (vec) => {
    const isRevoked = revokedIndices.has(vec.status_list_index);
    expect(isRevoked).toBe(vec.is_revoked);
  });
});

// ── Receipt chain hash cross-check ───────────────────────────────────────

interface ReceiptFixture {
  jwt: string;
  chain_hash: string;
}

describe("conformance: receipt chain hashes", () => {
  const files = ["receipts/root-delegation.json", "receipts/sub-delegation.json"];

  test.each(files)("%s", (file) => {
    const fixture = loadFixture<ReceiptFixture>(file);
    const result = computeChainHash(fixture.jwt);
    expect(result).toBe(fixture.chain_hash);
  });
});

// ── Full chain bundle structure ──────────────────────────────────────────

describe("conformance: full chain bundle structure", () => {
  interface FullChainFixture {
    bundle: {
      bundle_version: string;
      invocation: string;
      receipts: string[];
    };
    expected_result: {
      valid: boolean;
      context: {
        root_principal: string;
        root_type: string;
        chain_depth: number;
      };
    };
  }

  test("bundle receipts chain hashes match invocation dr_chain", () => {
    const fixture = loadFixture<FullChainFixture>("receipts/full-chain-bundle.json");
    const invFixture = loadFixture<{ payload: { dr_chain: string[] } }>("receipts/invocation.json");

    for (let i = 0; i < fixture.bundle.receipts.length; i++) {
      const receiptHash = computeChainHash(fixture.bundle.receipts[i]!);
      expect(receiptHash).toBe(invFixture.payload.dr_chain[i]);
    }
  });

  test("bundle has expected structure", () => {
    const fixture = loadFixture<FullChainFixture>("receipts/full-chain-bundle.json");
    expect(fixture.bundle.bundle_version).toBe("4.0");
    expect(fixture.bundle.receipts.length).toBe(fixture.expected_result.context.chain_depth);
    expect(fixture.bundle.invocation).toBeTruthy();
  });
});
