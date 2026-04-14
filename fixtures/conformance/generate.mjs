/**
 * Conformance fixture generator for DRS 4.0.
 *
 * Produces deterministic test vectors that all three implementations
 * (Rust drs-core, Go drs-verify, TypeScript drs-sdk) must agree on.
 *
 * Run: node fixtures/conformance/generate.mjs
 * Requires: @noble/ed25519 and @noble/hashes from drs-sdk/node_modules
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const require = createRequire(
  join(dirname(fileURLToPath(import.meta.url)), "../../drs-sdk/package.json"),
);

const edPkg = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../drs-sdk/node_modules/@noble/ed25519/index.js",
);
const hashesPkg = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../drs-sdk/node_modules/@noble/hashes/sha256.js",
);
const sha512Pkg = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../drs-sdk/node_modules/@noble/hashes/sha512.js",
);

const ed = await import(edPkg);
const { sha256 } = await import(hashesPkg);
const { sha512 } = await import(sha512Pkg);

ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

const ROOT = dirname(fileURLToPath(import.meta.url));

function ensureDir(p) {
  mkdirSync(p, { recursive: true });
}

function writeJson(relPath, data) {
  const full = join(ROOT, relPath);
  ensureDir(dirname(full));
  writeFileSync(full, JSON.stringify(data, null, 2) + "\n");
  console.log(`  wrote ${relPath}`);
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64url(input) {
  const binary = Array.from(new TextEncoder().encode(input), (b) =>
    String.fromCharCode(b),
  ).join("");
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function base64urlBytes(bytes) {
  const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function jcsSerialise(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value))
      throw new Error("jcsSerialise: non-finite number is not valid JSON");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(jcsSerialise).join(",")}]`;
  }
  if (typeof value === "object") {
    const sortedKeys = Object.keys(value).sort();
    const entries = sortedKeys.map(
      (k) => `${JSON.stringify(k)}:${jcsSerialise(value[k])}`,
    );
    return `{${entries.join(",")}}`;
  }
  return "null";
}

function computeChainHash(jwt) {
  const bytes = new TextEncoder().encode(jwt);
  const digest = sha256(bytes);
  return `sha256:${bytesToHex(digest)}`;
}

async function buildJwt(payload, signingKey) {
  const header = { alg: "EdDSA", typ: "JWT" };
  const headerB64 = base64url(jcsSerialise(header));
  const payloadB64 = base64url(jcsSerialise(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const sig = await ed.signAsync(
    new TextEncoder().encode(signingInput),
    signingKey,
  );
  return `${signingInput}.${base64urlBytes(sig)}`;
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = digits.length - 1; j >= 0; j--) {
      carry += 256 * digits[j];
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.unshift(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (const b of bytes) {
    if (b !== 0) break;
    result += "1";
  }
  for (const d of digits) {
    result += BASE58_ALPHABET[d];
  }
  return result;
}

function encodeDidKey(pubKeyBytes) {
  const multicodec = new Uint8Array(2 + pubKeyBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(pubKeyBytes, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

// ── Test key material ────────────────────────────────────────────────

const KEYS = {
  alice: {
    seed_hex:
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  },
  bob: {
    seed_hex:
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  },
  charlie: {
    seed_hex:
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
  },
};

for (const [name, k] of Object.entries(KEYS)) {
  const seed = hexToBytes(k.seed_hex);
  const pub = ed.getPublicKey(seed);
  k.pub_hex = bytesToHex(pub);
  k.did = encodeDidKey(pub);
  k.seed = seed;
  k.pub = pub;
}

console.log("Generating conformance fixtures...\n");
console.log("Test identities:");
for (const [name, k] of Object.entries(KEYS)) {
  console.log(`  ${name}: ${k.did}`);
}
console.log();

// ── 1. JCS vectors ──────────────────────────────────────────────────

const jcsVectors = [
  { id: "jcs-001-integer", input: 1, expected: "1" },
  { id: "jcs-002-string", input: "hello", expected: '"hello"' },
  { id: "jcs-003-null", input: null, expected: "null" },
  { id: "jcs-004-true", input: true, expected: "true" },
  { id: "jcs-005-false", input: false, expected: "false" },
  {
    id: "jcs-006-sorted-keys",
    input: { z: 26, m: 13, a: 1 },
    expected: '{"a":1,"m":13,"z":26}',
  },
  {
    id: "jcs-007-nested-keys",
    input: { outer: { z: 2, a: 1 }, a: 0 },
    expected: '{"a":0,"outer":{"a":1,"z":2}}',
  },
  {
    id: "jcs-008-array-preserved",
    input: [3, 1, 4, 1, 5, 9],
    expected: "[3,1,4,1,5,9]",
  },
  { id: "jcs-009-empty-object", input: {}, expected: "{}" },
  { id: "jcs-010-empty-array", input: [], expected: "[]" },
  {
    id: "jcs-011-mixed-types",
    input: { b: true, a: [1, "two", null], c: { d: false } },
    expected: '{"a":[1,"two",null],"b":true,"c":{"d":false}}',
  },
  {
    id: "jcs-012-string-escaping",
    input: { msg: 'hello "world"' },
    expected: '{"msg":"hello \\"world\\""}',
  },
  {
    id: "jcs-013-deeply-nested",
    input: { c: { b: { a: 1 } } },
    expected: '{"c":{"b":{"a":1}}}',
  },
  { id: "jcs-014-float", input: 1.5, expected: "1.5" },
  { id: "jcs-015-negative", input: -42, expected: "-42" },
];

for (const v of jcsVectors) {
  const actual = jcsSerialise(v.input);
  if (actual !== v.expected) {
    throw new Error(
      `JCS vector ${v.id} mismatch: got ${actual}, expected ${v.expected}`,
    );
  }
}

writeJson("jcs/vectors.json", {
  suite: "jcs-canonicalization",
  version: "4.0",
  description:
    "RFC 8785 JCS canonicalization test vectors. Input is an arbitrary JSON value. Expected is the canonical serialization.",
  vectors: jcsVectors,
});

// ── 2. Chain hash vectors ───────────────────────────────────────────

const chainHashInputs = [
  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0In0.signature",
  "header.payload.sig",
  "a.b.c",
];

const chainHashVectors = chainHashInputs.map((input, i) => ({
  id: `hash-${String(i + 1).padStart(3, "0")}`,
  input,
  expected: computeChainHash(input),
}));

writeJson("chain-hash/vectors.json", {
  suite: "chain-hash",
  version: "4.0",
  description:
    'Chain hash computation: SHA-256 of raw JWT bytes, formatted as "sha256:{hex}".',
  vectors: chainHashVectors,
});

// ── 3. Policy vectors ───────────────────────────────────────────────

const policyPassVectors = [
  {
    id: "pol-pass-001-identical",
    parent: { max_cost_usd: 10.0, pii_access: false, write_access: false },
    child: { max_cost_usd: 10.0, pii_access: false, write_access: false },
  },
  {
    id: "pol-pass-002-tighter-cost",
    parent: { max_cost_usd: 10.0 },
    child: { max_cost_usd: 5.0 },
  },
  {
    id: "pol-pass-003-subset-tools",
    parent: { allowed_tools: ["web_search", "file_read", "summarise"] },
    child: { allowed_tools: ["web_search"] },
  },
  {
    id: "pol-pass-004-child-adds-restriction",
    parent: { max_cost_usd: 50.0 },
    child: { max_cost_usd: 10.0, pii_access: false },
  },
  {
    id: "pol-pass-005-wildcard-parent-tools",
    parent: { allowed_tools: ["*"] },
    child: { allowed_tools: ["web_search", "file_read"] },
  },
  {
    id: "pol-pass-006-tighter-max-calls",
    parent: { max_calls: 100 },
    child: { max_calls: 50 },
  },
  {
    id: "pol-pass-007-subset-resources",
    parent: { allowed_resources: ["mcp://tools/a", "mcp://tools/b"] },
    child: { allowed_resources: ["mcp://tools/a"] },
  },
  {
    id: "pol-pass-008-subset-data-classes",
    parent: { allowed_data_classes: ["public", "internal"] },
    child: { allowed_data_classes: ["public"] },
  },
];

const policyFailVectors = [
  {
    id: "pol-fail-001-cost-escalation",
    parent: { max_cost_usd: 10.0 },
    child: { max_cost_usd: 20.0 },
    expected_keyword: "max_cost_usd",
  },
  {
    id: "pol-fail-002-pii-escalation",
    parent: { pii_access: false },
    child: { pii_access: true },
    expected_keyword: "pii_access",
  },
  {
    id: "pol-fail-003-write-escalation",
    parent: { write_access: false },
    child: { write_access: true },
    expected_keyword: "write_access",
  },
  {
    id: "pol-fail-004-tool-not-in-parent",
    parent: { allowed_tools: ["web_search"] },
    child: { allowed_tools: ["web_search", "delete_database"] },
    expected_keyword: "allowed_tools",
  },
  {
    id: "pol-fail-005-child-wildcard-tools",
    parent: { allowed_tools: ["web_search"] },
    child: { allowed_tools: ["*"] },
    expected_keyword: "allowed_tools",
  },
  {
    id: "pol-fail-006-max-calls-escalation",
    parent: { max_calls: 10 },
    child: { max_calls: 20 },
    expected_keyword: "max_calls",
  },
  {
    id: "pol-fail-007-resource-not-in-parent",
    parent: { allowed_resources: ["mcp://tools/a"] },
    child: { allowed_resources: ["mcp://tools/a", "mcp://tools/b"] },
    expected_keyword: "allowed_resources",
  },
  {
    id: "pol-fail-008-data-class-not-in-parent",
    parent: { allowed_data_classes: ["public"] },
    child: { allowed_data_classes: ["public", "confidential"] },
    expected_keyword: "allowed_data_classes",
  },
  {
    id: "pol-fail-009-child-omits-cost",
    parent: { max_cost_usd: 10.0 },
    child: {},
    expected_keyword: "max_cost_usd",
  },
  {
    id: "pol-fail-010-child-omits-tools",
    parent: { allowed_tools: ["web_search"] },
    child: {},
    expected_keyword: "allowed_tools",
  },
];

writeJson("policy/pass.json", {
  suite: "policy-attenuation-pass",
  version: "4.0",
  description:
    "Parent-child policy pairs that must pass attenuation check (child does not escalate).",
  vectors: policyPassVectors,
});

writeJson("policy/fail.json", {
  suite: "policy-attenuation-fail",
  version: "4.0",
  description:
    "Parent-child policy pairs that must fail attenuation check. expected_keyword identifies which field caused the violation.",
  vectors: policyFailVectors,
});

// ── 4. Temporal vectors ─────────────────────────────────────────────

const temporalVectors = [
  {
    id: "temp-001-valid-within-window",
    nbf: 1000000,
    exp: 2000000,
    now: 1500000,
    valid: true,
  },
  {
    id: "temp-002-not-yet-valid",
    nbf: 2000000,
    exp: 3000000,
    now: 1500000,
    valid: false,
    expected_code: "NOT_YET_VALID",
  },
  {
    id: "temp-003-expired",
    nbf: 1000000,
    exp: 1500000,
    now: 2000000,
    valid: false,
    expected_code: "EXPIRED",
  },
  {
    id: "temp-004-exact-nbf-boundary",
    nbf: 1500000,
    exp: 2000000,
    now: 1500000,
    valid: true,
  },
  {
    id: "temp-005-exact-exp-boundary",
    nbf: 1000000,
    exp: 1500000,
    now: 1500000,
    valid: true,
  },
  {
    id: "temp-006-null-exp-valid",
    nbf: 1000000,
    exp: null,
    now: 9999999999,
    valid: true,
  },
  {
    id: "temp-007-just-expired",
    nbf: 1000000,
    exp: 1500000,
    now: 1500001,
    valid: false,
    expected_code: "EXPIRED",
  },
];

writeJson("temporal/vectors.json", {
  suite: "temporal-validity",
  version: "4.0",
  description:
    "Temporal validity test vectors. exp=null means no expiry (standing delegation).",
  vectors: temporalVectors,
});

// ── 5. Revocation vectors ───────────────────────────────────────────

const revocationVectors = [
  { id: "rev-001-not-revoked", status_list_index: 0, is_revoked: false },
  { id: "rev-002-revoked", status_list_index: 42, is_revoked: true },
  { id: "rev-003-not-revoked-high-idx", status_list_index: 9999, is_revoked: false },
];

writeJson("revocation/vectors.json", {
  suite: "revocation",
  version: "4.0",
  description:
    "Revocation status vectors. Conformance tests configure a local store with revoked indices and verify lookup.",
  vectors: revocationVectors,
});

// ── 6. Receipt vectors (signed JWTs with known keys) ────────────────

const rootPayload = {
  iss: KEYS.alice.did,
  sub: KEYS.alice.did,
  aud: KEYS.bob.did,
  drs_v: "4.0",
  drs_type: "delegation-receipt",
  cmd: "/mcp/tools/call",
  policy: {
    max_cost_usd: 10.0,
    pii_access: false,
    write_access: false,
    allowed_tools: ["web_search", "file_read"],
  },
  nbf: 1700000000,
  exp: 1800000000,
  iat: 1700000001,
  jti: "dr:conformance-root-001",
  drs_root_type: "human",
  drs_consent: {
    method: "explicit-ui-click",
    timestamp: "2026-01-01T00:00:00Z",
    session_id: "conformance-session-001",
    policy_hash:
      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    locale: "en-GB",
  },
};

const rootJwt = await buildJwt(rootPayload, KEYS.alice.seed);
const rootHash = computeChainHash(rootJwt);

const subPayload = {
  iss: KEYS.bob.did,
  sub: KEYS.alice.did,
  aud: KEYS.charlie.did,
  drs_v: "4.0",
  drs_type: "delegation-receipt",
  cmd: "/mcp/tools/call",
  policy: {
    max_cost_usd: 5.0,
    pii_access: false,
    write_access: false,
    allowed_tools: ["web_search"],
  },
  nbf: 1700000000,
  exp: 1800000000,
  iat: 1700000002,
  jti: "dr:conformance-sub-001",
  prev_dr_hash: rootHash,
};

const subJwt = await buildJwt(subPayload, KEYS.bob.seed);
const subHash = computeChainHash(subJwt);

const invPayload = {
  iss: KEYS.charlie.did,
  sub: KEYS.alice.did,
  drs_v: "4.0",
  drs_type: "invocation-receipt",
  cmd: "/mcp/tools/call",
  args: {
    tool: "web_search",
    query: "DRS specification",
    estimated_cost_usd: 0.5,
  },
  dr_chain: [rootHash, subHash],
  tool_server: "mcp://tools.example.com",
  iat: 1700000003,
  jti: "inv:conformance-inv-001",
};

const invJwt = await buildJwt(invPayload, KEYS.charlie.seed);

const receiptKeys = {};
for (const [name, k] of Object.entries(KEYS)) {
  receiptKeys[name] = {
    seed_hex: k.seed_hex,
    pub_hex: k.pub_hex,
    did: k.did,
  };
}

writeJson("receipts/root-delegation.json", {
  suite: "receipt-root-delegation",
  version: "4.0",
  note: "CONFORMANCE TEST KEY ONLY — not for production use",
  keys: receiptKeys,
  payload: rootPayload,
  jwt: rootJwt,
  chain_hash: rootHash,
});

writeJson("receipts/sub-delegation.json", {
  suite: "receipt-sub-delegation",
  version: "4.0",
  note: "CONFORMANCE TEST KEY ONLY — not for production use",
  keys: receiptKeys,
  parent_jwt: rootJwt,
  parent_hash: rootHash,
  payload: subPayload,
  jwt: subJwt,
  chain_hash: subHash,
});

writeJson("receipts/invocation.json", {
  suite: "receipt-invocation",
  version: "4.0",
  note: "CONFORMANCE TEST KEY ONLY — not for production use",
  keys: receiptKeys,
  chain_receipts: [rootJwt, subJwt],
  chain_hashes: [rootHash, subHash],
  payload: invPayload,
  jwt: invJwt,
});

writeJson("receipts/full-chain-bundle.json", {
  suite: "receipt-full-chain-bundle",
  version: "4.0",
  note: "CONFORMANCE TEST KEY ONLY — not for production use",
  description:
    "Complete valid chain bundle for end-to-end verification. All implementations must accept this bundle.",
  keys: receiptKeys,
  bundle: {
    bundle_version: "4.0",
    invocation: invJwt,
    receipts: [rootJwt, subJwt],
  },
  expected_result: {
    valid: true,
    context: {
      root_principal: KEYS.alice.did,
      root_type: "human",
      chain_depth: 2,
      leaf_policy: subPayload.policy,
    },
  },
});

console.log("\nAll conformance fixtures generated successfully.");
