# @okeyamy/drs-sdk

[![npm](https://img.shields.io/npm/v/@okeyamy/drs-sdk.svg)](https://www.npmjs.com/package/@okeyamy/drs-sdk)
[![license](https://img.shields.io/npm/l/@okeyamy/drs-sdk.svg)](https://github.com/OkeyAmy/DRS/blob/main/LICENSE)

TypeScript SDK for the **Delegation Receipt Standard (DRS)** — the issuance path.

DRS is a JWT-based delegation receipt system for agentic accountability: every step an
agent takes is backed by a signed, attenuated, hash-chained receipt that a verifier can
check independently. This package is how an issuer **mints** those receipts and assembles
the bundle that travels with a request. Verification itself is performed by the
[`drs-verify`](https://github.com/OkeyAmy/DRS/tree/main/drs-verify) service; this SDK only
issues receipts and offers a thin client for calling a verifier.

- **RFC 8785 (JCS)** canonicalization
- **Ed25519** signatures
- **`did:key`** identity
- **SHA-256** chain linkage (`prev_dr_hash` / `dr_chain`)

> Scope: issuance only. The SDK does not make trust decisions — that is the verifier's job.

## Install

```bash
pnpm add @okeyamy/drs-sdk
# or: npm install @okeyamy/drs-sdk
```

## Quick start

Issue a root delegation, build an invocation bundle for a tool call, and verify it
against a running `drs-verify`:

```ts
import {
  issueRootDelegation,
  createInvocationBundle,
  derivePublicKey,
  VerifyClient,
} from "@okeyamy/drs-sdk";

// 32-byte Ed25519 private keys (use `drs keygen` or your KMS in production).
const ownerKey = /* Uint8Array(32) */;
const agentKey = /* Uint8Array(32) */;

const ownerDid = "did:key:z6Mk...owner";
const agentDid = "did:key:z6Mk...agent";
const toolServer = "did:key:z6Mk...tool";

// 1. Owner delegates a constrained capability to the agent.
const rootReceipt = await issueRootDelegation({
  signingKey: ownerKey,
  issuerDid: ownerDid,
  subjectDid: ownerDid,
  audienceDid: agentDid,
  cmd: "/mcp/tools/call",
  policy: { allowed_tools: ["expenses.read"], max_cost_usd: 5 },
  nbf: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
});

// 2. Agent issues an invocation and assembles the chain bundle.
const bundle = await createInvocationBundle({
  rootReceipt,
  signingKey: agentKey,
  issuerDid: agentDid,
  subjectDid: ownerDid,
  toolServer,
  tool: "expenses.read",
  args: { month: "2026-06" },
});

// 3. Verify against drs-verify (the verifier decides allow/deny).
const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
const result = await client.verify(bundle, { body: { month: "2026-06" } });

if (!result.valid) {
  throw new Error(`denied: ${result.error?.code}`);
}
```

The verifier returns `valid: true | false` in the body. **Never** treat an HTTP `200`
as success on its own — read `result.valid`.

## API

### Issuance
- `issueRootDelegation(params)` — mint a root delegation receipt (JWT).
- `issueSubDelegation(params)` — attenuate and re-delegate down the chain.
- `issueInvocation(params)` — mint a leaf invocation receipt.
- `createInvocationBundle(params)` — convenience: root + invocation → ready-to-send bundle.
- `derivePublicKey(signingKey)` — Ed25519 public key from a 32-byte private key.
- `computeChainHash(...)`, `buildJwt(...)` — low-level chain/JWT primitives.

### Bundle & canonicalization
- `buildBundle`, `serialiseBundle`, `parseBundle` — assemble and (de)serialise a `ChainBundle`.
- `jcsSerialise(value)` — RFC 8785 JCS canonical JSON. Use this, never `JSON.stringify`.

### Policy
- `checkPolicyAttenuation(parent, child)` — confirm a child policy only narrows the parent.
- `translatePolicy(...)` — map a policy across representations.

### Verification client
- `new VerifyClient({ baseUrl, timeoutMs? })`
- `client.verify(bundle, { includeTimestamps?, body? })` → `VerificationResult`

### WASM (optional)
- `initWasm()`, `getWasmModule()`, `isWasmReady()` — load the `drs-core` Rust crypto core
  for canonicalization/signing parity with the verifier. Falls back to `@noble/ed25519`
  when not initialised.

### Operator config
- `validateOperatorConfig`, `parseOperatorConfig` — machine-to-machine standing-delegation
  trust model.

All exported types (`Policy`, `ChainBundle`, `VerificationResult`, `DrsError`, …) are
available from the package root.

## CLI

The package ships a `drs` binary:

```bash
drs keygen                 # generate an Ed25519 keypair + did:key
drs verify <bundle.json>   # verify a bundle against a drs-verify endpoint
drs policy <...>           # inspect / attenuate policies
drs translate <...>        # translate policy representations
drs audit <...>            # audit a receipt chain
```

## How it fits together

| Layer | Package | Role |
|---|---|---|
| Issuance | `@okeyamy/drs-sdk` (this) | mint receipts, assemble bundles, call the verifier |
| Crypto core | [`drs-core`](https://crates.io/crates/drs-core) (Rust/WASM) | JCS, SHA-256 chain hash, Ed25519 |
| Verification | [`drs-verify`](https://github.com/OkeyAmy/DRS/tree/main/drs-verify) (Go) | the `/verify` service + MCP/A2A middleware |

The Rust core compiles to both native and WASM, so issuance (SDK) and verification
(`drs-verify`) share one canonicalization implementation — chains cannot diverge across
languages.

## License

Apache-2.0 © Okey Amy
