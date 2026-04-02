# DRS Expense Agent

A complete, runnable example showing how to integrate the **Delegation Receipt Standard (DRS)**
into an AI agent. Amara (a human) delegates an AI agent to process expense reports. Every tool
call goes through a local **Expense Tool Server** that verifies the DRS bundle before executing —
this is the correct DRS integration pattern.

## What This Demonstrates

| Concept | How it appears in this demo |
|---|---|
| Human delegation | Amara signs a JWT granting the agent permission to read and categorize expenses |
| MCP command path | `cmd: "/mcp/tools/call"` — the standard DRS command namespace |
| Consent record | Amara's delegation records method, session_id, and policy_hash |
| `allowed_tools` policy | Only `read_expenses` and `categorize_transaction` are permitted |
| X-DRS-Bundle header | Agent sends base64url(ChainBundle) in HTTP header to the tool server |
| Tool server enforcement | The tool server calls drs-verify before executing — tools never run without a valid chain |
| Policy violation | `approve_payment` is not in `allowed_tools` → `POLICY_VIOLATION` on every call |
| Independent verification | The Go server checks signatures, chain integrity, policy, and temporal validity |

## Prerequisites

- Node.js ≥ 20
- pnpm
- Docker (with docker-compose v1 — `docker-compose` command)
- A [Gemini API key](https://aistudio.google.com/apikey)

## Setup

```bash
# 1. Copy env file and add your Gemini API key
cp .env.example .env
# Edit .env and set: GEMINI_API_KEY=your-key-here

# 2. Build the drs-verify binary (requires Go 1.22+, runs locally — no Docker Hub needed)
cd ../../drs-verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o drs-verify-bin ./cmd/server
cd ../examples/drs-expense-agent

# 3. Start drs-verify in Docker
docker-compose up -d

# 4. Confirm it is running
docker-compose ps
# drs-verify should show state "Up"

# 5. Install dependencies
pnpm install

# 6. Run the demo
pnpm start
```

## Architecture

```
Amara (did:key, Ed25519)
  │
  │  signs Root Delegation Receipt (JWT):
  │    iss: amara.did
  │    aud: agent.did
  │    cmd: "/mcp/tools/call"
  │    policy: { allowed_tools: ["read_expenses", "categorize_transaction"] }
  │    drs_consent: { method: "explicit-click", session_id, policy_hash }
  │    drs_root_type: "human"
  ▼
Agent (did:key, Ed25519)
  │
  │  For each Gemini tool call:
  │    1. Issues Invocation Receipt (JWT):
  │         iss: agent.did
  │         args: { tool: "read_expenses", ... }
  │         dr_chain: [sha256(rootDelegation)]
  │    2. Builds ChainBundle:
  │         { bundle_version: "4.0", receipts: [rootDR], invocation: invJwt }
  │    3. Serialises bundle → base64url
  │
  │  HTTP POST /mcp/tools/call
  │  X-DRS-Bundle: base64url(ChainBundle)
  ▼
Expense Tool Server (:3001)         ← the DRS trust boundary
  │
  │  1. Parses X-DRS-Bundle header
  │  2. POST /verify → drs-verify Go service (:8080)
  │       Block A: bundle is complete
  │       Block B: chain hash linkage is intact
  │       Block C: Ed25519 signatures are valid
  │       Block D: args["tool"] ∈ policy.allowed_tools  ← policy check
  │       Block E: delegation has not expired
  │       Block F: delegation has not been revoked
  │
  │  VALID   → executes tool, returns 200
  └  INVALID → returns 403 (tool never executes)
```

## Expected Output

```
╔══════════════════════════════════════════════════════════╗
║         DRS Expense Agent — Live Demo                    ║
║  Delegation Receipt Standard + Gemini Function Calling   ║
╚══════════════════════════════════════════════════════════╝

[DRS] Generating Ed25519 keypairs...
  Amara (human)  : did:key:z6Mk...
  Agent          : did:key:z6Mk...
  Tool Server    : did:key:z6Mk...

[DRS] Issuing root delegation receipt (Amara → Agent)...
  Session ID : 550e8400-e29b-41d4-a716-446655440000
  Command    : /mcp/tools/call
  Policy     :
    Permitted tools: read_expenses, categorize_transaction.
  JWT issued ✓  (EdDSA/Ed25519)

[Tool Server] Starting on :3001...
[Tool Server] Ready — POST /mcp/tools/call verifies X-DRS-Bundle before executing

[Gemini] Starting expense processing session...

[Gemini → Tool Server] read_expenses({})
[Tool Server] {"expenses":[...],"count":5}
  [DRS] ✓ VALID — read_expenses
        root_principal : did:key:z6Mk...
        root_type      : human
        chain_depth    : 1
        allowed_tools  : read_expenses, categorize_transaction
        consent        : session=550e8400... method=explicit-click

[Gemini → Tool Server] categorize_transaction({"transaction_id":"TXN-001","category":"infrastructure"})
[Tool Server] {"success":true,"message":"Transaction TXN-001 categorized as \"infrastructure\"."}
  [DRS] ✓ VALID — categorize_transaction
        ...

[Gemini → Tool Server] approve_payment({"transaction_id":"TXN-001"})
[Tool Server] {"drs_error":{"code":"POLICY_VIOLATION","message":"receipt[0] policy violated..."}}
  [DRS] ✗ INVALID — approve_payment
        code       : POLICY_VIOLATION
        message    : receipt[0] policy violated by invocation args: tool not permitted:
                     allowed [read_expenses categorize_transaction], requested "approve_payment"
        suggestion : The invocation arguments exceed the permissions granted in the delegation chain.
```

## How Policy Enforcement Works

```
Amara's delegation policy:
  allowed_tools: ["read_expenses", "categorize_transaction"]
                                   ↑
                         approve_payment is absent

Agent invocation args for approve_payment:
  { tool: "approve_payment", transaction_id: "TXN-001" }

drs-verify Block D1 — policy.Evaluate():
  for each DR in the chain:
    if args["tool"] not in policy.allowed_tools → POLICY_VIOLATION

Tool server receives POLICY_VIOLATION → returns 403 → tool never executes.
```

## Key Integration Points

**Issuing the delegation** (`src/delegation.ts`):
```typescript
const rootDelegation = await issueRootDelegation({
  signingKey: amara.privateKey,
  issuerDid: amara.did,
  audienceDid: agent.did,
  cmd: "/mcp/tools/call",
  policy: { allowed_tools: ["read_expenses", "categorize_transaction"] },
  rootType: "human",
  consent: { method: "explicit-click", session_id, timestamp, policy_hash, locale },
});
```

**Building the bundle per tool call** (`src/agent.ts`):
```typescript
const invocationJwt = await issueInvocation({
  signingKey: agent.privateKey,
  issuerDid: agent.did,
  cmd: "/mcp/tools/call",
  args: { tool: "approve_payment", transaction_id: "TXN-001" },
  drChain: [computeChainHash(rootDelegation)],
  toolServer: toolServer.did,
});

const bundle = buildBundle([rootDelegation], invocationJwt);
const bundleHeader = serialiseBundle(bundle); // base64url

await fetch("http://localhost:3001/mcp/tools/call", {
  method: "POST",
  headers: { "X-DRS-Bundle": bundleHeader, "Content-Type": "application/json" },
  body: JSON.stringify({ tool: "approve_payment", transaction_id: "TXN-001" }),
});
```

**Verifying at the tool server boundary** (`src/tool-server.ts`):
```typescript
const bundle = parseBundle(req.headers["x-drs-bundle"]);
const result = await client.verify(bundle);   // POST /verify → Go service

if (!result.valid) {
  res.writeHead(403);
  res.end(JSON.stringify({ drs_error: result.error }));
  return;
}
// Only here do we execute the tool
```

## Project Structure

```
├── docker-compose.yml    starts drs-verify on :8080
├── .env.example          GEMINI_API_KEY, DRS_VERIFY_URL, TOOL_SERVER_PORT
├── data/
│   └── expenses.json     5 real expense records (TXN-001 starts as uncategorized)
└── src/
    ├── main.ts           entry point — keys, delegation, tool server, agent
    ├── keys.ts           Ed25519 keygen + did:key derivation (multicodec 0xed01 + base58btc)
    ├── delegation.ts     issues root delegation with consent record and policy
    ├── tool-server.ts    HTTP tool server — verifies X-DRS-Bundle before executing
    ├── agent.ts          Gemini function-calling loop + DRS bundle per tool call
    ├── tools.ts          real tool implementations (file I/O, no mocks)
    └── verify.ts         shared VerificationResult printer
```
