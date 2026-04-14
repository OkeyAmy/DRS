# Tutorial: End-to-End Trace

This tutorial traces one complete tool call through the full DRS lifecycle — from the human granting authority to the auditor reading the evidence. It covers every actor and every component.

## The scenario

- **Amara (End User):** grants a research agent permission to use `web_search`, spend up to £50
- **Research Agent:** delegates to a sub-agent with tighter constraints (£5, `web_search` only)
- **Sub-Agent:** calls `web_search` on the tool server
- **Tool Server:** runs `verify_chain` before executing
- **Auditor:** reconstructs the chain afterwards

---

## Step 1: Amara grants authority

Amara sees a consent UI on the developer's application:

```
Research Agent wants permission to:
✓  Search the web
✗  Cannot access personal data
✗  Cannot spend more than £50.00

This permission lasts 30 days.  [Allow] [Deny]
```

Amara clicks **Allow**. The SDK issues the root DR:

```
Root DR JWT payload (keys sorted by JCS):
{
  "aud": "did:key:z6MkAgent1...",
  "cmd": "/mcp/tools/call",
  "drs_consent": {
    "locale": "en-GB",
    "method": "explicit-ui-click",
    "policy_hash": "sha256:a1b2c3...",   ← SHA-256 of the text Amara saw
    "session_id": "sess:abc-123",
    "timestamp": "2026-03-28T10:30:00Z"
  },
  "drs_root_type": "human",
  "drs_type": "delegation-receipt",
  "drs_v": "4.0",
  "exp": 1748437800,
  "iat": 1743000000,
  "iss": "did:key:z6MkAmara...",
  "jti": "dr:8f3a2b1c-4d5e-4abc-8b9c-0d1e2f3a4b5c",
  "nbf": 1743000000,
  "policy": { "allowed_tools": ["web_search"], "max_cost_usd": 50 },
  "prev_dr_hash": null,
  "sub": "did:key:z6MkAmara..."
}
```

The JWT is signed with Amara's Ed25519 private key.

---

## Step 2: Research Agent evaluates and sub-delegates

Before acting, the Research Agent evaluates the proposed `web_search` call against its current policy:
- `web_search` ∈ `allowed_tools` ✓
- `estimated_cost: 0.02` ≤ `max_cost_usd: 50` ✓

The Research Agent decides to delegate to the Sub-Agent with tighter constraints (POLA):

```
Sub-DR JWT payload:
{
  "aud": "did:key:z6MkAgent2...",
  "cmd": "/mcp/tools/call",
  "drs_type": "delegation-receipt",
  "drs_v": "4.0",
  "exp": 1743003600,          ← 1 hour (shorter than Amara's 30 days)
  "iat": 1743000010,
  "iss": "did:key:z6MkAgent1...",
  "jti": "dr:1a2b3c4d-5e6f-4xyz-9abc-def012345678",
  "nbf": 1743000000,
  "policy": { "allowed_tools": ["web_search"], "max_cost_usd": 5 },
  "prev_dr_hash": "sha256:abc123...",   ← SHA-256 of rootDR JWT bytes
  "sub": "did:key:z6MkAmara..."         ← unchanged
}
```

---

## Step 3: Sub-Agent creates the invocation receipt

The Sub-Agent records the actual tool call:

```
Invocation Receipt JWT payload:
{
  "args": {
    "estimated_cost_usd": 0.02,
    "query": "Monad TPS benchmarks",
    "tool": "web_search"
  },
  "cmd": "/mcp/tools/call",
  "dr_chain": [
    "sha256:abc123...",   ← SHA-256 of rootDR
    "sha256:def456..."    ← SHA-256 of subDR
  ],
  "drs_type": "invocation-receipt",
  "drs_v": "4.0",
  "iat": 1743000300,
  "iss": "did:key:z6MkAgent2...",
  "jti": "inv:7h5c4d3e-2a3b-4c5d-6e7f-8a9b0c1d2e3f",
  "sub": "did:key:z6MkAmara...",
  "tool_server": "did:key:z6MkToolServer..."
}
```

---

## Step 4: Tool server receives and verifies

The Sub-Agent sends:

```
POST /mcp/tools/call HTTP/1.1
Authorization: Bearer <oauth-token>
X-DRS-Bundle: eyJidW5kbGVfdmVyc2lvbiI6IjQuMCIsImludm9jYXRpb24i...
Content-Type: application/json

{"tool": "web_search", "query": "Monad TPS benchmarks"}
```

The MCP middleware runs `verify_chain`:

```
Block A: receipts=[rootDR, subDR], invocation present                → PASS ✓
Block B: rootDR.aud == subDR.iss (z6MkAgent1)                        → PASS ✓
         subDR.prev_dr_hash == sha256(rootDR)                         → PASS ✓
         inv.dr_chain matches [sha256(rootDR), sha256(subDR)]         → PASS ✓
Block C: Ed25519 verify rootDR (Amara's key)                         → PASS ✓
         Ed25519 verify subDR (Agent1's key)                          → PASS ✓
         Ed25519 verify invocation (Agent2's key)                     → PASS ✓
Block D: web_search ∈ allowed_tools at both DR levels                → PASS ✓
         0.02 ≤ 5 (subDR) ≤ 50 (rootDR)                             → PASS ✓
         subDR policy ⊆ rootDR policy (attenuation check)            → PASS ✓
Block E: now=1743000300 ∈ [1743000000, 1743003600] (subDR window)    → PASS ✓
         now=1743000300 ∈ [1743000000, 1748437800] (rootDR window)   → PASS ✓
Block F: rootDR jti "dr:8f3a..." not in status list                  → PASS ✓
         subDR jti "dr:1a2b..." not in status list                   → PASS ✓

RESULT: VALID — executing tool call
```

---

## Step 5: Tool executes and emits event

The tool server runs `web_search` and emits:

```json
{
  "event": "drs:tool-call",
  "root_principal": "did:key:z6MkAmara...",
  "chain_depth": 2,
  "command": "/mcp/tools/call",
  "tool": "web_search",
  "policy_result": "pass",
  "cost_usd": 0.02,
  "inv_jti": "inv:7h5c4d3e-..."
}
```

Amara's activity feed updates: *"Research agent used web_search — £0.02 of £50.00 budget used."*

---

## Step 6: Auditor reconstructs the chain (later)

Three months later, a compliance officer wants evidence:

```bash
pnpm exec drs verify bundle.json
pnpm exec drs audit bundle.json
```

The compliance officer does not need to contact the operator. The evidence is in
the signed bundle plus the verifier output. The current `drs audit` command is
compact rather than full forensic export, but it still exposes the key receipt
and invocation fields.
