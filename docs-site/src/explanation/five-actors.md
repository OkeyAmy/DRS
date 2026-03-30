# The Five Actors

DRS defines five actors. Every use case in this documentation maps to one or more of them.

## 1. End User (Human granting authority)

The human whose data or resources are at stake. They grant the initial delegation through a consent UI that translates policy into plain English.

**What they see:**
```
Research Agent wants permission to:
✓  Search the web
✓  Save files to your workspace
✗  Cannot access personal data
✗  Cannot spend more than £50.00

This permission lasts 30 days. Revoke it at any time.
```

The `drs_consent` field in the root DR records evidence of this consent: the method (`explicit-ui-click`), timestamp, session ID, and a SHA-256 hash of the human-readable text the user actually saw — not the machine-readable policy JSON.

**Key concern:** Did I actually authorise this specific action?

---

## 2. Developer

Integrates DRS into MCP tool servers or agent runtimes. Interacts with the TypeScript SDK (`@drs/sdk`) and the drs-verify HTTP API.

**What they do:**
- Call `issueRootDelegation` / `issueSubDelegation` from the SDK
- Add `X-DRS-Bundle` header to MCP requests
- Deploy the Go middleware in front of their tool server
- Use the CLI (`drs verify`, `drs audit`, `drs policy`) for debugging

**Key concern:** How do I integrate this in a day?

---

## 3. Agent Runtime

The automated system that acts on the user's behalf. Can be a single agent or a chain of agents delegating to sub-agents.

**What it does:**
- Evaluates its policy before every action (POLA — principle of least authority)
- Issues sub-delegation receipts when delegating to sub-agents
- Escalates out-of-policy requests to a supervisor agent (not a human)
- Auto-renews delegations before expiry for machine-rooted standing delegations
- Stops immediately when any policy constraint is exceeded

**Key concern:** Can I take this action within my current delegation?

---

## 4. Tool Server (Operator)

Receives MCP requests with `X-DRS-Bundle` headers. Runs full chain verification before executing any tool. Deployed by the enterprise operator.

**What it does:**
- Extracts and parses the DRS bundle from the HTTP header
- Runs `verify_chain` (Blocks A–F) on every request — fail-closed
- Rejects requests with invalid bundles
- Rate-limits by `root_principal` (not just agent DID) to prevent agent-churn bypass
- Emits `drs:tool-call` activity events

**Key concern:** Is this agent authorised to call this tool with these arguments?

---

## 5. Auditor / Compliance Officer

Reconstructs delegation chains after the fact to produce evidence for regulators, legal proceedings, or internal investigation. Does not need operator cooperation.

**What they do:**
```bash
drs audit retrieve --inv-jti "inv:7h5c4d3e-..."
drs verify evidence.json
drs audit export --inv-jti "inv:7h5c4d3e-..." --format eu-ai-act
```

**Key concern:** Can I prove what happened to a standard that satisfies EU AI Act Article 12?

---

## How the actors interact

```
End User ──grant──► Agent Runtime ──sub-delegate──► Sub-Agent
                                                          │
                                                     invoke tool
                                                          ▼
                                                    Tool Server
                                                  (verify_chain)
                                                          │
                                                    emit event
                                                          ▼
                                                    Auditor reads
                                                    evidence later
```

The Developer builds both the agent runtime and the tool server integrations. The Operator deploys and configures the verification infrastructure.
