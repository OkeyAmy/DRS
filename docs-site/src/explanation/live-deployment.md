# A Live Deployment, End to End

This page walks one complete DRS flow through a realistic production
deployment — every receipt, every check, every actor. Field names, error
codes, and environment variables are the real ones from the implementation.

## The setting

Picture a consumer fintech whose AI assistant already handles support at the
scale of hundreds of human agents — and can move money: issue refunds, cancel
orders, adjust payment plans. Every one of those actions is an AI acting on a
human's behalf. Without DRS, the proof that the human actually asked for it
is application logs — logs the company itself writes.

The [five actors](./five-actors.md), mapped onto this deployment:

| DRS actor | In this deployment |
|---|---|
| Human principal | Sarah, a customer asking for a refund |
| Agent runtime | the company's AI assistant |
| Developer | the engineer who integrated `@okeyamy/drs-sdk` into the assistant |
| Tool owner | the payments team running the `refund_order` tool server |
| Auditor | a financial regulator's examiner, six months later |

## Step 1 — Sarah consents (root delegation)

Sarah taps **"Yes, process my refund"** in the app. That tap is captured as a
`ConsentRecord` (method, timestamp, session ID, hash of the policy she saw,
locale), and the app mints the root **delegation receipt**:

```ts
import { issueRootDelegation } from "@okeyamy/drs-sdk";

const rootDr = await issueRootDelegation({
  signingKey: sarahKey,             // Ed25519, held client-side
  issuerDid: sarahDid,              // did:key:z6Mk...
  subjectDid: sarahDid,
  audienceDid: assistantDid,        // the AI assistant's identity
  cmd: "/mcp/tools/call",
  policy: {
    max_cost_usd: 120,              // refund cap — she saw this number
    allowed_tools: ["refund_order"],
    write_access: true,
  },
  nbf: now,
  exp: now + 900,                   // valid 15 minutes, then dead
  rootType: "human",
  consent: consentRecord,           // required — MISSING_CONSENT without it
});
```

The result is a signed JWT whose payload carries `drs_root_type: "human"` and
`drs_consent`. Her consent is *inside the signed bytes*, not in a log next to
them.

**Analogy:** a power of attorney with the amount, the specific power, and an
expiry written on it — not a verbal "yeah, go ahead."

## Step 2 — The assistant delegates down (sub-delegation)

The front assistant hands the task to a payments sub-agent. That is a
**sub-delegation**, and the SDK refuses to mint an illegal one *at issuance
time*, before the verifier ever sees it:

- the child `cmd` must equal or be a sub-path of the parent's —
  otherwise `CMD_ESCALATION`
- `checkPolicyAttenuation(parent, child)` — the sub-agent can receive
  `max_cost_usd: 120` or less, never 121 — otherwise `POLICY_ESCALATION`
- the child's validity window must sit inside the parent's — otherwise
  `TEMPORAL_BOUNDS_VIOLATION`
- `prev_dr_hash = sha256(parentJwt)` — each receipt cryptographically points
  at its parent

**Analogy:** you can photocopy the power of attorney and hand it to your
assistant with *less* authority written on it. Never more. And every copy has
the original stapled to it.

## Step 3 — The tool call (invocation bundle)

The payments sub-agent actually calls the tool. One SDK call packages
everything:

```ts
import { createInvocationBundle, serialiseBundle } from "@okeyamy/drs-sdk";

const bundle = await createInvocationBundle({
  rootReceipt: rootDr,
  signingKey: subAgentKey,
  issuerDid: subAgentDid,
  subjectDid: sarahDid,
  toolServer: "did:key:z6MkPaymentsToolServer", // which server this is FOR
  tool: "refund_order",
  args: { order_id: "ord_8812", amount_usd: 89.99, estimated_cost_usd: 89.99 },
});
```

The invocation receipt is a third signed JWT: the exact `args`, the
`tool_server` it is destined for, an `iat`, and a one-time `jti`
(`inv:` + UUID). The bundle — delegation receipts plus invocation — travels
base64url-encoded in the `X-DRS-Bundle` header on the normal HTTP request
(Shape 1), or in JSON-RPC `_meta` (Shape 2). DRS does not transport anything;
it rides the call you were already making.

## Step 4 — The door (tool server + drs-verify)

The payments team runs its refund service unchanged, with `drs-verify`
deployed as a sidecar:

```bash
docker pull ghcr.io/okeyamy/drs-verify
```

```bash
SERVER_IDENTITY=did:key:z6MkPaymentsToolServer  # this server's own identity
NONCE_STORE_BACKEND=redis                        # multi-replica replay protection
REDIS_URL=redis://...
STORE_DIR=/data                                  # audit storage
TSA_URL=https://freetsa.org/tsr                  # RFC 3161 timestamping
```

The Go `MCPMiddleware` is fail-closed: a request with no `X-DRS-Bundle`
header gets **401** before the refund handler ever runs. With a bundle
present, the verifier runs the six blocks, cheapest first:

| Block | Check | What dies here |
|---|---|---|
| A — Completeness | ≤ 16 receipts, invocation present — before any crypto | CPU-exhaustion chains (`CHAIN_TOO_DEEP`) |
| B — Structural | linkage, `prev_dr_hash` / `dr_chain` hashes match | spliced or reordered chains |
| C — Cryptographic | every Ed25519 signature, strict; DIDs resolved via LRU cache | forgery |
| D — Policy | attenuation down the whole chain; `estimated_cost_usd` ≤ `max_cost_usd` | escalation — a $500 refund on a $120 grant |
| E — Temporal | `nbf`/`exp` windows; invocation `iat` freshness | expired grants, stale invocations (`INVOCATION_STALE`) |
| F — Revocation | status list + local revocations | pulled authority |

Plus two checks the blocks alone cannot give you:

- **Replay** — the `jti` has been seen before → `REPLAY_DETECTED` (409). A
  captured request resent is dead. Redis-backed, so the guarantee holds
  across replicas.
- **Binding** — the request body is JCS-compared against the signed
  `invocation.args`. `binding: "mismatch"` means the agent signed
  "refund $89.99" but the body says $500. In `enforced` mode the middleware
  rejects it outright.

And `SERVER_IDENTITY`: a bundle minted for the payments server, replayed at
the invoicing server, fails with `TOOL_SERVER_MISMATCH`. The check is
fail-closed even when the variable is unset.

All checks pass → the handler runs with the `VerificationContext` (root
principal, consent record, leaf policy, chain depth) attached to the request
context. The refund executes. Measured end-to-end overhead for the whole
gate: ~5.5 ms median ([benchmark harness](https://github.com/OkeyAmy/drs-bench)).

**Analogy:** the bank vault does not trust the teller's word. One guard
counts the pages. One checks the staples. One checks every signature. One
checks the amount against the power of attorney. One checks the dates. One
calls the revocation desk. Any hand goes up, the drawer stays shut.

## Step 5 — Something goes wrong (revocation)

Sarah calls: "cancel that, my account was compromised." Operations hits
`POST /admin/revoke` (bearer `DRS_ADMIN_TOKEN`; the endpoint answers 503
unless the token is configured), or flips her bit in the W3C Bitstring
Status List. Every future bundle carrying her delegation fails Block F
within the status cache TTL (`STATUS_CACHE_TTL_SECS`, default 300 s).
Revocation checks are fail-closed: if the status list index is out of range
or the source errors, the capability is denied — never waved through.

## Step 6 — Six months later (the auditor)

The regulator asks: *prove this refund was authorised.* Because `STORE_DIR`
and `TSA_URL` were set, every receipt was stored with an RFC 3161 timestamp
token — third-party cryptographic proof of *when* it existed. The examiner
takes the bundle and verifies it **independently**: signatures against
public DIDs, chain hashes, the policy arithmetic, the consent record, the
timestamps. No database access, no trust in the company's logs. The receipt
proves itself.

That is the difference from logging. Logs say *"we recorded that she said
yes."* DRS says *"here are her signed bytes — check them yourself."*

## What each party actually integrated

- **App developer:** `pnpm add @okeyamy/drs-sdk`, three issuance calls,
  consent capture in the UI.
- **Tool owner:** one container (`ghcr.io/okeyamy/drs-verify`, pinned by
  digest), environment variables, routes wrapped in `MCPMiddleware` — or a
  plain HTTP gate that POSTs to `/verify` and executes only on
  `valid: true` + `binding: "match"`. No changes to the refund service
  itself.
- **A2A deployments:** the same via `A2AMiddleware` interceptors.
- **drs-core (Rust):** deliberately *not* deployed. It is the frozen,
  non-normative algorithm reference — it lacks Block F, replay protection,
  and binding by design. `drs-verify` is the only production verifier.

And what DRS deliberately did **not** do here: it did not log Sarah in
(OAuth and the IDP did), did not carry the message (HTTP/MCP did), did not
decide what `refund_order` means (the payments team did). It answers one
question, cryptographically: **was this exact action authorised by this
human, within these limits, right now — prove it.**
