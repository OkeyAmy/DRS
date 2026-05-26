# DRS Persona Walkthrough

A compact, runnable example for people evaluating where DRS fits in their system.
It uses real SDK-issued Ed25519 JWT receipts and the real Go `drs-verify` service.
There are no mocked verifier results.

## Personas

| Persona | What they learn |
|---|---|
| Product builder | How an allowed tool call becomes a signed invocation bundle. |
| Auditor | How consent and regulatory metadata come back from verifier context. |
| Security engineer | How ungranted tools fail closed with `POLICY_VIOLATION`. |
| Tool owner | How the verifier detects a body different from signed intent. |

## Run

```bash
pnpm install
pnpm --filter drs-persona-walkthrough start
```

By default the example starts a controlled local verifier with:

```bash
go run ./cmd/server
```

from `../../drs-verify`, listening on a loopback-only high port selected by the
test harness. To use an already running verifier instead:

```bash
DRS_VERIFY_URL=http://localhost:8080 pnpm --filter drs-persona-walkthrough start
```

## Test

```bash
pnpm --filter drs-persona-walkthrough test
pnpm --filter drs-persona-walkthrough capture -- .local/drs-assessment/responses
pnpm --filter drs-persona-walkthrough typecheck
```

The tests start the real Go verifier unless `DRS_VERIFY_URL` is set. Each test
issues fresh invocation receipts so nonce replay protection remains active.
The capture command writes structured verifier request/response evidence without
recording private keys or raw JWTs.

## Why this example exists

The larger `drs-expense-agent` example shows a full Gemini-driven agent. This
walkthrough is smaller and role-oriented: it lets a builder, operator, auditor,
or security reviewer run the minimum live flow needed to see DRS enforcement.
