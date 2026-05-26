# DRS Persona Examples

Each persona example must be backed by a real controlled-environment run, not
mocked behavior. The first runnable persona package is
`examples/drs-persona-walkthrough`.

| Persona | Question answered | Required evidence | Current runnable path |
|---|---|---|---|
| SDK integrator | How do I issue receipts and submit a bundle? | SDK command/script and `/verify` response | `pnpm --filter drs-persona-walkthrough test` |
| Node middleware integrator | How does body binding protect my handler? | Middleware run showing handler rejects tamper | `S-middleware-handler-block` capture proves `BINDING_MISMATCH` with `handlerCalls: 0` |
| Go verifier operator | How do I deploy and monitor verifier health? | Docker logs, health/readiness, metrics | `operator-guide.md` documents proven local surfaces and blocked Docker evidence. |
| MCP/A2A builder | Which integration shape is safe for execution integrity? | Shape 1 pass and Shape 2 limitation walkthrough | `integration-shapes.md` documents Shape 1 evidence and Shape 2 limits. |
| Auditor | How do I reconstruct evidence? | Bundle, chain hash, consent, regulatory context, verification response | `drs-persona-walkthrough` audit test |
| Security engineer | What abuse cases were tested? | Threat model and runtime results links | Policy denial and body-binding mismatch tests |
| Product evaluator | What is production-ready and what is pilot-only? | Readiness mapping and risk register | `product-readiness.md` documents pilot-safe wording and production blockers. |

## Current Persona Walkthrough

`examples/drs-persona-walkthrough` covers four concrete paths with real DRS
components:

1. valid support lookup,
2. audit context reconstruction,
3. forbidden refund denial,
4. signed-intent versus body mismatch detection.

The walkthrough uses canonical metadata ids such as `eu-ai-act-art12` and
`soc2-security`. Friendly labels are display-only and do not claim legal
compliance or certification.
