# DRS Practical Assessment Risk Register

| ID | Risk | Layer | STRIDE | Severity | Likelihood | Evidence status | Next action |
|---|---|---|---|---|---|---|---|
| R-001 | Integrators may execute a request body that differs from signed invocation arguments if they do not enforce body binding. | Middleware / tool server | Tampering | High | Medium | Persona walkthrough proves verifier reports mismatch; handler enforcement must be verified per adapter. | Add adapter-specific runbook evidence. |
| R-002 | Memory nonce backend does not share replay state across replicas. | `drs-verify` deployment | Elevation of Privilege | Medium | Medium | Documented behavior; distributed runtime evidence pending. | Run Redis versus memory replay scenario. |
| R-003 | Operators may expose metrics listener unintentionally if network policy is weak. | Deployment / observability | Information Disclosure | Medium | Low | Evidence pending. | Run metrics exposure scenario with explicit bind address. |
| R-004 | Product readers may confuse example-level readiness with production readiness. | Documentation / adoption | Repudiation | Medium | Medium | Mitigated by assessment warnings and persona README. | Keep examples explicit about controlled local scope. |
| R-005 | Docker/published-artifact behavior may drift from local source behavior. | Deployment / supply chain | Tampering | High | Medium | Local Docker Compose run is blocked by `http+docker` runtime error. | Fix Docker Compose environment or capture equivalent CI evidence before claiming published-artifact validation. |

## Severity Rule

Severity is assigned only after runtime evidence exists or after a documented
deployment limitation is confirmed from authoritative project docs. Speculative
risks remain open questions, not findings.
