# DRS Assessment Runbooks

Runbooks turn assessment scenarios into repeatable operator procedures. Every
runbook must identify the exact command, environment variables, expected output,
raw evidence path, sanitized report destination, and cleanup step.

## Available Runbooks

| Runbook | Purpose | Status |
|---|---|---|
| `persona-walkthrough.md` | Capture lightweight evidence from the persona example. | Ready |
| `metadata.md` | Validate regulatory/audit metadata boundaries. | Ready |
| Docker verifier runbook | Health/readiness/metrics evidence from container runtime. | Blocked: Docker Compose fails locally with `Not supported URL scheme http+docker`. |
| Redis replay runbook | Distributed nonce replay behavior. | Blocked: requires Docker/Redis environment that currently fails before startup. |
| Revocation runbook | Wrong-token, correct-token, and revoked-chain behavior. | Not implemented as a separate runbook; live evidence exists in `results.md` via `S-live-admin-revoke-*`. |

Current local Docker/Redis runbooks are blocked by the Docker Compose runtime
error recorded in `../evidence.md`.
