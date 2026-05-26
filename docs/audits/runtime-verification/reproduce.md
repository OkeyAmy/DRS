# Reproducing the DRS Practical Assessment

## Prerequisites

- Node.js 20 or newer
- pnpm 9 or newer
- Go toolchain compatible with `drs-verify/go.mod`
- Docker only for scenarios that explicitly require Compose or Redis

## Lightweight Persona Evidence

Run the compact persona walkthrough against a controlled local verifier:

```bash
pnpm install
pnpm --filter drs-persona-walkthrough test
pnpm --filter drs-persona-walkthrough capture -- .local/drs-assessment/responses
pnpm --filter drs-persona-walkthrough start
```

Metadata validation evidence is included in the test run and in every captured
response file under `metadataValidation`.
Middleware handler-blocking evidence is captured in
`S-middleware-handler-block.json` with `handlerCalls: 0`.

To target an already running verifier:

```bash
DRS_VERIFY_URL=http://localhost:8080 pnpm --filter drs-persona-walkthrough test
```

## Assessment Runner

Run the local evidence collector:

```bash
scripts/assessment/run-live-assessment.sh
```

The runner writes raw output under `.local/drs-assessment/live-*`. Do not commit
that directory. Copy only sanitized conclusions into the assessment reports.

The runner currently captures:

- TypeScript typecheck and test logs,
- SDK and MCP server build logs,
- live `/verify`, `/admin/revoke`, replay, tamper, and `/metrics` scenarios,
- persona walkthrough tests and structured verifier/middleware responses,
- Go verifier package tests,
- Rust core tests.

Docker/Redis/published-image E2E remains separate and is currently blocked in
this local environment by the Docker Compose `http+docker` error recorded in
`evidence.md`.

## No-Mock Rule

If a command does not exercise real SDK issuance, real verifier behavior, real
middleware behavior, or real HTTP responses, it may support development but it
does not count as final assessment evidence.
