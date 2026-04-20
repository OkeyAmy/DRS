# End-to-end integration tests

These tests prove the **published artifacts** of DRS work together. They
do not depend on anything inside the monorepo source tree — a fresh clone
plus the published npm package plus the published Docker image is the
intended starting state.

## What's exercised

- `@okeyamy/drs-sdk` from npm → issues a delegation chain
- `ghcr.io/okeyamy/drs-verify` from GHCR → verifies it over HTTP
- Failure paths: tampered signature, broken chain, replay
- Operational endpoints: `/healthz`, `/readyz`, `/metrics`

## Prereqs

- Docker with `docker compose` (v2) available as a subcommand
- Node.js 20+
- pnpm (install: `npm i -g pnpm`)

## Run

```bash
cd integration-tests
pnpm install
./run.sh
```

`run.sh` starts the verifier via Docker Compose, waits for `/readyz`,
runs the test suite, then tears everything down.

## Override the version under test

By default the tests target the `latest` image and the latest SDK.
To pin to a specific version — e.g., to validate a release candidate
before promoting the tag — set:

```bash
DRS_VERIFY_TAG=v0.2.0-rc.1 ./run.sh
```

To test a locally-built image (for CI pre-merge):

```bash
docker build -t drs-verify:local ../drs-verify
DRS_VERIFY_IMAGE=drs-verify:local ./run.sh
```

## CI

Wire this workflow into `.github/workflows/e2e.yml` with a `docker compose`
service so every PR exercises the real HTTP surface.
