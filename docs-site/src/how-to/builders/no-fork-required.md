# You do not need to fork this repo

This page exists to remove a common confusion.

**Consuming DRS means pulling from package registries. It does not mean
cloning this repository into your source tree.**

All three layers are published. Pick the ones that match your role and
install them the way you'd install any other dependency.

| Layer | How builders get it | You edit this? |
|---|---|---|
| `drs-core` | `cargo add drs-core` (or via WASM inside `@okeyamy/drs-sdk`) | No — unless you're contributing back |
| `drs-verify` | `docker pull ghcr.io/okeyamy/drs-verify:latest` | No — it's a service, you run the image |
| `drs-sdk` | `pnpm add @okeyamy/drs-sdk` | No — regular npm dependency |

You only clone the repo if you want to:

- **contribute** (fix a bug, propose a feature, submit a PR)
- **build from source** (e.g. for air-gapped deployments where pulling
  from Docker Hub / GHCR is not allowed)
- **vendor a specific commit** (hash-pin for supply-chain strictness)

## "But where does my code go?"

Your application lives in **your own repository**. DRS is a dependency.
The typical shape:

```
your-app/
├── package.json            ← "@okeyamy/drs-sdk": "^0.1.0"
├── docker-compose.yml      ← services: your-app, drs-verify
└── src/
    ├── issue-receipt.ts    ← uses @okeyamy/drs-sdk
    └── verify-middleware.ts ← calls http://drs-verify:8080/verify
```

You never add `drs-core/`, `drs-verify/`, or `drs-sdk/` as subdirectories
of your repo.

## Verification: the five-minute test

Run this on a fresh machine with Docker and Node 20:

```bash
# No `git clone` of the DRS monorepo — this stays empty.
mkdir my-drs-app && cd my-drs-app

# 1. Pull the SDK from npm.
echo '{"type":"module","dependencies":{"@okeyamy/drs-sdk":"latest"}}' > package.json
npm install

# 2. Pull the verifier from GHCR and run it.
docker run --rm -d -p 8080:8080 --name drs-v ghcr.io/okeyamy/drs-verify:latest

# 3. Prove the SDK works against the running verifier.
node -e '
  import("@okeyamy/drs-sdk").then(async (s) => {
    console.log("SDK version loaded:", typeof s.issueRootDelegation === "function" ? "ok" : "missing");
    const res = await fetch("http://localhost:8080/healthz");
    console.log("verifier healthz:", res.status, await res.json());
  });
'

# 4. Stop the verifier.
docker stop drs-v
```

Expected output:

```
SDK version loaded: ok
verifier healthz: 200 { status: 'ok' }
```

No clone. No fork. Nothing about this machine knows about the DRS
source tree.

## When you should clone

Clone if:

1. **You're changing DRS itself.** Crypto bug, new feature, new test
   vector — clone, fix, PR. See
   [Contributing](../contributors/dev-setup.md).
2. **You need reproducible builds with a commit hash.** Pin to a commit,
   build the Docker image yourself in your CI, push to your own registry.
   Your base of trust moves from GHCR to your own build.
3. **You're running an air-gapped deployment.** Build `drs-verify` from
   source, vendor the SDK into your npm mirror, run the container from
   your private registry.

In every other case — using DRS in your product, wiring it into MCP or
A2A, issuing receipts from a React Native app — you install from the
registries. No fork.
