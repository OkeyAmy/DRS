# Install the SDK

## Requirements

- Node.js 20+
- pnpm

## Install

```bash
pnpm add @okeyamy/drs-sdk
```

Repository: `https://github.com/OkeyAmy/DRS`

## TypeScript configuration

```json
{
  "compilerOptions": {
    "moduleResolution": "bundler",
    "target": "ES2022",
    "lib": ["ES2022", "DOM"]
  }
}
```

## Verify the install

```bash
pnpm exec drs keygen
```

Expected output includes:

```text
Ed25519 keypair generated.

DID          : did:key:z6Mk...
Public key   : <hex>
Private key  : written to /home/you/.drs/signing.key
```

## What's in the package

The published package exports from the root entry only. Import from
`@okeyamy/drs-sdk`, not subpaths.

If you are wiring middleware guides from this docs site, use package names and
paths exactly as shown in each page. Do not switch to legacy aliases.

```ts
import {
  issueRootDelegation,
  issueSubDelegation,
  issueInvocation,
  createInvocationBundle,
  buildBundle,
  serialiseBundle,
  parseBundle,
  computeChainHash,
  checkPolicyAttenuation,
  translatePolicy,
  VerifyClient,
} from "@okeyamy/drs-sdk";
```

## Browser / WASM notes

As of SDK 0.2.0 the package no longer exports a WASM loader
(`initWasm` / `getWasmModule` / `isWasmReady` were removed from the entry
point — no standalone WASM artifact was ever published, so the loader could
never succeed). All verification goes through `VerifyClient` against a
running `drs-verify` HTTP service. The deprecated loader module remains in
the source tree as an integration path if a WASM artifact is released in
the future.
