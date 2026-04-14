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
Private key  : <hex>
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
  buildBundle,
  serialiseBundle,
  parseBundle,
  computeChainHash,
  checkPolicyAttenuation,
  translatePolicy,
  VerifyClient,
  initWasm,
  getWasmModule,
  isWasmReady,
} from "@okeyamy/drs-sdk";
```

## Browser / WASM notes

The SDK includes a WASM loader, but browser/WASM verification is still an
explicit integration path:

- `VerifyClient` talks to a running `drs-verify` HTTP service
- `initWasm()` / `getWasmModule()` are available if you wire in a WASM build
- there is no published standalone `@drs/wasm` package in this repo today

## Building the WASM package yourself

If you are developing locally and want to experiment with the WASM build:

```bash
cd drs-core
wasm-pack build --target web --features wasm
# Output: drs-core/pkg/
```
