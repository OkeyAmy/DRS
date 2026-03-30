# Install the SDK

## Requirements

- Node.js 20+
- pnpm (required — do not use npm or yarn)

## Install

```bash
pnpm add @drs/sdk
```

## Optional: browser-side verification

For client-side verification in browser environments, also install the WASM package:

```bash
pnpm add @drs/wasm
```

`@drs/sdk` detects `@drs/wasm` at runtime. If absent, the SDK's `VerifyClient` falls back to calling drs-verify over HTTP. If present, `initWasm()` loads the WASM module for local verification.

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

Expected:
```
Private key (keep secret): <base64url 32 bytes>
DID:                        did:key:z6Mk...
```

## What's in the package

| Export path | Contents |
|---|---|
| `@drs/sdk` (main) | `issueRootDelegation`, `issueSubDelegation`, `issueInvocation`, `buildBundle`, `serialiseBundle`, `parseBundle`, `computeChainHash`, `checkPolicyAttenuation`, `translatePolicy` |
| `@drs/sdk/verify` | `VerifyClient` — HTTP client for drs-verify |
| `@drs/sdk/wasm` | `initWasm`, `getWasmModule`, `isWasmReady` |
| `@drs/sdk/types` | All TypeScript interfaces |

## Building the WASM package yourself

If you are developing locally or want to use unreleased drs-core changes:

```bash
cd drs-core
wasm-pack build --target web --features wasm
# Output: drs-core/pkg/

# Link it locally
cd drs-core/pkg && pnpm link --global
cd drs-sdk && pnpm link --global @drs/wasm
```
