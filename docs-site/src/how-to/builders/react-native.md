# Integrate DRS in a React Native app

This guide covers installing and using `@okeyamy/drs-sdk` inside an Expo
or bare React Native app. The SDK is pure TypeScript plus pure-JS
cryptography (`@noble/ed25519`) — no native modules, no WASM glue code
required on the mobile side.

## Compatibility matrix

| Runtime | Status |
|---|---|
| Expo SDK 50+ (managed) | Supported |
| Expo SDK 50+ (bare) | Supported |
| React Native 0.73+ (community CLI) | Supported |
| Hermes (default on RN 0.70+) | Supported |
| JavaScriptCore | Supported |

The SDK relies on:

- `crypto.getRandomValues` — provided by React Native's `expo-crypto` or
  by modern RN directly. Polyfill on older targets.
- `TextEncoder` / `TextDecoder` — provided by Hermes. On JSC, polyfill
  with `text-encoding`.
- `atob` / `btoa` — provided by both engines.

## Install

```bash
# Expo
npx expo install @okeyamy/drs-sdk

# RN community CLI
pnpm add @okeyamy/drs-sdk
```

If your project runs on an older RN (<0.74) or bare JSC:

```bash
pnpm add react-native-get-random-values text-encoding
```

Then import the polyfills once, at the top of your entry file
(`index.js` or `App.tsx`):

```ts
import "react-native-get-random-values";
import "text-encoding/encoding-indexes";
```

## Generate and persist a key

Mobile apps typically generate a per-device key on first launch and
store it in the OS secure enclave / Keychain. Use
`expo-secure-store` (Expo) or `react-native-keychain` (bare).

```ts
import * as SecureStore from "expo-secure-store";
import { derivePublicKey } from "@okeyamy/drs-sdk";

export async function getOrCreateAgentKey(): Promise<Uint8Array> {
  const existing = await SecureStore.getItemAsync("drs.agent_sk");
  if (existing) {
    return Uint8Array.from(Buffer.from(existing, "hex"));
  }
  // Fresh key: 32 bytes from a CSPRNG.
  const sk = new Uint8Array(32);
  globalThis.crypto.getRandomValues(sk);
  await SecureStore.setItemAsync(
    "drs.agent_sk",
    Buffer.from(sk).toString("hex"),
    { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY },
  );
  return sk;
}

export function didFromKey(sk: Uint8Array): string {
  const pub = derivePublicKey(sk);
  const multicodec = new Uint8Array([0xed, 0x01, ...pub]);
  return `did:key:z${base58btc(multicodec)}`;
}
```

`base58btc` is a small pure-JS helper; see the
[SDK tests](https://github.com/OkeyAmy/DRS/blob/main/drs-sdk/src/sdk/issue.test.ts)
for an inlineable implementation.

## Issue an invocation when the user taps a button

```tsx
import { useState } from "react";
import { Button, Text } from "react-native";
import {
  buildBundle,
  issueInvocation,
  computeChainHash,
  serialiseBundle,
} from "@okeyamy/drs-sdk";

export function CallToolButton({
  agentKey,
  agentDid,
  rootDR,
  toolServerDid,
}: Props) {
  const [result, setResult] = useState<string>("");

  async function onCall() {
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: agentDid,
      cmd: "/mcp/tools/call",
      args: { tool: "web_search", query: "react native drs integration" },
      drChain: [computeChainHash(rootDR)],
      toolServer: toolServerDid,
    });

    const bundle = buildBundle([rootDR], invocation);
    const bundleHeader = serialiseBundle(bundle);

    const res = await fetch("https://your-tool-server.example.com/mcp/tools/call", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-DRS-Bundle": bundleHeader,
      },
      body: JSON.stringify({ tool: "web_search", query: "..." }),
    });
    setResult(await res.text());
  }

  return (
    <>
      <Button onPress={onCall} title="Run tool with DRS receipt" />
      <Text>{result}</Text>
    </>
  );
}
```

The root delegation (`rootDR`) was issued when the user approved the
agent — see [Human Consent Records](../developers/human-consent.md).
Persist it alongside the agent key, or fetch it from your backend on app
launch.

## Where `drs-verify` runs

The verifier **does not run on the phone.** It is a backend service
that your tool server calls (or that your tool server is wrapped by).
From the React Native app's perspective, DRS is issuance-only: you sign
receipts, you send them over HTTPS in the `X-DRS-Bundle` header, the
server verifies.

A typical deployment:

```
┌───────────────────────┐
│ React Native app      │  @okeyamy/drs-sdk (npm)
└─────────┬─────────────┘
          │ HTTPS + X-DRS-Bundle header
          ▼
┌───────────────────────┐
│ Your tool server API  │  validates bundle (sidecar or Go middleware)
└─────────┬─────────────┘
          │ POST /verify (optional sidecar mode)
          ▼
┌───────────────────────┐
│ drs-verify (Docker)   │  ghcr.io/okeyamy/drs-verify
└───────────────────────┘
```

See [Integrate DRS with an MCP Node server](./mcp-node.md) for the
server side.

## Troubleshooting

### "crypto.getRandomValues is not a function"

You're on an older RN without a secure random source. Install and import
`react-native-get-random-values` as shown above.

### "Cannot find module '@noble/ed25519'"

This is a transitive dependency of the SDK. It should resolve
automatically. If it doesn't, clear the Metro cache:

```bash
npx expo start --clear
# or for bare:
pnpm start -- --reset-cache
```

### Signatures don't verify on the server

Double-check that `drChain` entries are **chain hashes**
(`sha256:...`), not raw JWTs. The SDK exposes `computeChainHash(jwt)`
for this — forgetting it is the most common mistake.

### Bundle is too large for HTTP headers

Some gateways cap header size at 8 KB. If your delegation chain has many
sub-delegations, consider sending the bundle as a request body field
using the JSON-RPC `_meta` pattern instead of the `X-DRS-Bundle`
header. Both shapes are defined in
[`drs-source-of-truth.md`](https://github.com/OkeyAmy/DRS/blob/main/docs/drs-source-of-truth.md).
