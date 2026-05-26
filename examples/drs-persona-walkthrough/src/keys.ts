import { derivePublicKey } from "@okeyamy/drs-sdk";

export interface ExamplePrincipal {
  readonly name: string;
  readonly signingKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly did: string;
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function createExamplePrincipal(
  name: string,
  seedByte: number,
): ExamplePrincipal {
  const signingKey = new Uint8Array(32).fill(seedByte);
  const publicKey = derivePublicKey(signingKey);
  return {
    name,
    signingKey,
    publicKey,
    did: publicKeyToDidKey(publicKey),
  };
}

function publicKeyToDidKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

function base58btcEncode(bytes: Uint8Array): string {
  let n = BigInt(0);
  for (const byte of bytes) {
    n = n * BigInt(256) + BigInt(byte);
  }

  let result = "";
  while (n > BigInt(0)) {
    const remainder = Number(n % BigInt(58));
    n = n / BigInt(58);
    result = BASE58_ALPHABET[remainder] + result;
  }

  for (const byte of bytes) {
    if (byte !== 0) break;
    result = "1" + result;
  }

  return result;
}
