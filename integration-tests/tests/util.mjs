// Small helpers shared by E2E tests.
// Kept free of test framework imports so they can run under any runner.

import { derivePublicKey } from "@okeyamy/drs-sdk";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Base58btc-encode bytes (Bitcoin alphabet). */
export function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = digits.length - 1; j >= 0; j--) {
      carry += 256 * (digits[j] ?? 0);
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.unshift(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    result += "1";
  }
  for (const d of digits) result += ALPHABET[d];
  return result;
}

/** Generates a fresh Ed25519 signing key (raw 32 bytes). */
export function generateKey() {
  const key = new Uint8Array(32);
  globalThis.crypto.getRandomValues(key);
  return key;
}

/** Returns the did:key string for the given private key. */
export function didFromKey(privKey) {
  const pub = derivePublicKey(privKey);
  const multicodec = new Uint8Array([0xed, 0x01, ...pub]);
  return `did:key:z${base58Encode(multicodec)}`;
}

/** Unix timestamp, seconds. */
export function now() {
  return Math.floor(Date.now() / 1000);
}

/** POST /verify and return the parsed JSON body (+ status). */
export async function postVerify(url, bundle) {
  const res = await fetch(`${url}/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(bundle),
  });
  return { status: res.status, body: await res.json() };
}
