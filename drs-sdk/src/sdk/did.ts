import { DrsError } from "./types.js";
import { derivePublicKey } from "./issue.js";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_MULTICODEC = [0xed, 0x01] as const;

/** Encodes bytes with the Bitcoin base58 alphabet (as used by did:key). */
export function base58Encode(bytes: Uint8Array): string {
  const digits: number[] = [0];
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
  let out = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += "1";
  }
  if (bytes.length === 0) return out;
  for (const d of digits) out += BASE58_ALPHABET[d];
  return out;
}

/** Returns the did:key (multicodec 0xed01, base58btc) for an Ed25519 public key. */
export function didKeyFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new DrsError(
      "INVALID_KEY",
      `Ed25519 public key must be 32 bytes, got ${publicKey.length}.`,
    );
  }
  return `did:key:z${base58Encode(Uint8Array.from([...ED25519_MULTICODEC, ...publicKey]))}`;
}

/** Returns the did:key for the Ed25519 key pair whose private key (32-byte seed) is given. */
export function didKeyFromSigningKey(signingKey: Uint8Array): string {
  if (signingKey.length !== 32) {
    throw new DrsError(
      "INVALID_KEY",
      `Ed25519 signing key must be 32 bytes, got ${signingKey.length}.`,
    );
  }
  return didKeyFromPublicKey(derivePublicKey(signingKey));
}
