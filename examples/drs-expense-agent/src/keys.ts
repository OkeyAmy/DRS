/**
 * Ed25519 keypair generation and did:key derivation for DRS.
 *
 * The did:key format is:
 *   did:key:z<base58btc(multicodec_prefix || pubkey_bytes)>
 *
 * where multicodec_prefix = [0xed, 0x01] (Ed25519 public key).
 *
 * This matches exactly what drs-verify/pkg/resolver/did.go decodes.
 */

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

// @noble/ed25519 v2 requires SHA-512 to be set explicitly
ed.etc.sha512Sync = (...msgs) => sha512(ed.etc.concatBytes(...msgs));

export interface DrsKeypair {
  /** Raw 32-byte Ed25519 private key */
  privateKey: Uint8Array;
  /** Raw 32-byte Ed25519 public key */
  publicKey: Uint8Array;
  /** did:key identifier derived from the public key */
  did: string;
}

/**
 * Generates a fresh Ed25519 keypair and derives its did:key identifier.
 * Uses @noble/ed25519 cryptographically secure random key generation.
 */
export function generateKeypair(): DrsKeypair {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  const did = publicKeyToDidKey(publicKey);
  return { privateKey, publicKey, did };
}

/**
 * Derives a did:key string from a raw 32-byte Ed25519 public key.
 *
 * Steps:
 * 1. Prepend multicodec prefix [0xed, 0x01]
 * 2. Base58btc-encode the result
 * 3. Prepend 'z' (multibase identifier for base58btc)
 * 4. Prepend 'did:key:'
 */
export function publicKeyToDidKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);
  return `did:key:z${base58btcEncode(prefixed)}`;
}

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encodes a byte array to base58btc (without the multibase 'z' prefix).
 * Standard Bitcoin-style base58 encoding.
 */
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

  // Leading zero bytes encode as '1'
  for (const byte of bytes) {
    if (byte !== 0) break;
    result = "1" + result;
  }

  return result;
}
