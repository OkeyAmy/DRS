import { derivePublicKey } from "../../sdk/issue.js";

export async function keygen(_args: string[]): Promise<void> {
  const privKey = new Uint8Array(32);
  globalThis.crypto.getRandomValues(privKey);
  const pubKey = derivePublicKey(privKey);

  // Encode as did:key
  const multicodec = new Uint8Array([0xed, 0x01, ...pubKey]);
  const did = `did:key:z${base58Encode(multicodec)}`;

  const privHex = Array.from(privKey)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const pubHex = Array.from(pubKey)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  console.log("Ed25519 keypair generated.");
  console.log("");
  console.log(`DID          : ${did}`);
  console.log(`Public key   : ${pubHex}`);
  console.log(`Private key  : ${privHex}`);
  console.log("");
  console.warn("WARNING: Store the private key securely. Never commit it to version control.");
}

function base58Encode(bytes: Uint8Array): string {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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
  let result = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    result += "1";
  }
  for (const d of digits) result += ALPHABET[d];
  return result;
}
