/**
 * Base64url encoding utilities (RFC 4648 §5, no padding).
 * Used for JWT header/payload/signature encoding.
 */

/** Encodes a string as base64url (UTF-8 bytes, no padding). */
export function base64url(input: string): string {
  return base64urlBytes(new TextEncoder().encode(input));
}

/** Encodes raw bytes as base64url (no padding). */
export function base64urlBytes(bytes: Uint8Array): string {
  // btoa is available in Node 16+ and all modern browsers
  const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/** Decodes a base64url string to bytes. */
export function decodeBase64url(input: string): Uint8Array {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = padded.length % 4;
  const withPad = remainder === 0 ? padded : padded + "=".repeat(4 - remainder);
  const binary = atob(withPad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
