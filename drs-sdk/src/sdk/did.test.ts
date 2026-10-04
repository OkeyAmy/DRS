import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { base58Encode, didKeyFromPublicKey, didKeyFromSigningKey } from "./did.js";

// The conformance keys are the RFC 8032 §7.1 Ed25519 test vectors, and the Go
// resolver independently decodes these exact DIDs in its conformance suite.
const fixture = JSON.parse(
  readFileSync(
    join(__dirname, "../../../fixtures/conformance/receipts/root-delegation.json"),
    "utf8",
  ),
) as { keys: Record<string, { seed_hex: string; pub_hex: string; did: string }> };

const hex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));

describe("did:key encoding", () => {
  for (const [name, k] of Object.entries(fixture.keys)) {
    it(`derives the conformance did:key for ${name} from its public key and its seed`, () => {
      // blindfold: golden — fixtures/conformance/receipts/root-delegation.json keys.*.did (cross-checked by the Go resolver)
      expect(didKeyFromPublicKey(hex(k.pub_hex))).toBe(k.did);
      expect(didKeyFromSigningKey(hex(k.seed_hex))).toBe(k.did);
    });
  }

  it("rejects keys that are not 32 bytes", () => {
    expect(() => didKeyFromPublicKey(new Uint8Array(31))).toThrow(/32 bytes/);
    expect(() => didKeyFromSigningKey(new Uint8Array(33))).toThrow(/32 bytes/);
  });

  it("encodes leading zero bytes as '1' per the base58 convention", () => {
    // blindfold: standard — base58 (Bitcoin): each leading 0x00 byte becomes '1'; 0x00 0x01 -> "12"
    expect(base58Encode(Uint8Array.from([0, 1]))).toBe("12");
    expect(base58Encode(new Uint8Array(0))).toBe("");
  });
});
