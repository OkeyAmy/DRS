import { describe, test, expect } from "vitest";
import { jcsSerialise } from "./jcs.js";

// Locks in the JCS hardening from the VULN-FINDINGS pass:
// F-033 (omit undefined object keys to match serde_json / JSON.stringify) and
// F-040 (bounded recursion depth).

describe("jcsSerialise: undefined object keys (F-033)", () => {
  test("omits keys whose value is undefined", () => {
    // exp is undefined — it must be absent from the canonical form, matching
    // JSON.stringify and the Rust serde_json verifier (which never emits null
    // for an absent field). Otherwise the chain hash diverges across layers.
    expect(jcsSerialise({ a: 1, exp: undefined })).toBe('{"a":1}');
  });

  test("a present null value is preserved", () => {
    expect(jcsSerialise({ a: null })).toBe('{"a":null}');
  });

  test("undefined array elements remain positional null", () => {
    expect(jcsSerialise([1, undefined, 3])).toBe("[1,null,3]");
  });

  test("matches JSON.stringify key-presence for mixed object", () => {
    const obj = { b: undefined, a: 2, c: undefined };
    // JSON.stringify drops b and c; jcsSerialise must agree on which keys exist.
    expect(jcsSerialise(obj)).toBe('{"a":2}');
  });
});

describe("jcsSerialise: recursion depth limit (F-040)", () => {
  test("throws on deeply nested input instead of overflowing the stack", () => {
    let nested: unknown = 0;
    for (let i = 0; i < 200; i++) nested = { n: nested };
    expect(() => jcsSerialise(nested)).toThrow(/depth/);
  });

  test("accepts input within the depth limit", () => {
    let nested: unknown = 0;
    for (let i = 0; i < 50; i++) nested = { n: nested };
    expect(() => jcsSerialise(nested)).not.toThrow();
  });
});
