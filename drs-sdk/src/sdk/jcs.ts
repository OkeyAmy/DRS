/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serialiser.
 *
 * This is the single canonical TypeScript implementation used by both
 * the issuance path and the conformance tests. Do not duplicate this
 * logic elsewhere — import from this module.
 *
 * Rules:
 * - Object keys are sorted by Unicode code point order (RFC 8785 sec3.2.3-compliant).
 * - Numbers use JSON.stringify (V8 produces RFC 8785-compliant output).
 * - No whitespace between tokens.
 * - A top-level null/undefined serialises to "null". Object keys whose value is
 *   undefined are OMITTED (matching JSON.stringify and serde_json), so the
 *   canonical bytes agree with the Rust verifier which never emits `null` for
 *   an absent field.
 *
 * IMPORTANT: Do not use JSON.stringify for signed content — it does not
 * sort nested object keys.
 */

/**
 * Maximum nesting depth. Matches serde_json's default recursion limit (128) on
 * the Rust side so that any payload the Rust verifier would reject for depth is
 * also rejected here, and a deeply-nested input cannot exhaust the JS call stack.
 */
const MAX_JCS_DEPTH = 128;

/**
 * Compares two strings by Unicode code point order as required by RFC 8785
 * section 3.2.3. The default JS sort uses UTF-16 code unit values, which
 * diverges for supplementary-plane characters (U+10000+). This comparator
 * uses codePointAt() to obtain full code point values (0–0x10FFFF), then
 * advances the index by 2 for supplementary characters (which occupy two
 * UTF-16 code units) and 1 for BMP characters.
 */
function compareKeysByCodePoint(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const cpA = a.codePointAt(i)!;
    const cpB = b.codePointAt(j)!;
    if (cpA !== cpB) return cpA - cpB;
    i += cpA > 0xffff ? 2 : 1;
    j += cpB > 0xffff ? 2 : 1;
  }
  return a.length - b.length;
}

export function jcsSerialise(value: unknown, depth = 0): string {
  if (depth > MAX_JCS_DEPTH) {
    throw new Error(`jcsSerialise: nesting depth exceeds ${MAX_JCS_DEPTH}`);
  }
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("jcsSerialise: non-finite number is not valid JSON");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    // Array elements keep their position: an undefined element is `null` in JSON.
    return `[${value.map((v) => jcsSerialise(v, depth + 1)).join(",")}]`;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    // Omit keys whose value is undefined, matching JSON.stringify / serde_json.
    const sortedKeys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort(compareKeysByCodePoint);
    const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${jcsSerialise(obj[k], depth + 1)}`);
    return `{${entries.join(",")}}`;
  }
  return "null";
}
