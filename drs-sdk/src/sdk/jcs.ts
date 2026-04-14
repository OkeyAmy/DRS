/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serialiser.
 *
 * This is the single canonical TypeScript implementation used by both
 * the issuance path and the conformance tests. Do not duplicate this
 * logic elsewhere — import from this module.
 *
 * Rules:
 * - Object keys are sorted lexicographically (UTF-16 code unit order).
 * - Numbers use JSON.stringify (V8 produces RFC 8785-compliant output).
 * - No whitespace between tokens.
 * - null/undefined serialize to "null".
 *
 * IMPORTANT: Do not use JSON.stringify for signed content — it does not
 * sort nested object keys.
 */
export function jcsSerialise(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value)) throw new Error("jcsSerialise: non-finite number is not valid JSON");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(jcsSerialise).join(",")}]`;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${jcsSerialise(obj[k])}`);
    return `{${entries.join(",")}}`;
  }
  return "null";
}
