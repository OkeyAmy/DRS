import { describe, it, expect } from "vitest";
import {
  buildBundle,
  parseBundle,
  parseBundleJSON,
  parseBundleAuto,
  serialiseBundle,
} from "./bundle.js";
import { base64url } from "./base64url.js";
import { DrsError } from "./types.js";

function catchDrsError(fn: () => unknown): DrsError {
  try {
    fn();
  } catch (e) {
    if (e instanceof DrsError) return e;
    throw e;
  }
  throw new Error("Expected DrsError to be thrown but nothing was thrown");
}

describe("buildBundle", () => {
  it("assembles a bundle from receipts and invocation", () => {
    const bundle = buildBundle(["receipt.a.1"], "inv.b.2");
    expect(bundle.bundle_version).toBe("4.0");
    expect(bundle.receipts).toEqual(["receipt.a.1"]);
    expect(bundle.invocation).toBe("inv.b.2");
  });

  it("throws EMPTY_CHAIN for empty receipts", () => {
    const err = catchDrsError(() => buildBundle([], "inv.b.2"));
    expect(err.code).toBe("EMPTY_CHAIN");
  });

  it("throws MISSING_INVOCATION for empty invocation", () => {
    const err = catchDrsError(() => buildBundle(["receipt.a.1"], ""));
    expect(err.code).toBe("MISSING_INVOCATION");
  });
});

describe("serialiseBundle / parseBundle", () => {
  it("round-trips through base64url encoding", () => {
    const bundle = buildBundle(["r1.p.s", "r2.p.s"], "inv.p.s");
    const encoded = serialiseBundle(bundle);
    const parsed = parseBundle(encoded);
    expect(parsed).toEqual(bundle);
  });

  it("parseBundle throws MALFORMED_BUNDLE for invalid base64url JSON", () => {
    const err = catchDrsError(() => parseBundle("not-json"));
    expect(err.code).toBe("MALFORMED_BUNDLE");
  });

  it("parseBundle throws MALFORMED_BUNDLE for missing required fields", () => {
    const encoded = base64url(JSON.stringify({ receipts: [] }));
    const err = catchDrsError(() => parseBundle(encoded));
    expect(err.code).toBe("MALFORMED_BUNDLE");
  });
});

describe("parseBundleJSON", () => {
  it("parses raw JSON bundle string", () => {
    const original = buildBundle(["r1.p.s"], "inv.p.s");
    const json = JSON.stringify(original);
    const parsed = parseBundleJSON(json);
    expect(parsed).toEqual(original);
  });

  it("throws MALFORMED_BUNDLE for invalid JSON", () => {
    const err = catchDrsError(() => parseBundleJSON("{bad json"));
    expect(err.code).toBe("MALFORMED_BUNDLE");
  });

  it("throws MALFORMED_BUNDLE for missing required fields", () => {
    const err = catchDrsError(() => parseBundleJSON(JSON.stringify({ receipts: [] })));
    expect(err.code).toBe("MALFORMED_BUNDLE");
  });
});

describe("parseBundleAuto", () => {
  it("auto-detects raw JSON (starts with '{')", () => {
    const original = buildBundle(["r1.p.s"], "inv.p.s");
    const json = JSON.stringify(original);
    const parsed = parseBundleAuto(json);
    expect(parsed).toEqual(original);
  });

  it("auto-detects raw JSON with leading whitespace", () => {
    const original = buildBundle(["r1.p.s"], "inv.p.s");
    const json = "  \n" + JSON.stringify(original);
    const parsed = parseBundleAuto(json);
    expect(parsed).toEqual(original);
  });

  it("auto-detects base64url-encoded bundle", () => {
    const original = buildBundle(["r1.p.s"], "inv.p.s");
    const encoded = serialiseBundle(original);
    const parsed = parseBundleAuto(encoded);
    expect(parsed).toEqual(original);
  });

  it("throws MALFORMED_BUNDLE for garbage input", () => {
    const err = catchDrsError(() => parseBundleAuto("!!!not-valid!!!"));
    expect(err.code).toBe("MALFORMED_BUNDLE");
  });
});
