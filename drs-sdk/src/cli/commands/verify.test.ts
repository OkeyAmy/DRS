import { describe, expect, it } from "vitest";
import { parseVerifyArgs } from "./verify.js";

describe("parseVerifyArgs", () => {
  it("takes the value after --body as the body path, not as the bundle", () => {
    // blindfold: contract — USAGE in verify.ts: --body <request.json> <bundle.json>
    expect(parseVerifyArgs(["--body", "req.json", "bundle.json"])).toEqual({
      bundlePath: "bundle.json",
      bodyPath: "req.json",
      includeTimestamps: false,
    });
  });

  it("keeps the first positional as the bundle when --body is absent", () => {
    expect(parseVerifyArgs(["bundle.json", "--include-timestamps"])).toEqual({
      bundlePath: "bundle.json",
      bodyPath: undefined,
      includeTimestamps: true,
    });
  });

  it("reports a missing bundle path", () => {
    expect(parseVerifyArgs(["--body", "req.json"]).bundlePath).toBe(undefined);
  });
});
