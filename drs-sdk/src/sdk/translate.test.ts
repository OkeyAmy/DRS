import { describe, it, expect } from "vitest";
import { translatePolicy } from "./translate.js";
import type { Policy } from "./types.js";

describe("translatePolicy", () => {
  it("returns no-restriction message for empty policy", () => {
    const result = translatePolicy({});
    expect(result).toBe("No restrictions specified.");
  });

  it("includes max_cost_usd", () => {
    const p: Policy = { max_cost_usd: 5.5 };
    expect(translatePolicy(p)).toContain("$5.50");
  });

  it("includes max_calls", () => {
    const p: Policy = { max_calls: 10 };
    expect(translatePolicy(p)).toContain("10");
  });

  it("says PII not permitted when pii_access is false", () => {
    const p: Policy = { pii_access: false };
    expect(translatePolicy(p)).toContain("not permitted");
  });

  it("says write not permitted when write_access is false", () => {
    const p: Policy = { write_access: false };
    expect(translatePolicy(p)).toContain("not permitted");
  });

  it("lists allowed tools", () => {
    const p: Policy = { allowed_tools: ["web_search", "file_read"] };
    const result = translatePolicy(p);
    expect(result).toContain("web_search");
    expect(result).toContain("file_read");
  });

  it("shows 'all' for wildcard tools", () => {
    const p: Policy = { allowed_tools: ["*"] };
    expect(translatePolicy(p)).toContain("all");
  });

  it("produces one line per restriction", () => {
    const p: Policy = {
      max_cost_usd: 10.0,
      pii_access: false,
      write_access: false,
      allowed_tools: ["web_search"],
    };
    const result = translatePolicy(p);
    const lines = result.split("\n").filter(Boolean);
    expect(lines.length).toBe(4);
  });
});
