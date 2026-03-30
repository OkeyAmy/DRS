import { describe, it, expect, vi } from "vitest";
import { VerifyClient } from "./client.js";
import type { VerificationResult } from "../sdk/types.js";
import { DrsError } from "../sdk/types.js";

const validResult: VerificationResult = {
  valid: true,
  context: {
    root_principal: "did:key:zAlice",
    chain_depth: 1,
    leaf_policy: {},
  },
};

const invalidResult: VerificationResult = {
  valid: false,
  error: {
    code: "EXPIRED",
    message: "receipt[0] expired",
    suggestion: "Issue a new receipt.",
  },
};

describe("VerifyClient", () => {
  it("returns VerificationResult on success", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => validResult,
    });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    const result = await client.verify({
      bundle_version: "1.0",
      receipts: ["r.p.s"],
      invocation: "i.p.s",
    });

    expect(result.valid).toBe(true);
    vi.unstubAllGlobals();
  });

  it("returns invalid result on 403", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => invalidResult,
    });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    const result = await client.verify({
      bundle_version: "1.0",
      receipts: ["r.p.s"],
      invocation: "i.p.s",
    });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe("EXPIRED");
    vi.unstubAllGlobals();
  });

  it("throws DrsError on network failure", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new TypeError("fetch failed"));
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await expect(
      client.verify({ bundle_version: "1.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
    ).rejects.toMatchObject({ code: "NETWORK_ERROR" });
    vi.unstubAllGlobals();
  });

  it("throws DrsError on unexpected server status", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({}),
    });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await expect(
      client.verify({ bundle_version: "1.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
    ).rejects.toMatchObject({ code: "VERIFY_SERVICE_ERROR" });
    vi.unstubAllGlobals();
  });

  it("throws DrsError on malformed response", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ not_a_result: true }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await expect(
      client.verify({ bundle_version: "1.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
    ).rejects.toMatchObject({ code: "VERIFY_RESPONSE_INVALID" });
    vi.unstubAllGlobals();
  });
});
