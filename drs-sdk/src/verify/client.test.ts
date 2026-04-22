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
      bundle_version: "4.0",
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
      bundle_version: "4.0",
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
      client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
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
      client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
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
      client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" }),
    ).rejects.toMatchObject({ code: "VERIFY_RESPONSE_INVALID" });
    vi.unstubAllGlobals();
  });

  it("sends include_timestamps:true in the request body when the option is set", async () => {
    let capturedBody: Record<string, unknown> | null = null;
    const mockFetch = vi
      .fn()
      .mockImplementation(async (_url: unknown, init?: RequestInit) => {
        capturedBody = JSON.parse(init?.body as string) as Record<string, unknown>;
        return { ok: true, status: 200, json: async () => validResult };
      });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await client.verify(
      { bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" },
      { includeTimestamps: true },
    );

    expect(capturedBody).not.toBeNull();
    expect(capturedBody!["include_timestamps"]).toBe(true);
    vi.unstubAllGlobals();
  });

  it("does not include include_timestamps in the request body by default", async () => {
    let capturedBody: Record<string, unknown> | null = null;
    const mockFetch = vi
      .fn()
      .mockImplementation(async (_url: unknown, init?: RequestInit) => {
        capturedBody = JSON.parse(init?.body as string) as Record<string, unknown>;
        return { ok: true, status: 200, json: async () => validResult };
      });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" });

    expect(capturedBody).not.toBeNull();
    expect(capturedBody!["include_timestamps"]).toBeUndefined();
    vi.unstubAllGlobals();
  });

  it("sends body in the request when options.body is provided", async () => {
    let capturedBody: Record<string, unknown> | null = null;
    const mockFetch = vi
      .fn()
      .mockImplementation(async (_url: unknown, init?: RequestInit) => {
        capturedBody = JSON.parse(init?.body as string) as Record<string, unknown>;
        return { ok: true, status: 200, json: async () => ({ ...validResult, binding: "match" }) };
      });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    const requestBody = { tool: "approve_payment", transaction_id: "T1" };
    const result = await client.verify(
      { bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" },
      { body: requestBody },
    );

    expect(capturedBody).not.toBeNull();
    expect(capturedBody!["body"]).toEqual(requestBody);
    expect(result.binding).toBe("match");
    vi.unstubAllGlobals();
  });

  it("does not include body in the request when options.body is absent", async () => {
    let capturedBody: Record<string, unknown> | null = null;
    const mockFetch = vi
      .fn()
      .mockImplementation(async (_url: unknown, init?: RequestInit) => {
        capturedBody = JSON.parse(init?.body as string) as Record<string, unknown>;
        return { ok: true, status: 200, json: async () => validResult };
      });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await client.verify({ bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" });

    expect(capturedBody).not.toBeNull();
    expect("body" in capturedBody!).toBe(false);
    vi.unstubAllGlobals();
  });

  it("sends body even when the value is null (explicit opt-in)", async () => {
    // Distinguishes "I sent null on purpose" from "I didn't pass body."
    let capturedBody: Record<string, unknown> | null = null;
    const mockFetch = vi
      .fn()
      .mockImplementation(async (_url: unknown, init?: RequestInit) => {
        capturedBody = JSON.parse(init?.body as string) as Record<string, unknown>;
        return { ok: true, status: 200, json: async () => validResult };
      });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    await client.verify(
      { bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" },
      { body: null },
    );

    expect(capturedBody).not.toBeNull();
    expect("body" in capturedBody!).toBe(true);
    expect(capturedBody!["body"]).toBeNull();
    vi.unstubAllGlobals();
  });

  it("surfaces binding=mismatch from the server response", async () => {
    const mismatchResponse = { ...validResult, binding: "mismatch" as const };
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mismatchResponse,
    });
    vi.stubGlobal("fetch", mockFetch);

    const client = new VerifyClient({ baseUrl: "http://localhost:8080" });
    const result = await client.verify(
      { bundle_version: "4.0", receipts: ["r.p.s"], invocation: "i.p.s" },
      { body: { tool: "attacker-supplied" } },
    );

    expect(result.valid).toBe(true);
    expect(result.binding).toBe("mismatch");
    vi.unstubAllGlobals();
  });
});
