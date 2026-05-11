import { describe, it, expect, vi } from "vitest";
import { drsMcpMiddleware } from "./middleware.js";
import type { DrsServerConfig, VerificationResult } from "./middleware.js";

function toBase64Url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function mockFetch(result: VerificationResult, status = 200): typeof fetch {
  return vi.fn(async () => ({
    json: async () => result,
    ok: status >= 200 && status < 300,
    status,
  })) as unknown as typeof fetch;
}

function mockFetchError(error: Error): typeof fetch {
  return vi.fn(async () => {
    throw error;
  }) as unknown as typeof fetch;
}

function mockFetchNonJson(status = 200): typeof fetch {
  return vi.fn(async () => ({
    json: async () => {
      throw new SyntaxError("Unexpected token");
    },
    ok: status >= 200 && status < 300,
    status,
  })) as unknown as typeof fetch;
}

function mockFetchBadShape(status = 200): typeof fetch {
  return vi.fn(async () => ({
    json: async () => ({ not_valid: "missing valid field" }),
    ok: status >= 200 && status < 300,
    status,
  })) as unknown as typeof fetch;
}

function makeConfig(overrides?: Partial<DrsServerConfig>): DrsServerConfig {
  return {
    verifyUrl: "http://localhost:8080/verify",
    fetchFn: mockFetch({ valid: true, context: validContext() }),
    ...overrides,
  };
}

function validContext() {
  return {
    root_principal: "did:key:zAlice",
    root_type: "human",
    leaf_policy: { max_cost_usd: 5.0 },
    chain_depth: 2,
  };
}

function validBundleObject() {
  return {
    bundle_version: "4.0",
    invocation: "inv.jwt",
    receipts: ["root.jwt", "sub.jwt"],
  };
}

function validBundleEncoded() {
  return toBase64Url(JSON.stringify(validBundleObject()));
}

describe("drsMcpMiddleware", () => {
  it("returns verified=true for a valid base64url-encoded bundle", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 1,
      params: {
        name: "web_search",
        _meta: { "X-DRS-Bundle": validBundleEncoded() },
      },
    });

    expect(result.verified).toBe(true);
    expect(result.result.valid).toBe(true);
    expect(result.result.context?.root_principal).toBe("did:key:zAlice");
  });

  it("passes through non-tool-call methods without verification", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "resources/list",
      id: 2,
    });

    expect(result.verified).toBe(true);
    expect(config.fetchFn).not.toHaveBeenCalled();
  });

  it("passes through messages without method (responses)", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      id: 3,
      result: { tools: [] },
    });

    expect(result.verified).toBe(true);
  });

  it("returns MISSING_BUNDLE when no bundle is present on tools/call", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 4,
      params: { name: "web_search" },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("MISSING_BUNDLE");
  });

  it("returns MISSING_BUNDLE when _meta is missing", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 5,
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("MISSING_BUNDLE");
  });

  it("returns MALFORMED_BUNDLE when bundle is not valid base64url", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 6,
      params: { _meta: { "X-DRS-Bundle": "!!!not-base64!!!" } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("MALFORMED_BUNDLE");
  });

  it("returns MALFORMED_BUNDLE when decoded base64url is not valid JSON", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const notJson = toBase64Url("not-json{{{");
    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 7,
      params: { _meta: { "X-DRS-Bundle": notJson } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("MALFORMED_BUNDLE");
  });

  it("forwards decoded bundle to verify URL as JSON POST", async () => {
    const fetchFn = mockFetch({ valid: true, context: validContext() });
    const config = makeConfig({ fetchFn });
    const verify = drsMcpMiddleware(config);

    await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 8,
      params: { _meta: { "X-DRS-Bundle": validBundleEncoded() } },
    });

    expect(fetchFn).toHaveBeenCalledOnce();
    const [url, opts] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(url).toBe("http://localhost:8080/verify");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");

    const postedBody = JSON.parse(opts.body as string);
    expect(postedBody).toEqual(validBundleObject());
  });

  it("returns verified=false when verifier says invalid", async () => {
    const failResult: VerificationResult = {
      valid: false,
      error: {
        code: "EXPIRED",
        message: "receipt[0] expired",
        suggestion: "Reissue.",
      },
    };
    const config = makeConfig({ fetchFn: mockFetch(failResult) });
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 9,
      params: { _meta: { "X-DRS-Bundle": validBundleEncoded() } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("EXPIRED");
  });

  it("returns VERIFICATION_FAILED on non-2xx response from verifier", async () => {
    const config = makeConfig({
      fetchFn: mockFetch({ valid: false }, 500),
    });
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 10,
      params: { _meta: { "X-DRS-Bundle": validBundleEncoded() } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("VERIFICATION_FAILED");
    expect(result.result.error?.message).toContain("500");
  });

  it("returns VERIFICATION_FAILED when verifier returns non-JSON", async () => {
    const config = makeConfig({ fetchFn: mockFetchNonJson() });
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 11,
      params: { _meta: { "X-DRS-Bundle": validBundleEncoded() } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("VERIFICATION_FAILED");
    expect(result.result.error?.message).toContain("non-JSON");
  });

  it("returns VERIFICATION_FAILED when response shape is wrong", async () => {
    const config = makeConfig({ fetchFn: mockFetchBadShape() });
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 12,
      params: { _meta: { "X-DRS-Bundle": validBundleEncoded() } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("VERIFICATION_FAILED");
  });

  it("returns VERIFICATION_UNAVAILABLE on fetch error", async () => {
    const config = makeConfig({
      fetchFn: mockFetchError(new Error("ECONNREFUSED")),
    });
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 13,
      params: { _meta: { "X-DRS-Bundle": validBundleEncoded() } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("VERIFICATION_UNAVAILABLE");
    expect(result.result.error?.message).toContain("ECONNREFUSED");
  });

  it("uses custom header name when configured", async () => {
    const config = makeConfig({ headerName: "X-Custom-Header" });
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 14,
      params: { _meta: { "X-Custom-Header": validBundleEncoded() } },
    });

    expect(result.verified).toBe(true);
  });

  it("returns MISSING_BUNDLE when bundle value is non-string", async () => {
    const config = makeConfig();
    const verify = drsMcpMiddleware(config);

    const result = await verify({
      jsonrpc: "2.0",
      method: "tools/call",
      id: 15,
      params: { _meta: { "X-DRS-Bundle": 42 } },
    });

    expect(result.verified).toBe(false);
    expect(result.result.error?.code).toBe("MISSING_BUNDLE");
  });
});
