import { describe, it, expect, vi } from "vitest";
import { createDrsHttpMiddleware } from "./http.js";
import type { VerificationResult } from "./middleware.js";

function bundleHeader(): string {
  return Buffer.from(
    JSON.stringify({
      bundle_version: "4.0",
      receipts: ["root.jwt"],
      invocation: "inv.jwt",
    }),
    "utf8",
  ).toString("base64url");
}

function jsonRequest(body: unknown, headers?: Record<string, string>) {
  return {
    headers: {
      "x-drs-bundle": bundleHeader(),
      ...headers,
    },
    body,
  };
}

function mockFetch(result: VerificationResult, status = 200): typeof fetch {
  return vi.fn(async () => ({
    json: async () => result,
    ok: status >= 200 && status < 300,
    status,
  })) as unknown as typeof fetch;
}

describe("createDrsHttpMiddleware", () => {
  it("passes a valid request to the app handler with verified context attached", async () => {
    const fetchFn = mockFetch({
      valid: true,
      binding: "match",
      context: {
        root_principal: "did:key:zHuman",
        leaf_policy: { allowed_tools: ["read_expenses"] },
        chain_depth: 1,
      },
    });
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn,
    });
    const next = vi.fn();

    const result = await middleware(
      jsonRequest({ tool: "read_expenses" }),
      next,
    );

    expect(result.ok).toBe(true);
    expect(next).toHaveBeenCalledOnce();
    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({
        drs: expect.objectContaining({ root_principal: "did:key:zHuman" }),
      }),
    );
  });

  it("reads DRS bundle headers case-insensitively", async () => {
    const fetchFn = mockFetch({ valid: true, binding: "match" });
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn,
    });

    const result = await middleware(
      {
        headers: { "X-DRS-BUNDLE": bundleHeader() },
        body: { tool: "read_expenses" },
      },
      vi.fn(),
    );

    expect(result.ok).toBe(true);
  });

  it("posts the decoded bundle plus the actual request body to drs-verify", async () => {
    const fetchFn = mockFetch({ valid: true, binding: "match" });
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn,
    });
    const requestBody = {
      tool: "categorize_transaction",
      transaction_id: "T1",
    };

    await middleware(jsonRequest(requestBody), vi.fn());

    const [, opts] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect(opts.method).toBe("POST");
    expect(opts.headers["Content-Type"]).toBe("application/json");
    expect(JSON.parse(opts.body as string)).toEqual({
      bundle_version: "4.0",
      receipts: ["root.jwt"],
      invocation: "inv.jwt",
      body: requestBody,
    });
  });

  it("rejects requests without a bundle before the app handler runs", async () => {
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn: mockFetch({ valid: true, binding: "match" }),
    });
    const next = vi.fn();

    const result = await middleware({ headers: {}, body: { tool: "x" } }, next);

    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
    expect(result.error.code).toBe("MISSING_BUNDLE");
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects a valid chain when body binding mismatches", async () => {
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn: mockFetch({ valid: true, binding: "mismatch" }),
    });
    const next = vi.fn();

    const result = await middleware(
      jsonRequest({ tool: "approve_payment" }),
      next,
    );

    expect(result.ok).toBe(false);
    expect(result.status).toBe(403);
    expect(result.error.code).toBe("BINDING_MISMATCH");
    expect(next).not.toHaveBeenCalled();
  });

  it("rejects when the verifier says the bundle is invalid", async () => {
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn: mockFetch({
        valid: false,
        error: {
          code: "POLICY_VIOLATION",
          message: "tool not permitted",
          suggestion: "Request a narrower tool call.",
        },
      }),
    });
    const next = vi.fn();

    const result = await middleware(
      jsonRequest({ tool: "approve_payment" }),
      next,
    );

    expect(result.ok).toBe(false);
    expect(result.status).toBe(403);
    expect(result.error.code).toBe("POLICY_VIOLATION");
    expect(next).not.toHaveBeenCalled();
  });

  it("fails closed when the verifier is unavailable", async () => {
    const middleware = createDrsHttpMiddleware({
      verifyUrl: "http://localhost:8080/verify",
      fetchFn: vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
    });
    const next = vi.fn();

    const result = await middleware(
      jsonRequest({ tool: "read_expenses" }),
      next,
    );

    expect(result.ok).toBe(false);
    expect(result.status).toBe(503);
    expect(result.error.code).toBe("VERIFICATION_UNAVAILABLE");
    expect(next).not.toHaveBeenCalled();
  });
});
