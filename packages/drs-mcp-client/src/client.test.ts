import { describe, it, expect, vi } from "vitest";
import { DrsTransportWrapper, stringToBase64Url, base64UrlToString } from "./client.js";
import type { McpTransport, McpMessage, BundleProvider, DrsClientConfig } from "./client.js";

function createMockTransport(): McpTransport & { sent: McpMessage[] } {
  const sent: McpMessage[] = [];
  return {
    sent,
    send: vi.fn(async (msg: McpMessage) => {
      sent.push(msg);
    }),
  };
}

function createBundleProvider(bundle: string | null): BundleProvider {
  return {
    getBundle: vi.fn(async () => bundle),
  };
}

const SAMPLE_BUNDLE_JSON = '{"bundle_version":"4.0","invocation":"inv.jwt","receipts":["dr.jwt"]}';

function makeConfig(overrides?: Partial<DrsClientConfig>): DrsClientConfig & {
  transport: ReturnType<typeof createMockTransport>;
  bundleProvider: ReturnType<typeof createBundleProvider>;
} {
  const transport = createMockTransport();
  const bundleProvider = createBundleProvider(SAMPLE_BUNDLE_JSON);
  return { transport, bundleProvider, ...overrides } as ReturnType<typeof makeConfig>;
}

describe("base64url encoding roundtrip", () => {
  it("encodes and decodes back to the original string", () => {
    const input = '{"hello":"world","num":42}';
    const encoded = stringToBase64Url(input);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    const decoded = base64UrlToString(encoded);
    expect(decoded).toBe(input);
  });

  it("produces the same encoding as Go base64.RawURLEncoding", () => {
    const input = "test-string";
    const encoded = stringToBase64Url(input);
    expect(encoded).toBe("dGVzdC1zdHJpbmc");
  });
});

describe("DrsTransportWrapper", () => {
  it("injects base64url-encoded bundle for tools/call", async () => {
    const config = makeConfig();
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "tools/call",
      id: 1,
      params: { name: "web_search", arguments: { query: "test" } },
    };

    await wrapper.send(msg);

    expect(config.transport.send).toHaveBeenCalledOnce();
    const sent = config.transport.sent[0]!;
    const meta = sent.params?._meta as Record<string, unknown>;
    expect(meta).toBeDefined();

    const encoded = meta["X-DRS-Bundle"] as string;
    expect(typeof encoded).toBe("string");

    const decoded = base64UrlToString(encoded);
    expect(decoded).toBe(SAMPLE_BUNDLE_JSON);
    expect(JSON.parse(decoded)).toEqual(JSON.parse(SAMPLE_BUNDLE_JSON));
  });

  it("does not inject bundle for non-tool-call methods", async () => {
    const config = makeConfig();
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "resources/list",
      id: 2,
    };

    await wrapper.send(msg);

    expect(config.bundleProvider.getBundle).not.toHaveBeenCalled();
    const sent = config.transport.sent[0]!;
    expect(sent.params?._meta).toBeUndefined();
  });

  it("does not inject bundle for tools/execute (non-standard method)", async () => {
    const config = makeConfig();
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "tools/execute",
      id: 3,
      params: { name: "web_search" },
    };

    await wrapper.send(msg);

    expect(config.bundleProvider.getBundle).not.toHaveBeenCalled();
    const sent = config.transport.sent[0]!;
    expect(sent.params?._meta).toBeUndefined();
  });

  it("does not inject bundle for messages without a method", async () => {
    const config = makeConfig();
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      id: 4,
      result: { ok: true },
    };

    await wrapper.send(msg);

    expect(config.bundleProvider.getBundle).not.toHaveBeenCalled();
    expect(config.transport.sent[0]).toEqual(msg);
  });

  it("passes message through when bundle provider returns null", async () => {
    const config = makeConfig({ bundleProvider: createBundleProvider(null) });
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "tools/call",
      id: 5,
      params: { name: "file_read" },
    };

    await wrapper.send(msg);

    const sent = config.transport.sent[0]!;
    expect(sent.params?._meta).toBeUndefined();
  });

  it("uses custom header name when configured", async () => {
    const customHeader = "X-Custom-DRS";
    const config = makeConfig({ headerName: customHeader });
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "tools/call",
      id: 6,
      params: { name: "web_search" },
    };

    await wrapper.send(msg);

    const sent = config.transport.sent[0]!;
    const meta = sent.params?._meta as Record<string, unknown>;
    expect(meta[customHeader]).toBeDefined();
    expect(meta["X-DRS-Bundle"]).toBeUndefined();

    const decoded = base64UrlToString(meta[customHeader] as string);
    expect(decoded).toBe(SAMPLE_BUNDLE_JSON);
  });

  it("preserves existing _meta fields", async () => {
    const config = makeConfig();
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "tools/call",
      id: 7,
      params: {
        name: "web_search",
        _meta: { traceId: "abc-123" },
      },
    };

    await wrapper.send(msg);

    const sent = config.transport.sent[0]!;
    const meta = sent.params?._meta as Record<string, unknown>;
    expect(meta["traceId"]).toBe("abc-123");
    expect(meta["X-DRS-Bundle"]).toBeDefined();
  });

  it("preserves existing params fields", async () => {
    const config = makeConfig();
    const wrapper = new DrsTransportWrapper(config);

    const msg: McpMessage = {
      jsonrpc: "2.0",
      method: "tools/call",
      id: 8,
      params: { name: "web_search", arguments: { q: "hello" } },
    };

    await wrapper.send(msg);

    const sent = config.transport.sent[0]!;
    expect(sent.params?.name).toBe("web_search");
    expect((sent.params?.arguments as Record<string, string>)?.q).toBe("hello");
  });

  it("exposes onMessage from the inner transport", () => {
    const config = makeConfig();
    const handler = vi.fn();
    config.transport.onMessage = vi.fn((h) => h);

    const wrapper = new DrsTransportWrapper(config);
    wrapper.onMessage?.(handler);

    expect(config.transport.onMessage).toHaveBeenCalled();
  });
});
