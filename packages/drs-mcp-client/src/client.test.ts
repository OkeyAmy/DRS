import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  issueRootDelegation,
  derivePublicKey,
  parseBundle,
} from "@okeyamy/drs-sdk";
import {
  BUNDLE_HEADER,
  BUNDLE_META_KEY,
  callFor,
  createChainSigner,
} from "./signer.js";
import { createDrsFetch, embed } from "./fetch.js";
import { DrsClientTransport, type McpTransport } from "./transport.js";

// Wire envelopes recorded from the official SDKs (see drs-verify/pkg/gate/testdata/wire).
const WIRE = join(__dirname, "../../../drs-verify/pkg/gate/testdata/wire");
const wire = (name: string) =>
  JSON.parse(readFileSync(join(WIRE, `${name}.json`), "utf8"));

function payloadOf(jwt: string): Record<string, unknown> {
  return JSON.parse(
    Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf8"),
  );
}

async function realSigner() {
  const key = () => crypto.getRandomValues(new Uint8Array(32));
  const did = (k: Uint8Array) =>
    `did:key:z${Buffer.from(derivePublicKey(k)).toString("hex")}`;
  const human = key();
  const agent = key();
  const now = Math.floor(Date.now() / 1000);
  const root = await issueRootDelegation({
    signingKey: human,
    issuerDid: did(human),
    subjectDid: did(human),
    audienceDid: did(agent),
    cmd: "/mcp",
    policy: {},
    nbf: now - 60,
    exp: now + 600,
  });
  return createChainSigner({
    receipts: [root],
    signingKey: agent,
    issuerDid: did(agent),
    subjectDid: did(human),
    toolServer: "did:web:tools.example",
  });
}

describe("callFor — the args a gate will bind against", () => {
  it("maps a recorded MCP 2026-07-28 tools/call to arguments + tool", () => {
    const body = wire("mcp_2026-07-28_tools-call_post_header").body;
    // blindfold: contract — docs-site/src/reference/protocol-gate.md adapter table (mcp row); values from the recorded fixture
    expect(callFor("mcp", body)).toEqual({
      cmd: "/mcp/tools/call",
      args: { query: "weather", tool: "web_search" },
    });
  });

  it("ignores MCP traffic that is not a tool call", () => {
    for (const name of [
      "mcp_2025-11-25_initialize_post_na",
      "mcp_2026-07-28_server-discover_post_na",
    ]) {
      expect(callFor("mcp", wire(name).body)).toBe(null); // contract: non-tool messages carry no call
    }
  });

  it("maps a recorded A2A SendMessage to params + tool under /a2a/<method>", () => {
    const body = wire("a2a_1.0_SendMessage_post").body;
    const call = callFor("a2a", body)!;
    // blindfold: contract — spec adapter table (a2a row): cmd /a2a/<method>, tool = method
    expect(call.cmd).toBe("/a2a/SendMessage");
    expect(call.args).toEqual({ ...body.params, tool: "SendMessage" });
  });
});

describe("createChainSigner — real Ed25519 issuance", () => {
  it("signs exactly the requested cmd and args with a fresh jti per call", async () => {
    const sign = await realSigner();
    const call = {
      cmd: "/mcp/tools/call",
      args: { tool: "web_search", query: "x" },
    };
    const first = parseBundle(await sign(call));
    const second = parseBundle(await sign(call));
    const p1 = payloadOf(first.invocation);
    expect(p1.cmd).toBe(call.cmd);
    expect(p1.args).toEqual(call.args);
    expect(p1.tool_server).toBe("did:web:tools.example"); // blindfold: example — the toolServer passed to createChainSigner in realSigner()
    expect(p1.jti).not.toBe(payloadOf(second.invocation).jti);
  });
});

describe("createDrsFetch", () => {
  function recorder() {
    const sent: { url: string; init: RequestInit }[] = [];
    const fetchFn = (async (
      url: string | URL | Request,
      init?: RequestInit,
    ) => {
      sent.push({ url: String(url), init: init ?? {} });
      return new Response("{}");
    }) as typeof fetch;
    return { sent, fetchFn };
  }

  it("adds a header bundle signed for the call's own arguments", async () => {
    const { sent, fetchFn } = recorder();
    const sign = await realSigner();
    const f = createDrsFetch({ signer: sign, protocol: "mcp", fetchFn });
    const body = wire("mcp_2025-11-25_tools-call_post_header").body;
    await f("http://tools/mcp", { method: "POST", body: JSON.stringify(body) });

    const bundle = new Headers(sent[0]!.init.headers).get(BUNDLE_HEADER)!;
    const args = payloadOf(parseBundle(bundle).invocation).args;
    expect(args).toEqual({ ...body.params.arguments, tool: body.params.name });
    expect(sent[0]!.init.body).toBe(JSON.stringify(body)); // body untouched
  });

  it("embeds the bundle in params._meta when carrier is meta", async () => {
    const { sent, fetchFn } = recorder();
    const f = createDrsFetch({
      signer: async () => "BUNDLE",
      protocol: "mcp",
      carrier: "meta",
      fetchFn,
    });
    const body = wire("mcp_2026-07-28_tools-call_post_meta").body;
    await f("http://tools/mcp", { method: "POST", body: JSON.stringify(body) });
    const sentBody = JSON.parse(String(sent[0]!.init.body));
    expect(sentBody.params._meta[BUNDLE_META_KEY]).toBe("BUNDLE"); // blindfold: example — the value the signer above returns
    expect(sentBody.params.arguments).toEqual(body.params.arguments);
  });

  it("passes handshakes and stream GETs through unsigned", async () => {
    const { sent, fetchFn } = recorder();
    let signed = 0;
    const f = createDrsFetch({
      signer: async () => (signed++, "B"),
      protocol: "mcp",
      fetchFn,
    });
    await f("http://tools/mcp", {
      method: "POST",
      body: JSON.stringify(wire("mcp_2025-11-25_initialize_post_na").body),
    });
    await f("http://tools/mcp", { method: "GET" });
    expect(signed).toBe(0);
    expect(new Headers(sent[0]!.init.headers).has(BUNDLE_HEADER)).toBe(false);
  });
});

describe("DrsClientTransport — a real MCP Transport", () => {
  function innerTransport() {
    const sent: Record<string, unknown>[] = [];
    const t: McpTransport = {
      start: async () => {},
      close: async () => {},
      send: async (m) => void sent.push(m),
      sessionId: "s-1",
    };
    return { t, sent };
  }

  it("implements start/close and delegates handlers (the shape Client.connect requires)", async () => {
    const { t } = innerTransport();
    const wrapped = new DrsClientTransport(t, async () => "B");
    await expect(wrapped.start()).resolves.toBeUndefined();
    const handler = () => {};
    wrapped.onmessage = handler;
    expect(t.onmessage).toBe(handler);
    expect(wrapped.sessionId).toBe("s-1"); // blindfold: example — the inner transport's sessionId set in innerTransport()
  });

  it("signs each tools/call in _meta and leaves other messages alone", async () => {
    const { t, sent } = innerTransport();
    const wrapped = new DrsClientTransport(
      t,
      async (call) => `signed:${(call.args as { tool: string }).tool}`,
    );
    await wrapped.send(wire("mcp_2025-11-25_initialize_post_na").body);
    await wrapped.send(wire("mcp_2025-11-25_tools-call_post_meta").body);
    expect(sent[0]).toEqual(wire("mcp_2025-11-25_initialize_post_na").body);
    expect(
      (sent[1]!.params as { _meta: Record<string, string> })._meta[
        BUNDLE_META_KEY
      ],
    ).toBe("signed:web_search"); // blindfold: golden — signer echoes args.tool; recorded fixture params.name is web_search
  });
});

describe("embed", () => {
  it("adds the bundle to MCP params._meta and keeps existing keys", () => {
    const out = embed(
      { jsonrpc: "2.0", method: "tools/call", params: { _meta: { a: 1 } } },
      "B",
    );
    expect(out.params).toEqual({ _meta: { a: 1, [BUNDLE_META_KEY]: "B" } });
  });

  it("refuses the metadata carrier for A2A, which accepts only the header", () => {
    expect(() =>
      createDrsFetch({
        signer: async () => "B",
        protocol: "a2a",
        carrier: "meta",
      }),
    ).toThrow(/X-DRS-Bundle header/);
  });
});
