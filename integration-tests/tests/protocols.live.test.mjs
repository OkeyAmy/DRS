// Live protocol suite: official MCP and A2A SDKs, a running drs-verify, real
// Ed25519 chains. Each row of the matrix is a client configuration a real
// integrator would use; each case is an honest call or an attack.
//
// Expected outcomes come from docs-site/src/reference/protocol-gate.md:
//   honest call executes; tamper / replay / swap / unsigned are refused and the
//   tool never runs; handshake and discovery need no bundle.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { Client as ClientV1 } from "mcp-sdk-v1/client/index.js";
import { StreamableHTTPClientTransport as TransportV1 } from "mcp-sdk-v1/client/streamableHttp.js";
import { ClientFactory, JsonRpcTransportFactory } from "@a2a-js/sdk/client";
import { createDrsFetch, DrsClientTransport } from "@drs/mcp-client";
import {
  attacks,
  newSigner,
  startA2aAgent,
  startMcpHttpServer,
  VERIFY_URL,
} from "./live-harness.mjs";

const MCP_POLICY = { allowed_tools: ["web_search"] };

/** Client configurations under test — SDK × protocol era × bundle carrier. */
const MCP_CLIENTS = [
  {
    name: "sdk v2.2 / 2025-11-25 (default) / header",
    sdk: "v2",
    era: null,
    carrier: "header",
  },
  {
    name: "sdk v2.2 / 2026-07-28 (pinned) / header",
    sdk: "v2",
    era: "2026-07-28",
    carrier: "header",
  },
  {
    name: "sdk v2.2 / 2026-07-28 (pinned) / _meta",
    sdk: "v2",
    era: "2026-07-28",
    carrier: "meta",
  },
  {
    name: "sdk v1.31 / 2025-11-25 / header",
    sdk: "v1",
    era: null,
    carrier: "header",
  },
];

async function connectMcp(cfg, url, signer) {
  const fetch = signer
    ? createDrsFetch({ signer, protocol: "mcp", carrier: cfg.carrier })
    : undefined;
  if (cfg.sdk === "v1") {
    const client = new ClientV1({ name: "live", version: "1" });
    await client.connect(
      new TransportV1(new URL(`${url}/mcp`), fetch ? { fetch } : {}),
    );
    return client;
  }
  const options = cfg.era
    ? { versionNegotiation: { mode: { pin: cfg.era } } }
    : {};
  const client = new Client({ name: "live", version: "1" }, options);
  await client.connect(
    new StreamableHTTPClientTransport(
      new URL(`${url}/mcp`),
      fetch ? { fetch } : {},
    ),
  );
  return client;
}

/** Calls a tool; returns { ok, text } or { ok:false, error }. */
async function call(client, name, args) {
  try {
    const r = await client.callTool({ name, arguments: args });
    return { ok: !r.isError, text: r.content?.[0]?.text };
  } catch (error) {
    return { ok: false, error: String(error?.message ?? error) };
  }
}

before(async () => {
  const res = await fetch(`${VERIFY_URL}/readyz`).catch(() => null);
  assert.ok(
    res?.ok,
    `drs-verify must be running at ${VERIFY_URL} (set DRS_VERIFY_URL)`,
  );
});

for (const cfg of MCP_CLIENTS) {
  describe(`MCP over HTTP — ${cfg.name}`, () => {
    let server;
    before(async () => (server = await startMcpHttpServer()));
    after(() => server.close());

    test("handshake and tools/list need no bundle", async () => {
      const client = await connectMcp(cfg, server.url, null);
      const { tools } = await client.listTools();
      assert.deepEqual(tools.map((t) => t.name).sort(), [
        "delete_all",
        "web_search",
      ]);
      await client.close();
    });

    test("honest signed call executes", async () => {
      const client = await connectMcp(
        cfg,
        server.url,
        attacks.honest(await newSigner("/mcp", MCP_POLICY)),
      );
      const r = await call(client, "web_search", { query: "weather" });
      assert.equal(r.ok, true, r.error);
      assert.equal(r.text, "results for weather"); // blindfold: example — the web_search tool in live-harness.mjs echoes its query
      assert.ok(server.executed.includes("web_search:weather"));
      await client.close();
    });

    test("tampered arguments are refused and never execute", async () => {
      const client = await connectMcp(
        cfg,
        server.url,
        attacks.tamper(await newSigner("/mcp", MCP_POLICY)),
      );
      const r = await call(client, "web_search", { query: "secret-exfil" });
      assert.equal(r.ok, false);
      assert.match(r.error, /BINDING_MISMATCH/);
      assert.ok(!server.executed.includes("web_search:secret-exfil"));
      await client.close();
    });

    test("a replayed bundle is refused on second use", async () => {
      const client = await connectMcp(
        cfg,
        server.url,
        attacks.replay(await newSigner("/mcp", MCP_POLICY)),
      );
      assert.equal(
        (await call(client, "web_search", { query: "once" })).ok,
        true,
      );
      const second = await call(client, "web_search", { query: "once" });
      assert.equal(second.ok, false);
      assert.match(second.error, /REPLAY_DETECTED/);
      await client.close();
    });

    test("calling a tool other than the signed one is refused", async () => {
      const before = server.executed.filter((e) => e === "delete_all").length;
      const client = await connectMcp(
        cfg,
        server.url,
        attacks.swap(await newSigner("/mcp", MCP_POLICY)),
      );
      const r = await call(client, "delete_all", { confirm: true });
      assert.equal(r.ok, false);
      assert.match(r.error, /BINDING_MISMATCH/);
      assert.equal(
        server.executed.filter((e) => e === "delete_all").length,
        before,
      );
      await client.close();
    });

    test("a tool outside the delegated policy is refused even when honestly signed", async () => {
      const client = await connectMcp(
        cfg,
        server.url,
        attacks.honest(await newSigner("/mcp", MCP_POLICY)),
      );
      const r = await call(client, "delete_all", { confirm: true });
      assert.equal(r.ok, false);
      assert.match(r.error, /POLICY_VIOLATION/);
      await client.close();
    });

    test("an unsigned tool call is refused with 403, not an OAuth 401", async () => {
      const client = await connectMcp(cfg, server.url, null);
      const r = await call(client, "web_search", { query: "unsigned" });
      assert.equal(r.ok, false);
      assert.match(r.error, /MISSING_BUNDLE/);
      assert.doesNotMatch(r.error, /401|authoriz/i);
      assert.ok(!server.executed.includes("web_search:unsigned"));
      await client.close();
    });
  });
}

describe("MCP over stdio — sdk v2.2 with DrsClientTransport / DrsGatedServerTransport", () => {
  const serverScript = fileURLToPath(
    new URL("./fixtures/stdio-mcp-server.mjs", import.meta.url),
  );

  async function stdioClient(signer) {
    let stderr = "";
    const inner = new StdioClientTransport({
      command: process.execPath,
      args: [serverScript],
      env: { ...process.env, DRS_VERIFY_URL: VERIFY_URL },
      stderr: "pipe",
    });
    const transport = signer ? new DrsClientTransport(inner, signer) : inner;
    const client = new Client({ name: "live-stdio", version: "1" });
    await client.connect(transport);
    inner.stderr?.on("data", (d) => (stderr += d));
    return { client, executed: () => stderr };
  }

  test("honest call executes over stdio", async () => {
    const { client, executed } = await stdioClient(
      await newSigner("/mcp", MCP_POLICY),
    );
    const r = await call(client, "web_search", { query: "stdio" });
    assert.equal(r.ok, true, r.error);
    await new Promise((res) => setTimeout(res, 50));
    assert.match(executed(), /EXECUTED web_search:stdio/);
    await client.close();
  });

  test("tampered and unsigned calls are refused over stdio", async () => {
    const tampered = await stdioClient(
      attacks.tamper(await newSigner("/mcp", MCP_POLICY)),
    );
    const t = await call(tampered.client, "web_search", {
      query: "stdio-tamper",
    });
    assert.equal(t.ok, false);
    assert.match(t.error, /BINDING_MISMATCH/);
    await tampered.client.close();

    const unsigned = await stdioClient(null);
    const u = await call(unsigned.client, "web_search", {
      query: "stdio-unsigned",
    });
    assert.equal(u.ok, false);
    assert.match(u.error, /MISSING_BUNDLE/);
    await new Promise((res) => setTimeout(res, 50));
    assert.doesNotMatch(tampered.executed() + unsigned.executed(), /EXECUTED/);
    await unsigned.client.close();
  });
});

describe("A2A v1.0 JSON-RPC — @a2a-js/sdk 1.3.0", () => {
  let agent;
  before(async () => (agent = await startA2aAgent()));
  after(() => agent.close());

  const A2A_POLICY = { allowed_tools: ["SendMessage"] };

  async function send(signer, text, messageId = crypto.randomUUID()) {
    const fetchImpl = signer
      ? createDrsFetch({ signer, protocol: "a2a" })
      : undefined;
    const factory = new ClientFactory({
      transports: [new JsonRpcTransportFactory(fetchImpl ? { fetchImpl } : {})],
    });
    const client = await factory.createFromUrl(agent.url);
    const message = {
      messageId,
      contextId: "",
      taskId: "",
      role: 1,
      parts: [
        {
          content: { $case: "text", value: text },
          metadata: {},
          filename: "",
          mediaType: "",
        },
      ],
      metadata: {},
      extensions: [],
      referenceTaskIds: [],
    };
    try {
      await client.sendMessage({
        tenant: "",
        message,
        configuration: undefined,
        metadata: {},
      });
      return { ok: true };
    } catch (error) {
      return { ok: false, error: String(error?.message ?? error) };
    }
  }

  test("honest signed SendMessage reaches the agent under an allowed_tools policy", async () => {
    await send(
      attacks.honest(await newSigner("/a2a", A2A_POLICY)),
      "summarise Q3",
    );
    assert.ok(
      agent.executed.includes("summarise Q3"),
      `agent never ran: ${agent.executed}`,
    );
  });

  test("a changed message is refused and never reaches the agent", async () => {
    const lying = (sign) => (c) => {
      const params = structuredClone(c.args);
      params.message.parts[0].text = "harmless";
      return sign({ ...c, args: params });
    };
    const r = await send(
      lying(await newSigner("/a2a", A2A_POLICY)),
      "wire the funds",
    );
    assert.equal(r.ok, false);
    assert.match(r.error, /BINDING_MISMATCH/);
    assert.ok(!agent.executed.includes("wire the funds"));
  });

  test("replayed and unsigned A2A calls are refused", async () => {
    // Identical message (same messageId) so binding matches and only the nonce can refuse it.
    const replay = attacks.replay(await newSigner("/a2a", A2A_POLICY));
    const id = crypto.randomUUID();
    await send(replay, "first", id);
    const second = await send(replay, "first", id);
    assert.equal(second.ok, false);
    assert.match(second.error, /REPLAY_DETECTED/);

    const unsigned = await send(null, "unsigned");
    assert.equal(unsigned.ok, false);
    assert.match(unsigned.error, /MISSING_BUNDLE/);
    assert.ok(!agent.executed.includes("unsigned"));
  });
});
