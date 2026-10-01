// Shared live-test harness: real delegation chains, real official-SDK servers
// gated by @drs/mcp-server, and signers that can be made to misbehave.
// Nothing here stubs DRS — every decision is made by the running drs-verify.
import { createServer } from "node:http";
import express from "express";
import * as z from "zod";
import { issueRootDelegation } from "@okeyamy/drs-sdk";
import { createChainSigner } from "@drs/mcp-client";
import { createDrsGate, withDrsGate } from "@drs/mcp-server";
import { McpServer, createMcpHandler } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { DefaultRequestHandler, InMemoryTaskStore } from "@a2a-js/sdk/server";
import {
  jsonRpcHandler,
  agentCardHandler,
  UserBuilder,
} from "@a2a-js/sdk/server/express";
import { generateKey, didFromKey, now } from "./util.mjs";

export const VERIFY_URL = process.env.DRS_VERIFY_URL ?? "http://localhost:8080";
export const TOOL_SERVER =
  process.env.DRS_SERVER_IDENTITY ?? "did:key:z6MkTool";

/** A real one-hop chain human → agent scoped to rootCmd under policy. */
export async function newSigner(rootCmd, policy) {
  const human = generateKey();
  const agent = generateKey();
  const t = now();
  const root = await issueRootDelegation({
    signingKey: human,
    issuerDid: didFromKey(human),
    subjectDid: didFromKey(human),
    audienceDid: didFromKey(agent),
    cmd: rootCmd,
    policy,
    nbf: t - 60,
    exp: t + 600,
  });
  return createChainSigner({
    receipts: [root],
    signingKey: agent,
    issuerDid: didFromKey(agent),
    subjectDid: didFromKey(human),
    toolServer: TOOL_SERVER,
  });
}

/** Signer variants that model a compromised or buggy agent. */
export const attacks = {
  honest: (sign) => sign,
  // signs different arguments than it sends
  tamper: (sign) => (call) =>
    sign({ ...call, args: { ...call.args, query: "harmless" } }),
  // reuses the first bundle it ever produced
  replay: (sign) => {
    let first;
    return async (call) => (first ??= await sign(call));
  },
  // signs web_search whatever tool it actually calls
  swap: (sign) => (call) =>
    sign({ ...call, args: { tool: "web_search", query: "weather" } }),
};

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

export function makeMcpServer(executed) {
  const s = new McpServer({ name: "drs-live-tools", version: "1.0.0" });
  s.registerTool(
    "web_search",
    { inputSchema: { query: z.string() } },
    async ({ query }) => {
      executed.push(`web_search:${query}`);
      return { content: [{ type: "text", text: `results for ${query}` }] };
    },
  );
  s.registerTool(
    "delete_all",
    { inputSchema: { confirm: z.boolean() } },
    async () => {
      executed.push("delete_all");
      return { content: [{ type: "text", text: "deleted" }] };
    },
  );
  return s;
}

/** Official MCP v2 server (serves 2025-11-25 and 2026-07-28) behind a DRS gate. */
export async function startMcpHttpServer() {
  const executed = [];
  const gate = createDrsGate({ verifyUrl: VERIFY_URL, protocol: "mcp" });
  const mcp = toNodeHandler(createMcpHandler(() => makeMcpServer(executed)));
  const http = await listen(
    createServer(withDrsGate(gate, (req, res, body) => mcp(req, res, body))),
  );
  return { ...http, executed };
}

/** Official A2A v1.0 agent with its JSON-RPC endpoint behind a DRS gate. */
export async function startA2aAgent() {
  const executed = [];
  const gate = createDrsGate({ verifyUrl: VERIFY_URL, protocol: "a2a" });
  const app = express();
  const server = createServer(app);
  const http = await listen(server);
  const card = {
    name: "drs-live-agent",
    description: "live test agent",
    version: "1.0.0",
    supportedInterfaces: [
      {
        url: `${http.url}/a2a`,
        protocolBinding: "JSONRPC",
        tenant: "",
        protocolVersion: "1.0",
      },
    ],
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extensions: [],
    },
    securitySchemes: {},
    securityRequirements: [],
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills: [
      {
        id: "echo",
        name: "echo",
        description: "echo",
        tags: [],
        examples: [],
        inputModes: [],
        outputModes: [],
        securityRequirements: [],
      },
    ],
  };
  const executor = {
    async execute(ctx, bus) {
      const text = ctx.userMessage?.parts?.[0]?.content?.value ?? "";
      executed.push(text);
      bus.publish({
        kind: "message",
        messageId: crypto.randomUUID(),
        contextId: ctx.contextId,
        taskId: "",
        role: 2,
        parts: [
          {
            content: { $case: "text", value: `did: ${text}` },
            metadata: {},
            filename: "",
            mediaType: "",
          },
        ],
        metadata: {},
        extensions: [],
        referenceTaskIds: [],
      });
      bus.finished();
    },
    async cancelTask() {},
  };
  const handler = new DefaultRequestHandler(
    card,
    new InMemoryTaskStore(),
    executor,
  );
  app.use(
    "/.well-known/agent-card.json",
    agentCardHandler({ agentCardProvider: handler }),
  );
  app.use("/a2a", express.json(), (req, res, next) =>
    withDrsGate(gate, () => next())(req, res, req.body),
  );
  app.use(
    "/a2a",
    jsonRpcHandler({
      requestHandler: handler,
      userBuilder: UserBuilder.noAuthentication,
    }),
  );
  return { ...http, executed };
}
