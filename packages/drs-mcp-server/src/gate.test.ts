import { describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  createDrsGate,
  pickForwardedHeaders,
  type GateDecision,
} from "./gate.js";
import { withDrsGate } from "./node.js";
import {
  DrsGatedServerTransport,
  type JsonRpcMessage,
  type McpTransport,
} from "./stdio.js";

// These tests cover this package's own logic: what it forwards, how it
// applies a decision, and that it fails closed. The protocol rules themselves
// run in drs-verify and are covered by the live suite in integration-tests/.

function recordingFetch(decision: unknown, status = 200) {
  const calls: { url: string; payload: Record<string, unknown> }[] = [];
  const fetchFn = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), payload: JSON.parse(String(init?.body)) });
    return new Response(JSON.stringify(decision), { status });
  }) as typeof fetch;
  return { calls, fetchFn };
}

const ALLOW: GateDecision = { allow: true, gated: true, status: 200 };

describe("pickForwardedHeaders", () => {
  it("keeps only the DRS/MCP/A2A routing headers and never credentials", () => {
    const out = pickForwardedHeaders({
      "X-DRS-Bundle": "b",
      "Mcp-Name": "web_search",
      Authorization: "Bearer secret",
      cookie: "sid=1",
      "A2A-Version": "1.0",
    });
    // blindfold: contract — gate.ts FORWARDED_HEADERS allowlist; credentials must never leave the process
    expect(out).toEqual({
      "x-drs-bundle": "b",
      "mcp-name": "web_search",
      "a2a-version": "1.0",
    });
  });
});

describe("createDrsGate", () => {
  it("posts protocol, method, filtered headers and body to /v1/gate", async () => {
    const { calls, fetchFn } = recordingFetch(ALLOW);
    const gate = createDrsGate({
      verifyUrl: "http://verifier:8080",
      protocol: "mcp",
      fetchFn,
    });
    const decision = await gate.check({
      method: "POST",
      headers: { authorization: "x", "x-drs-bundle": "b" },
      body: { a: 1 },
    });
    expect(decision.allow).toBe(true);
    // blindfold: contract — drs-verify cmd/server mounts POST /v1/gate
    expect(calls[0]!.url).toBe("http://verifier:8080/v1/gate");
    expect(calls[0]!.payload).toEqual({
      protocol: "mcp",
      method: "POST",
      headers: { "x-drs-bundle": "b" },
      body: { a: 1 },
    });
  });

  it("fails closed when the verifier is unreachable, errors, or answers nonsense", async () => {
    const down = createDrsGate({
      verifyUrl: "http://verifier",
      protocol: "mcp",
      fetchFn: (async () => {
        throw new Error("ECONNREFUSED");
      }) as typeof fetch,
    });
    const errored = createDrsGate({
      verifyUrl: "http://verifier",
      protocol: "mcp",
      fetchFn: recordingFetch({}, 500).fetchFn,
    });
    const nonsense = createDrsGate({
      verifyUrl: "http://verifier",
      protocol: "mcp",
      fetchFn: recordingFetch({ ok: 1 }).fetchFn,
    });
    for (const gate of [down, errored, nonsense]) {
      const d = await gate.check({ method: "POST", headers: {}, body: {} });
      // blindfold: contract — CLAUDE.md fail-closed: verifier failure denies with 503
      expect([d.allow, d.status]).toEqual([false, 503]);
    }
  });
});

describe("withDrsGate (node:http)", () => {
  async function serve(decision: GateDecision) {
    const { calls, fetchFn } = recordingFetch(decision);
    const gate = createDrsGate({
      verifyUrl: "http://verifier",
      protocol: "mcp",
      fetchFn,
    });
    const seen: unknown[] = [];
    const server: Server = createServer(
      withDrsGate(gate, (_req, res, body) => {
        seen.push(body);
        res.end("handled");
      }),
    );
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
    return {
      url,
      calls,
      seen,
      close: () => new Promise((r) => server.close(r)),
    };
  }

  it("hands the parsed body to the handler when allowed", async () => {
    const s = await serve(ALLOW);
    const res = await fetch(s.url, {
      method: "POST",
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
    });
    expect(await res.text()).toBe("handled"); // blindfold: example — the handler above writes "handled"
    expect(s.seen[0]).toEqual({ jsonrpc: "2.0", id: 1, method: "tools/call" });
    expect(s.calls[0]!.payload.body).toEqual({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
    });
    await s.close();
  });

  it("answers with the verifier's status and body when denied, and never runs the handler", async () => {
    const refusal = {
      jsonrpc: "2.0",
      id: 1,
      error: { code: -32010, message: "DRS: MISSING_BUNDLE" },
    };
    const s = await serve({
      allow: false,
      gated: true,
      status: 403,
      response: refusal,
    });
    const res = await fetch(s.url, { method: "POST", body: "{}" });
    expect(res.status).toBe(403); // blindfold: example — the decision fed in above has status 403
    expect(await res.json()).toEqual(refusal);
    expect(s.seen).toEqual([]);
    await s.close();
  });

  it("rejects a non-JSON body without consulting the verifier", async () => {
    const s = await serve(ALLOW);
    const res = await fetch(s.url, { method: "POST", body: "{not json" });
    expect(res.status).toBe(400); // blindfold: standard — RFC 9110 §15.5.1: malformed request syntax is 400
    expect(s.calls).toEqual([]);
    await s.close();
  });
});

describe("DrsGatedServerTransport (stdio)", () => {
  function inner() {
    const sent: JsonRpcMessage[] = [];
    const t: McpTransport = {
      start: async () => {},
      close: async () => {},
      send: async (m) => void sent.push(m),
    };
    return { t, sent };
  }

  it("delivers allowed messages in arrival order and answers refused requests with a JSON-RPC error", async () => {
    const decisions: Record<string, GateDecision> = {
      ok: ALLOW,
      bad: {
        allow: false,
        gated: true,
        status: 403,
        response: {
          jsonrpc: "2.0",
          id: 2,
          error: { code: -32010, message: "DRS: BINDING_MISMATCH" },
        },
      },
    };
    const gate = {
      check: async (r: { body?: unknown }) =>
        decisions[(r.body as { method: string }).method]!,
    };
    const { t, sent } = inner();
    const wrapped = new DrsGatedServerTransport(t, gate);
    const delivered: unknown[] = [];
    wrapped.onmessage = (m) => delivered.push(m.id);

    t.onmessage!({ jsonrpc: "2.0", id: 1, method: "ok" });
    t.onmessage!({ jsonrpc: "2.0", id: 2, method: "bad" });
    t.onmessage!({ jsonrpc: "2.0", id: 3, method: "ok" });
    await new Promise((r) => setTimeout(r, 10));

    expect(delivered).toEqual([1, 3]);
    expect(sent).toEqual([
      {
        jsonrpc: "2.0",
        id: 2,
        error: { code: -32010, message: "DRS: BINDING_MISMATCH" },
      },
    ]);
  });

  it("never replies to a refused notification", async () => {
    const gate = {
      check: async () =>
        ({ allow: false, gated: true, status: 403 }) as GateDecision,
    };
    const { t, sent } = inner();
    new DrsGatedServerTransport(t, gate);
    t.onmessage!({ jsonrpc: "2.0", method: "notifications/x" });
    await new Promise((r) => setTimeout(r, 10));
    expect(sent).toEqual([]);
  });
});
