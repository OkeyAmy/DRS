// End-to-end integration tests for DRS.
//
// Asserts that the PUBLISHED npm SDK and the PUBLISHED Docker image work
// together over HTTP. No local monorepo imports, no mocks — this is what
// an outside developer gets when they `pnpm add @okeyamy/drs-sdk` and
// `docker run ghcr.io/okeyamy/drs-verify`.

import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import {
  buildBundle,
  issueRootDelegation,
  issueInvocation,
  computeChainHash,
} from "@okeyamy/drs-sdk";
import { generateKey, didFromKey, now, postVerify, postVerifyWithBody } from "./util.mjs";

const VERIFY_URL = process.env.DRS_VERIFY_URL ?? "http://localhost:8080";
// /metrics lives on a separate listener (METRICS_ADDR), mapped to host 19090 by
// docker-compose.test.yml. Derive the host from VERIFY_URL and swap the port.
const METRICS_URL =
  process.env.DRS_METRICS_URL ??
  VERIFY_URL.replace(/:\d+$/, `:${process.env.DRS_VERIFY_METRICS_PORT ?? "19090"}`);

describe("operational endpoints", () => {
  test("/healthz returns 200", async () => {
    const res = await fetch(`${VERIFY_URL}/healthz`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "ok");
  });

  test("/readyz returns 200 once warm-up completes", async () => {
    const res = await fetch(`${VERIFY_URL}/readyz`);
    assert.equal(res.status, 200);
  });

  test("/metrics exposes Prometheus exposition format", async () => {
    const res = await fetch(`${METRICS_URL}/metrics`);
    assert.equal(res.status, 200);
    const body = await res.text();
    // Go runtime collectors register eagerly on boot — their presence proves
    // promhttp is wired. drs_* metrics register lazily (only when a code path
    // increments them), so we verify those separately after /verify runs.
    assert.match(body, /^# HELP go_/m, "expected Go runtime metrics from promhttp");
  });
});

describe("happy path — fresh chain verifies", () => {
  test("root DR + invocation → result.valid === true, and drs_verify metric increments", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: {
        max_cost_usd: 1.0,
        allowed_tools: ["echo"],
      },
      nbf: iat,
      exp: iat + 3600,
    });

    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args: { tool: "echo", message: "hello" },
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkExampleToolServer",
    });

    const bundle = buildBundle([rootDR], invocation);
    const { status, body } = await postVerify(VERIFY_URL, bundle);

    assert.equal(status, 200, `unexpected status: ${status}, body: ${JSON.stringify(body)}`);
    assert.equal(body.valid, true, `verification failed: ${JSON.stringify(body.error)}`);

    // Now that at least one verification has happened, drs_verify_verifications_total
    // must appear under the drs_ namespace on /metrics.
    const metricsRes = await fetch(`${METRICS_URL}/metrics`);
    const metricsBody = await metricsRes.text();
    assert.match(
      metricsBody,
      /drs_verify_verifications_total/,
      "drs_verify_verifications_total missing from /metrics after a /verify call",
    );
  });
});

describe("/verify body binding — JCS equality against invocation.args", () => {
  test("matching body → binding: 'match'", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0, allowed_tools: ["approve_payment"] },
      nbf: iat,
      exp: iat + 3600,
    });

    const args = { tool: "approve_payment", transaction_id: "T1" };
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args,
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });
    const bundle = buildBundle([rootDR], invocation);

    // Tool server sends the exact body it received; drs-verify confirms
    // body ≡ args after JCS.
    const { status, body } = await postVerifyWithBody(VERIFY_URL, bundle, args);

    assert.equal(status, 200, `unexpected status: ${status}`);
    assert.equal(body.valid, true, `chain must verify: ${JSON.stringify(body.error)}`);
    assert.equal(body.binding, "match", `binding should be match, got ${body.binding}`);
  });

  test("divergent body → binding: 'mismatch', chain still valid", async () => {
    // Agent signs args for T1 but tool server receives a body for T2. Chain
    // is untouched — only the body diverged. drs-verify must flag this as
    // binding=mismatch while leaving valid=true (cryptographic truth unchanged).
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0, allowed_tools: ["approve_payment"] },
      nbf: iat,
      exp: iat + 3600,
    });

    const signedArgs = { tool: "approve_payment", transaction_id: "T1" };
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args: signedArgs,
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });
    const bundle = buildBundle([rootDR], invocation);

    // Tampered body: T2 instead of T1. Bundle bytes untouched.
    const tamperedBody = { tool: "approve_payment", transaction_id: "T2" };
    const { body } = await postVerifyWithBody(VERIFY_URL, bundle, tamperedBody);

    assert.equal(body.valid, true, "bundle bytes were not touched; chain must verify");
    assert.equal(body.binding, "mismatch", `binding should be mismatch, got ${body.binding}`);
  });

  test("reordered keys in body still match via JCS", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0 },
      nbf: iat,
      exp: iat + 3600,
    });

    // Signer emitted args with a specific key order; body will arrive with a
    // different order. JCS canonicalisation must normalise both.
    const args = { b: 2, a: 1, c: "value" };
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args,
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });
    const bundle = buildBundle([rootDR], invocation);

    const reorderedBody = { a: 1, b: 2, c: "value" };
    const { body } = await postVerifyWithBody(VERIFY_URL, bundle, reorderedBody);

    assert.equal(body.valid, true);
    assert.equal(body.binding, "match", "JCS must normalise key order on both sides");
  });

  test("body omitted → no binding field in response", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0 },
      nbf: iat,
      exp: iat + 3600,
    });
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args: { tool: "echo" },
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });
    const bundle = buildBundle([rootDR], invocation);

    const { body } = await postVerify(VERIFY_URL, bundle);

    assert.equal(body.valid, true);
    assert.equal(
      body.binding,
      undefined,
      "binding field must be absent when no body was sent",
    );
  });
});

describe("failure paths", () => {
  test("tampered invocation signature returns invalid", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0 },
      nbf: iat,
      exp: iat + 3600,
    });
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args: {},
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });

    // Flip the last character of the signature segment.
    const parts = invocation.split(".");
    const sig = parts[2];
    const tampered =
      parts[0] + "." + parts[1] + "." + sig.slice(0, -1) + (sig.slice(-1) === "A" ? "B" : "A");

    const bundle = buildBundle([rootDR], tampered);
    const { body } = await postVerify(VERIFY_URL, bundle);

    assert.equal(body.valid, false, "tampered signature must fail verification");
    assert.ok(body.error, "response must include error object");
  });

  test("expired root DR returns invalid", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now() - 7200;
    const expiredExp = iat + 3600; // expired an hour ago
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0 },
      nbf: iat,
      exp: expiredExp,
    });
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args: {},
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });

    const { body } = await postVerify(VERIFY_URL, buildBundle([rootDR], invocation));
    assert.equal(body.valid, false);
  });

  test("replay of same bundle returns REPLAY_DETECTED on second call", async () => {
    const operatorKey = generateKey();
    const agentKey = generateKey();
    const operatorDid = didFromKey(operatorKey);
    const agentDid = didFromKey(agentKey);

    const iat = now();
    const rootDR = await issueRootDelegation({
      signingKey: operatorKey,
      issuerDid: operatorDid,
      subjectDid: operatorDid,
      audienceDid: agentDid,
      cmd: "/mcp/tools/call",
      policy: { max_cost_usd: 1.0 },
      nbf: iat,
      exp: iat + 3600,
    });
    const invocation = await issueInvocation({
      signingKey: agentKey,
      issuerDid: agentDid,
      subjectDid: operatorDid,
      cmd: "/mcp/tools/call",
      args: { n: 1 },
      drChain: [computeChainHash(rootDR)],
      toolServer: "did:key:z6MkTool",
    });
    const bundle = buildBundle([rootDR], invocation);

    const first = await postVerify(VERIFY_URL, bundle);
    assert.equal(first.body.valid, true, "first call should succeed");

    const second = await postVerify(VERIFY_URL, bundle);
    // The verifier commits the nonce only on valid chains. Once committed,
    // the same JTI must be rejected. Status may be 200 (with valid:false)
    // or 409 depending on how the server surfaces the replay — accept both.
    if (second.status === 409) {
      // ok — explicit REPLAY_DETECTED response
      assert.ok(
        second.body.error === "REPLAY_DETECTED" ||
          /replay/i.test(second.body.detail ?? second.body.error ?? ""),
      );
    } else {
      assert.equal(second.body.valid, false, "replayed bundle must not verify");
    }
  });
});

describe("/admin/revoke — requires DRS_ADMIN_TOKEN", () => {
  const ADMIN_TOKEN = "e2e-integration-test-token";

  test("wrong token returns 401", async () => {
    const res = await fetch(`${VERIFY_URL}/admin/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer not-the-right-token",
      },
      body: JSON.stringify({ status_list_index: 1 }),
    });
    assert.equal(res.status, 401);
  });

  test("correct token returns 200 and records revocation", async () => {
    const res = await fetch(`${VERIFY_URL}/admin/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${ADMIN_TOKEN}`,
      },
      body: JSON.stringify({ status_list_index: 42 }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.revoked, true);
    assert.equal(body.status_list_index, 42);
  });
});
