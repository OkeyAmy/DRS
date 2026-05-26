#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import {
  buildBundle,
  buildJwt,
  computeChainHash,
  derivePublicKey,
  issueInvocation,
  issueRootDelegation,
} from "../../drs-sdk/dist/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const OUT = resolve(process.argv.find((arg) => arg.startsWith("--out="))?.slice(6) ?? ".local/drs-assessment/live-scenarios");
const VERIFY_PORT = 19_180 + Math.floor(Math.random() * 1_000);
const METRICS_PORT = VERIFY_PORT + 10_000;
const VERIFY_URL = `http://127.0.0.1:${VERIFY_PORT}`;
const METRICS_URL = `http://127.0.0.1:${METRICS_PORT}`;
const ADMIN_TOKEN = "assessment-admin-token";
const TOOL_SERVER_DID = "did:key:z6MkAssessmentToolServer";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

await mkdir(resolve(OUT, "responses"), { recursive: true });
await mkdir(resolve(OUT, "logs"), { recursive: true });

const verifier = startVerifier();
try {
  await waitForReady(VERIFY_URL);
  await runScenarios();
} finally {
  await stopVerifier(verifier);
}

async function runScenarios() {
  const valid = await createBundle({ tool: "echo", args: { message: "hello" } });
  await capture("S-live-verify-happy-path", async () => {
    const response = await postJson(`${VERIFY_URL}/verify`, valid.bundle);
    return expectResult(response, (body) => response.status === 200 && body.valid === true);
  });

  await capture("S-live-malformed-verify-body", async () => {
    const response = await fetch(`${VERIFY_URL}/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "not-json",
    });
    const body = await response.json();
    return expectResult({ status: response.status, body }, () => response.status === 400);
  });

  await capture("S-live-chain-tamper", async () => {
    const tampered = { ...valid.bundle, receipts: [tamperJwtPayload(valid.rootReceipt)] };
    const response = await postJson(`${VERIFY_URL}/verify`, tampered);
    return expectResult(
      response,
      (body) => body.valid === false && body.error?.code === "CHAIN_REFERENCE_MISMATCH",
    );
  });

  await capture("S-live-receipt-signature-tamper", async () => {
    const tamperedRoot = tamperJwtPayload(valid.rootReceipt);
    const invocation = await issueInvocation({
      signingKey: valid.agentKey,
      issuerDid: valid.agentDid,
      subjectDid: valid.humanDid,
      cmd: "/mcp/tools/call",
      args: valid.invocationArgs,
      drChain: [computeChainHash(tamperedRoot)],
      toolServer: TOOL_SERVER_DID,
    });
    const response = await postJson(`${VERIFY_URL}/verify`, buildBundle([tamperedRoot], invocation));
    return expectResult(response, (body) => body.valid === false && body.error?.code === "INVALID_SIGNATURE");
  });

  await capture("S-live-replay", async () => {
    const replay = await createBundle({ tool: "echo", args: { message: "replay" } });
    const first = await postJson(`${VERIFY_URL}/verify`, replay.bundle);
    const second = await postJson(`${VERIFY_URL}/verify`, replay.bundle);
    return {
      verdict: first.status === 200 && first.body.valid === true && second.status === 409 ? "pass" : "fail",
      first,
      second,
    };
  });

  await capture("S-live-admin-revoke-wrong-token", async () => {
    const response = await postJson(
      `${VERIFY_URL}/admin/revoke`,
      { status_list_index: 44 },
      { Authorization: "Bearer wrong-token" },
    );
    return expectResult(response, () => response.status === 401);
  });

  await capture("S-live-admin-revoke-correct-token-and-reject", async () => {
    const revoked = await createBundle({
      tool: "echo",
      args: { message: "revoked" },
      statusListIndex: 45,
    });
    const before = await postJson(`${VERIFY_URL}/verify`, revoked.bundle);
    const revoke = await postJson(
      `${VERIFY_URL}/admin/revoke`,
      { status_list_index: 45 },
      { Authorization: `Bearer ${ADMIN_TOKEN}` },
    );
    const after = await postJson(`${VERIFY_URL}/verify`, revoked.bundle);
    return {
      verdict:
        before.status === 200 &&
        before.body.valid === true &&
        revoke.status === 200 &&
        revoke.body.revoked === true &&
        after.body.valid === false &&
        after.body.error?.code === "REVOKED"
          ? "pass"
          : "fail",
      before,
      revoke,
      after,
    };
  });

  await capture("S-live-metrics", async () => {
    const response = await fetch(`${METRICS_URL}/metrics`);
    const body = await response.text();
    const sample = body
      .split("\n")
      .filter((line) => line.includes("drs_verify_verifications_total") || line.includes("drs_binding_checks_total"))
      .slice(0, 12);
    return {
      verdict: response.status === 200 && sample.length > 0 ? "pass" : "fail",
      status: response.status,
      metric_sample: sample,
    };
  });
}

async function createBundle({ tool, args, statusListIndex }) {
  const humanKey = fixedKey(41);
  const agentKey = fixedKey(42);
  const humanDid = didFromKey(humanKey);
  const agentDid = didFromKey(agentKey);
  const now = Math.floor(Date.now() / 1000);
  let rootReceipt = await issueRootDelegation({
    signingKey: humanKey,
    issuerDid: humanDid,
    subjectDid: humanDid,
    audienceDid: agentDid,
    cmd: "/mcp/tools/call",
    policy: { allowed_tools: ["echo"] },
    nbf: now - 30,
    exp: now + 3600,
  });
  if (statusListIndex !== undefined) {
    const payload = decodeJwtPayload(rootReceipt);
    rootReceipt = await buildJwt({ ...payload, drs_status_list_index: statusListIndex }, humanKey);
  }
  const invocation = await issueInvocation({
    signingKey: agentKey,
    issuerDid: agentDid,
    subjectDid: humanDid,
    cmd: "/mcp/tools/call",
    args: { tool, ...args },
    drChain: [computeChainHash(rootReceipt)],
    toolServer: TOOL_SERVER_DID,
  });
  return {
    rootReceipt,
    invocation,
    bundle: buildBundle([rootReceipt], invocation),
    agentKey,
    agentDid,
    humanDid,
    invocationArgs: { tool, ...args },
  };
}

async function capture(name, run) {
  const startedAt = new Date().toISOString();
  const result = await run();
  const record = { scenario: name, started_at: startedAt, finished_at: new Date().toISOString(), ...result };
  await writeFile(resolve(OUT, "responses", `${name}.json`), `${JSON.stringify(record, null, 2)}\n`, "utf8");
  console.log(`${name}: ${record.verdict}`);
  if (record.verdict !== "pass") process.exitCode = 1;
}

function expectResult(response, predicate) {
  return { verdict: predicate(response.body) ? "pass" : "fail", response };
}

async function postJson(url, body, headers = {}) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

function startVerifier() {
  const child = spawn("go", ["run", "./cmd/server"], {
    cwd: resolve(ROOT, "drs-verify"),
    detached: true,
    env: {
      ...process.env,
      LISTEN_ADDR: `127.0.0.1:${VERIFY_PORT}`,
      METRICS_ADDR: `127.0.0.1:${METRICS_PORT}`,
      DRS_ADMIN_TOKEN: ADMIN_TOKEN,
      LOG_LEVEL: "error",
      LOG_FORMAT: "text",
      NONCE_STORE_BACKEND: "memory",
      RATE_LIMIT_PER_IP: "10000",
      RATE_LIMIT_GLOBAL: "10000",
    },
  });
  child.stdout.on("data", (chunk) => appendLog("verifier.log", chunk));
  child.stderr.on("data", (chunk) => appendLog("verifier.log", chunk));
  return child;
}

async function appendLog(name, chunk) {
  await writeFile(resolve(OUT, "logs", name), chunk, { flag: "a" });
}

async function stopVerifier(child) {
  if (child.pid === undefined) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  await Promise.race([
    new Promise((resolveExit) => child.once("exit", resolveExit)),
    delay(5_000).then(() => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }),
  ]);
}

async function waitForReady(baseUrl) {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/readyz`);
      if (response.ok) return;
    } catch (error) {
      await appendLog("verifier.log", `ready check failed: ${error instanceof Error ? error.message : String(error)}\n`);
    }
    await delay(500);
  }
  throw new Error(`drs-verify did not become ready at ${baseUrl}`);
}

function fixedKey(byte) {
  return new Uint8Array(32).fill(byte);
}

function didFromKey(privateKey) {
  const publicKey = derivePublicKey(privateKey);
  return `did:key:z${base58Encode(new Uint8Array([0xed, 0x01, ...publicKey]))}`;
}

function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      carry += 256 * digits[index];
      digits[index] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.unshift(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (const byte of bytes) {
    if (byte !== 0) break;
    result += "1";
  }
  for (const digit of digits) result += ALPHABET[digit];
  return result;
}

function decodeJwtPayload(jwt) {
  const [, payload] = jwt.split(".");
  return JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
}

function tamperJwtPayload(jwt) {
  const parts = jwt.split(".");
  const payload = decodeJwtPayload(jwt);
  const tamperedPayload = Buffer.from(
    JSON.stringify({ ...payload, jti: `${payload.jti}:tampered` }),
    "utf8",
  ).toString("base64url");
  return `${parts[0]}.${tamperedPayload}.${parts[2]}`;
}
