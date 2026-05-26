import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createDrsHttpMiddleware } from "@drs/mcp-server";
import { VerifyClient } from "@okeyamy/drs-sdk";
import { serialiseBundle } from "@okeyamy/drs-sdk";
import type { ChainBundle, VerificationResult } from "@okeyamy/drs-sdk";
import { validateVerificationMetadata } from "./metadata.js";
import { buildPersonaScenario } from "./personas.js";
import { createVerifierHarness } from "./verifier-harness.js";

interface EvidenceRecord {
  readonly scenario: string;
  readonly command: string;
  readonly request: {
    readonly tool: string;
    readonly signedArgs: Record<string, unknown>;
    readonly body: Record<string, unknown>;
    readonly bundle: {
      readonly version: ChainBundle["bundle_version"];
      readonly receiptCount: number;
      readonly invocationPresent: boolean;
    };
  };
  readonly response: VerificationResult;
  readonly metadataValidation: ReturnType<typeof validateVerificationMetadata>;
  readonly verdict: "pass" | "fail";
}

interface MiddlewareEvidenceRecord {
  readonly scenario: "S-middleware-handler-block";
  readonly command: string;
  readonly request: {
    readonly signedArgs: Record<string, unknown>;
    readonly body: Record<string, unknown>;
    readonly hasBundleHeader: boolean;
  };
  readonly middlewareResult: unknown;
  readonly handlerCalls: number;
  readonly verdict: "pass" | "fail";
}

const SCENARIOS = [
  {
    id: "S-verify-happy-path",
    tool: "lookup_customer",
    args: { customer_id: "cus_001" },
    expected: (result: VerificationResult) => result.valid && result.binding === "match",
  },
  {
    id: "S-audit-context",
    tool: "draft_reply",
    args: { customer_id: "cus_001", tone: "concise" },
    expected: (result: VerificationResult) =>
      result.valid &&
      result.context?.root_type === "human" &&
      result.context.regulatory?.frameworks.includes("eu-ai-act-art12") === true,
  },
  {
    id: "S-policy-violation",
    tool: "refund_customer",
    args: { customer_id: "cus_001", amount_usd: 25 },
    expected: (result: VerificationResult) =>
      !result.valid && result.error?.code === "POLICY_VIOLATION",
  },
  {
    id: "S-body-binding-mismatch",
    tool: "lookup_customer",
    args: { customer_id: "cus_001" },
    bodyOverride: { tool: "lookup_customer", customer_id: "cus_999" },
    expected: (result: VerificationResult) => result.valid && result.binding === "mismatch",
  },
] as const;

async function main(): Promise<void> {
  const outputDir = resolve(outputDirectoryArg());
  await mkdir(outputDir, { recursive: true });

  const harness = createVerifierHarness();
  try {
    await harness.start();
    const scenario = await buildPersonaScenario(harness.baseUrl());
    const client = new VerifyClient({ baseUrl: harness.baseUrl(), timeoutMs: 10_000 });

    for (const item of SCENARIOS) {
      const bundle = await scenario.buildBundle(item.tool, item.args);
      const signedBody = { tool: item.tool, ...item.args };
      const body = "bodyOverride" in item ? item.bodyOverride : signedBody;
      const response = await client.verify(bundle, { body });
      const metadataValidation = validateVerificationMetadata(response);
      const metadataOk = response.valid ? metadataValidation.valid : true;
      const record: EvidenceRecord = {
        scenario: item.id,
        command: "pnpm --filter drs-persona-walkthrough capture",
        request: {
          tool: item.tool,
          signedArgs: signedBody,
          body,
          bundle: {
            version: bundle.bundle_version,
            receiptCount: bundle.receipts.length,
            invocationPresent: bundle.invocation.length > 0,
          },
        },
        response,
        metadataValidation,
        verdict: item.expected(response) && metadataOk ? "pass" : "fail",
      };

      await writeEvidence(outputDir, record);
      console.log(`${item.id}: ${record.verdict}`);
      if (record.verdict === "fail") {
        process.exitCode = 1;
      }
    }

    await captureMiddlewareHandlerBlock(outputDir, scenario, harness.baseUrl());
  } finally {
    await harness.stop();
  }
}

async function captureMiddlewareHandlerBlock(
  outputDir: string,
  scenario: Awaited<ReturnType<typeof buildPersonaScenario>>,
  verifyBaseUrl: string,
): Promise<void> {
  const signedArgs = { tool: "lookup_customer", customer_id: "cus_001" };
  const body = { tool: "lookup_customer", customer_id: "cus_999" };
  const bundle = await scenario.buildBundle("lookup_customer", {
    customer_id: "cus_001",
  });
  let handlerCalls = 0;
  const middleware = createDrsHttpMiddleware({
    verifyUrl: `${verifyBaseUrl}/verify`,
    timeoutMs: 10_000,
  });

  const middlewareResult = await middleware(
    {
      headers: { "x-drs-bundle": serialiseBundle(bundle) },
      body,
    },
    () => {
      handlerCalls += 1;
    },
  );

  const record: MiddlewareEvidenceRecord = {
    scenario: "S-middleware-handler-block",
    command: "pnpm --filter drs-persona-walkthrough capture",
    request: {
      signedArgs,
      body,
      hasBundleHeader: true,
    },
    middlewareResult,
    handlerCalls,
    verdict:
      !middlewareResult.ok &&
      middlewareResult.status === 403 &&
      middlewareResult.error.code === "BINDING_MISMATCH" &&
      handlerCalls === 0
        ? "pass"
        : "fail",
  };
  await writeEvidence(outputDir, record);
  console.log(`${record.scenario}: ${record.verdict}`);
  if (record.verdict === "fail") {
    process.exitCode = 1;
  }
}

function outputDirectoryArg(): string {
  const args = process.argv.slice(2).filter((arg) => arg !== "--");
  return args[0] ?? ".local/drs-assessment/responses";
}

async function writeEvidence(
  outputDir: string,
  record: EvidenceRecord | MiddlewareEvidenceRecord,
): Promise<void> {
  const file = resolve(outputDir, `${record.scenario}.json`);
  await writeFile(file, `${JSON.stringify(record, null, 2)}\n`, "utf8");
}

main().catch((error: unknown) => {
  console.error("[FATAL]", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
