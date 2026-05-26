import { FRAMEWORK_REGISTRY } from "./metadata.js";
import { buildPersonaScenario } from "./personas.js";
import { createVerifierHarness } from "./verifier-harness.js";

async function main(): Promise<void> {
  const harness = createVerifierHarness();
  try {
    await harness.start();
    const scenario = await buildPersonaScenario(harness.baseUrl());

    console.log("DRS Persona Walkthrough — real verifier, real receipts");
    console.log(`Human DID      : ${scenario.audit.humanDid}`);
    console.log(`Agent DID      : ${scenario.audit.agentDid}`);
    console.log(`Tool server DID: ${scenario.audit.toolServerDid}`);
    console.log(`Session ID     : ${scenario.audit.sessionId}`);
    console.log();

    await printCase(
      "Product builder",
      "allowed support lookup executes only after DRS verification",
      scenario.verifyToolCall("lookup_customer", { customer_id: "cus_001" }),
    );

    await printCase(
      "Auditor",
      "verification returns consent and regulatory evidence",
      scenario.verifyToolCall("draft_reply", {
        customer_id: "cus_001",
        tone: "concise",
      }),
    );

    await printCase(
      "Security engineer",
      "refund attempt is denied because policy did not grant it",
      scenario.verifyToolCall("refund_customer", {
        customer_id: "cus_001",
        amount_usd: 25,
      }),
    );

    await printCase(
      "Tool owner",
      "signed intent and HTTP body must match before tool execution",
      scenario.verifyToolCall(
        "lookup_customer",
        { customer_id: "cus_001" },
        { bodyOverride: { tool: "lookup_customer", customer_id: "cus_999" } },
      ),
    );
  } finally {
    await harness.stop();
  }
}

async function printCase(
  persona: string,
  lesson: string,
  resultPromise: Promise<{ valid: boolean; binding?: string; error?: { code: string }; context?: unknown }>,
): Promise<void> {
  const result = await resultPromise;
  const status = result.valid ? "VALID" : `DENIED:${result.error?.code ?? "UNKNOWN"}`;
  const binding = result.binding === undefined ? "not checked" : result.binding;

  console.log(`[${persona}] ${lesson}`);
  console.log(`  verification: ${status}`);
  console.log(`  body binding: ${binding}`);
  if (result.context !== undefined) {
    console.log(`  audit context: present`);
    printAuditSummary(result.context);
  }
  console.log();
}

function printAuditSummary(context: unknown): void {
  if (typeof context !== "object" || context === null) return;
  const record = context as {
    session_id?: unknown;
    root_type?: unknown;
    regulatory?: { frameworks?: unknown };
  };
  if (typeof record.root_type === "string") {
    console.log(`  root type    : ${record.root_type}`);
  }
  if (typeof record.session_id === "string") {
    console.log(`  session      : ${record.session_id}`);
  }
  if (Array.isArray(record.regulatory?.frameworks)) {
    const labels = record.regulatory.frameworks.map((framework) =>
      typeof framework === "string" && framework in FRAMEWORK_REGISTRY
        ? FRAMEWORK_REGISTRY[framework as keyof typeof FRAMEWORK_REGISTRY].label
        : String(framework),
    );
    console.log(`  frameworks   : ${labels.join(", ")}`);
  }
}

main().catch((error: unknown) => {
  console.error("[FATAL]", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
