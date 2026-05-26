import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildPersonaScenario } from "./personas.js";
import { createVerifierHarness } from "./verifier-harness.js";

const harness = createVerifierHarness();

describe("DRS persona walkthrough", () => {
  beforeAll(async () => {
    await harness.start();
  }, 60_000);

  afterAll(async () => {
    await harness.stop();
  });

  it("lets a product builder send an allowed support lookup through the real verifier", async () => {
    const scenario = await buildPersonaScenario(harness.baseUrl());
    const result = await scenario.verifyToolCall("lookup_customer", {
      customer_id: "cus_001",
    });

    expect(result.valid).toBe(true);
    expect(result.binding).toBe("match");
    expect(result.context?.root_type).toBe("human");
    expect(result.context?.leaf_policy.allowed_tools).toEqual([
      "lookup_customer",
      "draft_reply",
    ]);
  });

  it("gives an auditor consent and regulatory context from a live verification", async () => {
    const scenario = await buildPersonaScenario(harness.baseUrl());
    const result = await scenario.verifyToolCall("draft_reply", {
      customer_id: "cus_001",
      tone: "concise",
    });

    expect(result.valid).toBe(true);
    expect(result.context?.consent_record?.session_id).toBe(
      scenario.audit.sessionId,
    );
    expect(result.context?.regulatory?.frameworks).toEqual([
      "eu-ai-act-art12",
      "eu-ai-act-art13",
      "soc2-security",
    ]);
    expect(result.context?.session_id).toBe(scenario.audit.sessionId);
  });

  it("shows a security engineer that forbidden tools fail closed", async () => {
    const scenario = await buildPersonaScenario(harness.baseUrl());
    const result = await scenario.verifyToolCall("refund_customer", {
      customer_id: "cus_001",
      amount_usd: 25,
    });

    expect(result.valid).toBe(false);
    expect(result.error?.code).toBe("POLICY_VIOLATION");
  });

  it("shows a tool owner how body binding blocks signed-intent tampering", async () => {
    const scenario = await buildPersonaScenario(harness.baseUrl());
    const result = await scenario.verifyToolCall(
      "lookup_customer",
      { customer_id: "cus_001" },
      { bodyOverride: { tool: "lookup_customer", customer_id: "cus_999" } },
    );

    expect(result.valid).toBe(true);
    expect(result.binding).toBe("mismatch");
  });
});
