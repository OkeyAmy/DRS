import { describe, expect, it } from "vitest";
import type { VerificationResult } from "@okeyamy/drs-sdk";
import { SUPPORT_POLICY_DISCLOSURE, computePolicyDisclosureHash } from "./policy.js";
import {
  EXAMPLE_REGULATORY_METADATA,
  validateVerificationMetadata,
} from "./metadata.js";

describe("metadata validation", () => {
  it("accepts canonical framework ids, consent evidence, and policy disclosure hash", () => {
    const report = validateVerificationMetadata(validResult());

    expect(report.valid).toBe(true);
    expect(report.issues).toEqual([]);
    expect(report.frameworks.map((framework) => framework.id)).toEqual([
      "eu-ai-act-art12",
      "eu-ai-act-art13",
      "soc2-security",
    ]);
    expect(report.externalTruthWarning).toContain("not EU AI Act compliance");
  });

  it("rejects display labels that look like compliance claims instead of canonical ids", () => {
    const result = validResult({
      regulatory: {
        frameworks: ["EU AI Act", "SOC 2"],
        risk_level: "limited",
        retention_days: 365,
      },
    });

    const report = validateVerificationMetadata(result);

    expect(report.valid).toBe(false);
    expect(report.issues).toEqual([
      "unsupported regulatory framework id: EU AI Act",
      "unsupported regulatory framework id: SOC 2",
    ]);
  });

  it("rejects policy_hash values that do not match the disclosed consent text", () => {
    const result = validResult({
      consent_record: {
        method: "explicit-ui-click",
        timestamp: "2026-05-25T00:00:00.000Z",
        session_id: "sess:persona-walkthrough-2026-05-25",
        policy_hash: "sha256:" + "0".repeat(64),
        locale: "en-US",
      },
    });

    const report = validateVerificationMetadata(result);

    expect(report.valid).toBe(false);
    expect(report.issues[0]).toContain("policy_hash mismatch");
  });

  it("rejects malformed session ids, unsupported consent methods, risk levels, and retention values", () => {
    const result = validResult({
      consent_record: {
        method: "explicit-click",
        timestamp: "not-a-date",
        session_id: "session_without_prefix",
        policy_hash: computePolicyDisclosureHash(SUPPORT_POLICY_DISCLOSURE),
        locale: "en-US",
      },
      regulatory: {
        frameworks: ["soc2-security"],
        risk_level: "medium",
        retention_days: -1,
      },
    });

    const report = validateVerificationMetadata(result);

    expect(report.valid).toBe(false);
    expect(report.issues).toEqual([
      "unsupported consent method: explicit-click",
      "session_id must start with sess:, got session_without_prefix",
      "timestamp must be ISO-8601 parseable, got not-a-date",
      "unsupported risk_level: medium",
      "retention_days must be a non-negative integer, got -1",
    ]);
  });
});

function validResult(
  overrides: Partial<NonNullable<VerificationResult["context"]>> = {},
): VerificationResult {
  return {
    valid: true,
    context: {
      root_principal: "did:key:zHuman",
      root_type: "human",
      consent_record: {
        method: "explicit-ui-click",
        timestamp: "2026-05-25T00:00:00.000Z",
        session_id: "sess:persona-walkthrough-2026-05-25",
        policy_hash: computePolicyDisclosureHash(SUPPORT_POLICY_DISCLOSURE),
        locale: "en-US",
      },
      regulatory: EXAMPLE_REGULATORY_METADATA,
      leaf_policy: {},
      chain_depth: 1,
      session_id: "sess:persona-walkthrough-2026-05-25",
      ...overrides,
    },
  };
}
