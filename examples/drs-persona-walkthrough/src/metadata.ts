import type {
  ConsentRecord,
  RegulatoryMetadata,
  VerificationResult,
} from "@okeyamy/drs-sdk";
import { SUPPORT_POLICY_DISCLOSURE, computePolicyDisclosureHash } from "./policy.js";

export type FrameworkId =
  | "eu-ai-act-art12"
  | "eu-ai-act-art13"
  | "soc2-security"
  | "soc2-availability"
  | "soc2-processing-integrity"
  | "soc2-confidentiality"
  | "soc2-privacy";

export interface FrameworkDefinition {
  readonly id: FrameworkId;
  readonly label: string;
  readonly source: string;
  readonly validationBoundary: string;
}

export interface MetadataValidationReport {
  readonly valid: boolean;
  readonly proofClasses: readonly string[];
  readonly issues: readonly string[];
  readonly frameworks: readonly FrameworkDefinition[];
  readonly externalTruthWarning: string;
}

export const FRAMEWORK_REGISTRY: Record<FrameworkId, FrameworkDefinition> = {
  "eu-ai-act-art12": {
    id: "eu-ai-act-art12",
    label: "EU AI Act Article 12 record-keeping",
    source: "https://data.europa.eu/eli/reg/2024/1689/oj",
    validationBoundary:
      "DRS can bind the label as asserted metadata; legal applicability requires a separate EU AI Act assessment.",
  },
  "eu-ai-act-art13": {
    id: "eu-ai-act-art13",
    label: "EU AI Act Article 13 transparency",
    source: "https://data.europa.eu/eli/reg/2024/1689/oj",
    validationBoundary:
      "DRS can bind the label as asserted metadata; transparency compliance requires external product evidence.",
  },
  "soc2-security": {
    id: "soc2-security",
    label: "SOC 2 Security trust service criterion",
    source:
      "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    validationBoundary:
      "DRS can bind the label as asserted metadata; SOC 2 examination evidence requires an independent service-auditor report.",
  },
  "soc2-availability": {
    id: "soc2-availability",
    label: "SOC 2 Availability trust service criterion",
    source:
      "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    validationBoundary:
      "DRS can bind the label as asserted metadata; SOC 2 examination evidence requires an independent service-auditor report.",
  },
  "soc2-processing-integrity": {
    id: "soc2-processing-integrity",
    label: "SOC 2 Processing Integrity trust service criterion",
    source:
      "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    validationBoundary:
      "DRS can bind the label as asserted metadata; SOC 2 examination evidence requires an independent service-auditor report.",
  },
  "soc2-confidentiality": {
    id: "soc2-confidentiality",
    label: "SOC 2 Confidentiality trust service criterion",
    source:
      "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    validationBoundary:
      "DRS can bind the label as asserted metadata; SOC 2 examination evidence requires an independent service-auditor report.",
  },
  "soc2-privacy": {
    id: "soc2-privacy",
    label: "SOC 2 Privacy trust service criterion",
    source:
      "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    validationBoundary:
      "DRS can bind the label as asserted metadata; SOC 2 examination evidence requires an independent service-auditor report.",
  },
};

const VALID_RISK_LEVELS = new Set(["unacceptable", "high", "limited", "minimal"]);
const VALID_CONSENT_METHODS = new Set([
  "explicit-ui-click",
  "explicit-ui-checkbox",
  "api-delegation",
  "operator-policy",
]);

export const EXAMPLE_REGULATORY_METADATA: RegulatoryMetadata = {
  frameworks: ["eu-ai-act-art12", "eu-ai-act-art13", "soc2-security"],
  risk_level: "limited",
  retention_days: 365,
};

export function validateVerificationMetadata(
  result: VerificationResult,
): MetadataValidationReport {
  const issues: string[] = [];
  const frameworks: FrameworkDefinition[] = [];

  if (!result.valid) {
    issues.push("verification result is invalid; metadata cannot be trusted");
  }

  validateRootType(result.context?.root_type, issues);
  validateConsent(result.context?.consent_record, issues);
  validateRegulatory(result.context?.regulatory, issues, frameworks);

  return {
    valid: issues.length === 0,
    proofClasses: [
      "cryptographic-binding: metadata is inside signed DRS receipts verified by drs-verify",
      "schema-validation: fields use assessment-approved ids, formats, and ranges",
      "policy-validation: policy_hash matches the human-readable disclosure used by this example",
      "external-truth: not proven by DRS; framework applicability requires separate audit/legal evidence",
    ],
    issues,
    frameworks,
    externalTruthWarning:
      "Framework ids are asserted metadata. DRS proves integrity of the assertion, not EU AI Act compliance or SOC 2 certification.",
  };
}

function validateRootType(rootType: string | undefined, issues: string[]): void {
  if (rootType !== "human") {
    issues.push(`root_type must be human for this walkthrough, got ${rootType ?? "missing"}`);
  }
}

function validateConsent(
  consent: ConsentRecord | undefined,
  issues: string[],
): void {
  if (consent === undefined) {
    issues.push("human-rooted walkthrough must expose consent_record");
    return;
  }
  if (!VALID_CONSENT_METHODS.has(consent.method)) {
    issues.push(`unsupported consent method: ${consent.method}`);
  }
  if (!consent.session_id.startsWith("sess:")) {
    issues.push(`session_id must start with sess:, got ${consent.session_id}`);
  }
  if (Number.isNaN(Date.parse(consent.timestamp))) {
    issues.push(`timestamp must be ISO-8601 parseable, got ${consent.timestamp}`);
  }
  if (consent.locale !== "en-US") {
    issues.push(`locale must be en-US for this walkthrough, got ${consent.locale}`);
  }
  const expectedHash = computePolicyDisclosureHash(SUPPORT_POLICY_DISCLOSURE);
  if (consent.policy_hash !== expectedHash) {
    issues.push(`policy_hash mismatch: expected ${expectedHash}, got ${consent.policy_hash}`);
  }
}

function validateRegulatory(
  regulatory: RegulatoryMetadata | undefined,
  issues: string[],
  frameworks: FrameworkDefinition[],
): void {
  if (regulatory === undefined) {
    issues.push("regulatory metadata is missing");
    return;
  }
  for (const framework of regulatory.frameworks) {
    if (isFrameworkId(framework)) {
      frameworks.push(FRAMEWORK_REGISTRY[framework]);
    } else {
      issues.push(`unsupported regulatory framework id: ${framework}`);
    }
  }
  if (!VALID_RISK_LEVELS.has(regulatory.risk_level)) {
    issues.push(`unsupported risk_level: ${regulatory.risk_level}`);
  }
  if (!Number.isInteger(regulatory.retention_days) || regulatory.retention_days < 0) {
    issues.push(`retention_days must be a non-negative integer, got ${regulatory.retention_days}`);
  }
}

function isFrameworkId(value: string): value is FrameworkId {
  return Object.hasOwn(FRAMEWORK_REGISTRY, value);
}
