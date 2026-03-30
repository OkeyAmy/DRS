/**
 * Policy evaluation and attenuation checks.
 * TypeScript port of drs-core/src/capability/policy.rs and
 * drs-verify/pkg/policy/evaluate.go.
 *
 * Used by the SDK at issuance time to prevent invalid sub-delegations.
 * Field names must match §6.3 of the technical audit exactly.
 */

import type { Policy } from "./types.js";

/**
 * Checks that `child` policy does not escalate beyond `parent` policy.
 * Returns null on success, an error string on violation.
 * Fail-closed: any violation denies the capability.
 */
export function checkPolicyAttenuation(parent: Policy, child: Policy): string | null {
  // max_cost_usd: child cannot raise the cost limit
  if (parent.max_cost_usd !== undefined && child.max_cost_usd !== undefined) {
    if (child.max_cost_usd > parent.max_cost_usd) {
      return `Child loosens max_cost_usd: parent $${parent.max_cost_usd.toFixed(2)}, child $${child.max_cost_usd.toFixed(2)}.`;
    }
  }

  // pii_access: child cannot grant pii if parent denies it
  if (parent.pii_access === false && child.pii_access === true) {
    return "Child relaxes pii_access restriction: parent false, child true.";
  }

  // write_access: child cannot grant write if parent denies it
  if (parent.write_access === false && child.write_access === true) {
    return "Child relaxes write_access restriction: parent false, child true.";
  }

  // max_calls: child cannot raise the call limit
  if (parent.max_calls !== undefined && child.max_calls !== undefined) {
    if (child.max_calls > parent.max_calls) {
      return `Child loosens max_calls: parent ${parent.max_calls}, child ${child.max_calls}.`;
    }
  }

  // allowed_tools: child's list must be a subset of parent's list
  if (parent.allowed_tools !== undefined && child.allowed_tools !== undefined) {
    if (!parent.allowed_tools.includes("*")) {
      for (const tool of child.allowed_tools) {
        if (tool === "*") {
          return "Child adds wildcard '*' to allowed_tools but parent does not allow all tools.";
        }
        if (!parent.allowed_tools.includes(tool)) {
          return `Child adds "${tool}" to allowed_tools not permitted by parent.`;
        }
      }
    }
  }

  // allowed_resources: child's list must be a subset of parent's list
  if (parent.allowed_resources !== undefined && child.allowed_resources !== undefined) {
    if (!parent.allowed_resources.includes("*")) {
      for (const res of child.allowed_resources) {
        if (res === "*") {
          return "Child adds wildcard '*' to allowed_resources but parent does not allow all.";
        }
        if (!parent.allowed_resources.includes(res)) {
          return `Child adds "${res}" to allowed_resources not permitted by parent.`;
        }
      }
    }
  }

  // allowed_data_classes: child's list must be a subset of parent's list
  if (parent.allowed_data_classes !== undefined && child.allowed_data_classes !== undefined) {
    if (!parent.allowed_data_classes.includes("*")) {
      for (const cls of child.allowed_data_classes) {
        if (cls === "*" || !parent.allowed_data_classes.includes(cls)) {
          return `Child adds "${cls}" to allowed_data_classes not permitted by parent.`;
        }
      }
    }
  }

  return null;
}

/**
 * Translates a policy object into human-readable plain English.
 * Used by the `drs policy` CLI command and consent UI flows.
 */
export function translatePolicy(policy: Policy, locale = "en"): string {
  if (locale !== "en") {
    // Locale support beyond English is not implemented in this version.
    // Return English fallback rather than throwing — consumers can detect
    // that the locale is unsupported via the locale parameter mismatch.
  }

  const lines: string[] = [];

  if (policy.max_cost_usd !== undefined) {
    lines.push(`Maximum cost: $${policy.max_cost_usd.toFixed(2)} USD per invocation.`);
  }
  if (policy.max_calls !== undefined) {
    lines.push(`Maximum calls: ${policy.max_calls}.`);
  }
  if (policy.pii_access === false) {
    lines.push("Personal data (PII) access: not permitted.");
  } else if (policy.pii_access === true) {
    lines.push("Personal data (PII) access: permitted.");
  }
  if (policy.write_access === false) {
    lines.push("Write operations: not permitted.");
  } else if (policy.write_access === true) {
    lines.push("Write operations: permitted.");
  }
  if (policy.allowed_tools !== undefined) {
    if (policy.allowed_tools.includes("*")) {
      lines.push("Permitted tools: all.");
    } else {
      lines.push(`Permitted tools: ${policy.allowed_tools.join(", ")}.`);
    }
  }
  if (policy.allowed_resources !== undefined) {
    if (policy.allowed_resources.includes("*")) {
      lines.push("Permitted resources: all.");
    } else {
      lines.push(`Permitted resources: ${policy.allowed_resources.join(", ")}.`);
    }
  }
  if (policy.allowed_data_classes !== undefined) {
    lines.push(`Permitted data classes: ${policy.allowed_data_classes.join(", ")}.`);
  }
  if (lines.length === 0) {
    return "No restrictions specified.";
  }

  return lines.join("\n");
}
