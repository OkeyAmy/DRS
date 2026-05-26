import { sha256 } from "@noble/hashes/sha2.js";
import { jcsSerialise } from "@okeyamy/drs-sdk";
import type { Policy } from "@okeyamy/drs-sdk";

export const SUPPORT_POLICY: Policy = {
  allowed_tools: ["lookup_customer", "draft_reply"],
  allowed_data_classes: ["support-ticket", "customer-profile"],
  max_cost_usd: 0.25,
  pii_access: true,
  write_access: false,
};

export const SUPPORT_POLICY_DISCLOSURE =
  "Amara authorises SupportAgent to call lookup_customer and draft_reply for support-ticket and customer-profile data only. Refunds are not authorised.";

export function computePolicyHash(policy: Policy): string {
  const digest = sha256(new TextEncoder().encode(jcsSerialise(policy)));
  return formatSha256(digest);
}

export function computePolicyDisclosureHash(disclosure: string): string {
  const digest = sha256(new TextEncoder().encode(disclosure));
  return formatSha256(digest);
}

function formatSha256(digest: Uint8Array): string {
  const hex = Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `sha256:${hex}`;
}
