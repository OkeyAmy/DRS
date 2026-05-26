import {
  VerifyClient,
  createInvocationBundle,
  issueRootDelegation,
} from "@okeyamy/drs-sdk";
import type { ChainBundle, VerificationResult } from "@okeyamy/drs-sdk";
import { createExamplePrincipal } from "./keys.js";
import { EXAMPLE_REGULATORY_METADATA } from "./metadata.js";
import {
  SUPPORT_POLICY,
  SUPPORT_POLICY_DISCLOSURE,
  computePolicyDisclosureHash,
} from "./policy.js";

export interface PersonaScenario {
  readonly audit: {
    readonly sessionId: string;
    readonly humanDid: string;
    readonly agentDid: string;
    readonly toolServerDid: string;
  };
  verifyToolCall(
    tool: string,
    args: Record<string, unknown>,
    options?: { readonly bodyOverride?: Record<string, unknown> },
  ): Promise<VerificationResult>;
  buildBundle(tool: string, args: Record<string, unknown>): Promise<ChainBundle>;
}

export async function buildPersonaScenario(
  verifyBaseUrl: string,
): Promise<PersonaScenario> {
  const human = createExamplePrincipal("Amara", 11);
  const agent = createExamplePrincipal("SupportAgent", 22);
  const toolServer = createExamplePrincipal("SupportToolServer", 33);
  const sessionId = "sess:persona-walkthrough-2026-05-25";
  const now = Math.floor(Date.now() / 1000);

  const rootReceipt = await issueRootDelegation({
    signingKey: human.signingKey,
    issuerDid: human.did,
    subjectDid: human.did,
    audienceDid: agent.did,
    cmd: "/mcp/tools/call",
    policy: SUPPORT_POLICY,
    nbf: now - 30,
    exp: now + 3600,
    rootType: "human",
    consent: {
      method: "explicit-ui-click",
      timestamp: new Date(now * 1000).toISOString(),
      session_id: sessionId,
      policy_hash: computePolicyDisclosureHash(SUPPORT_POLICY_DISCLOSURE),
      locale: "en-US",
    },
    regulatory: EXAMPLE_REGULATORY_METADATA,
  });

  const client = new VerifyClient({ baseUrl: verifyBaseUrl, timeoutMs: 10_000 });

  async function buildBundle(
    tool: string,
    args: Record<string, unknown>,
  ): Promise<ChainBundle> {
    return createInvocationBundle({
      rootReceipt,
      signingKey: agent.signingKey,
      issuerDid: agent.did,
      subjectDid: human.did,
      toolServer: toolServer.did,
      tool,
      args,
    });
  }

  async function verifyToolCall(
    tool: string,
    args: Record<string, unknown>,
    options?: { readonly bodyOverride?: Record<string, unknown> },
  ): Promise<VerificationResult> {
    const bundle = await buildBundle(tool, args);
    const signedBody = { tool, ...args };
    return client.verify(bundle, {
      body: options?.bodyOverride ?? signedBody,
    });
  }

  return {
    audit: {
      sessionId,
      humanDid: human.did,
      agentDid: agent.did,
      toolServerDid: toolServer.did,
    },
    verifyToolCall,
    buildBundle,
  };
}
