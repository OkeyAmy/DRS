import {
  buildBundle,
  computeChainHash,
  issueInvocation,
  serialiseBundle,
} from "@okeyamy/drs-sdk";

/** The DRS metadata key that carries a bundle inside a JSON-RPC message. */
export const BUNDLE_META_KEY = "xyz.okeyamy.drs/bundle";
export const BUNDLE_HEADER = "X-DRS-Bundle";

/** One call to authorise: the exact args the gate will bind against. */
export interface SignedCall {
  cmd: string;
  args: Record<string, unknown>;
}

/** Returns a base64url bundle authorising exactly this call (fresh jti each time). */
export type Signer = (call: SignedCall) => Promise<string>;

export interface ChainSignerConfig {
  /** Delegation receipts, root first. The leaf's audience is this agent. */
  receipts: string[];
  /** This agent's Ed25519 private key (raw 32 bytes). */
  signingKey: Uint8Array;
  /** This agent's DID (the leaf receipt's audience). */
  issuerDid: string;
  /** The root principal's DID. */
  subjectDid: string;
  /** The tool server's identity (drs-verify SERVER_IDENTITY). */
  toolServer: string;
}

/** A Signer backed by an existing delegation chain, using @okeyamy/drs-sdk. */
export function createChainSigner(config: ChainSignerConfig): Signer {
  const drChain = config.receipts.map(computeChainHash);
  return async ({ cmd, args }) => {
    const invocation = await issueInvocation({
      signingKey: config.signingKey,
      issuerDid: config.issuerDid,
      subjectDid: config.subjectDid,
      cmd,
      args,
      drChain,
      toolServer: config.toolServer,
    });
    return serialiseBundle(buildBundle(config.receipts, invocation));
  };
}

interface RpcMessage {
  jsonrpc?: string;
  method?: string;
  params?: Record<string, unknown>;
}

/**
 * The call a gated JSON-RPC message represents, or null when the message
 * carries no tool action. Mirrors drs-verify pkg/gate: MCP gates tools/call
 * with args = arguments + {tool: name}; A2A gates every method with
 * args = params + {tool: method}.
 */
export function callFor(
  protocol: "mcp" | "a2a",
  message: RpcMessage,
): SignedCall | null {
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string")
    return null;
  const params = message.params ?? {};
  if (protocol === "mcp") {
    if (message.method !== "tools/call") return null;
    const args =
      (params.arguments as Record<string, unknown> | undefined) ?? {};
    return { cmd: "/mcp/tools/call", args: { ...args, tool: params.name } };
  }
  return {
    cmd: `/a2a/${message.method}`,
    args: { ...params, tool: message.method },
  };
}
