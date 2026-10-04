import {
  BUNDLE_HEADER,
  BUNDLE_META_KEY,
  callFor,
  type Signer,
} from "./signer.js";

export interface DrsFetchConfig {
  signer: Signer;
  protocol: "mcp" | "a2a";
  /**
   * "header" (default) sends X-DRS-Bundle; "meta" embeds the bundle in MCP
   * params._meta. A2A accepts only the header.
   */
  carrier?: "header" | "meta";
  fetchFn?: typeof fetch;
}

/**
 * A fetch implementation that signs each gated JSON-RPC request with the
 * arguments it actually carries. Pass it as the `fetch` option of the MCP
 * StreamableHTTPClientTransport (SDK v1 and v2) or as `fetchImpl` of the
 * A2A JsonRpcTransportFactory.
 */
export function createDrsFetch(config: DrsFetchConfig): typeof fetch {
  const inner = config.fetchFn ?? globalThis.fetch;
  const carrier = config.carrier ?? "header";
  if (config.protocol === "a2a" && carrier === "meta") {
    throw new Error(
      'A2A bundles travel only in the X-DRS-Bundle header (carrier "header")',
    );
  }

  return async (input, init) => {
    if (typeof init?.body !== "string") return inner(input, init);
    let message: Record<string, unknown>;
    try {
      message = JSON.parse(init.body) as Record<string, unknown>;
    } catch {
      return inner(input, init);
    }
    const call = callFor(config.protocol, message);
    if (!call) return inner(input, init);

    const bundle = await config.signer(call);
    if (carrier === "header") {
      const headers = new Headers(init.headers);
      headers.set(BUNDLE_HEADER, bundle);
      return inner(input, { ...init, headers });
    }
    return inner(input, {
      ...init,
      body: JSON.stringify(embed(message, bundle)),
    });
  };
}

/** Places the bundle in MCP params._meta (MCP is the only metadata carrier). */
export function embed(
  message: Record<string, unknown>,
  bundle: string,
): Record<string, unknown> {
  const params = {
    ...((message.params as Record<string, unknown> | undefined) ?? {}),
  };
  params._meta = {
    ...((params._meta as Record<string, unknown> | undefined) ?? {}),
    [BUNDLE_META_KEY]: bundle,
  };
  return { ...message, params };
}
