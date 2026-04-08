import { readFileSync } from "node:fs";
import { parseBundleAuto } from "../../sdk/bundle.js";

export async function audit(args: string[]): Promise<void> {
  const bundlePath = args[0];
  if (!bundlePath) {
    console.error("Usage: drs audit <bundle.json>");
    process.exit(1);
  }

  let content: string;
  try {
    content = readFileSync(bundlePath, "utf8");
  } catch (error: unknown) {
    console.error(`Cannot read ${bundlePath}: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }

  const bundle = parseBundleAuto(content);

  console.log("=== DRS Chain Audit Trail ===");
  console.log(`Bundle version : ${bundle.bundle_version}`);
  console.log(`Receipt count  : ${bundle.receipts.length}`);
  console.log("");

  for (let i = 0; i < bundle.receipts.length; i++) {
    const jwt = bundle.receipts[i]!;
    const payloadB64 = jwt.split(".")[1] ?? "";
    let payload: Record<string, unknown> = {};
    try {
      const padded = payloadB64.replace(/-/g, "+").replace(/_/g, "/");
      payload = JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as Record<string, unknown>;
    } catch {
      payload = { error: "failed to decode" };
    }
    console.log(`Receipt[${i}]`);
    console.log(`  iss : ${payload["iss"] as string}`);
    console.log(`  aud : ${payload["aud"] as string}`);
    console.log(`  cmd : ${payload["cmd"] as string}`);
    console.log(`  exp : ${new Date((payload["exp"] as number) * 1000).toISOString()}`);
    if (i < bundle.receipts.length - 1) console.log("");
  }

  console.log("");
  console.log("Invocation");
  const invPayloadB64 = bundle.invocation.split(".")[1] ?? "";
  try {
    const padded = invPayloadB64.replace(/-/g, "+").replace(/_/g, "/");
    const inv = JSON.parse(Buffer.from(padded, "base64").toString("utf8")) as Record<string, unknown>;
    console.log(`  iss         : ${inv["iss"] as string}`);
    console.log(`  cmd         : ${inv["cmd"] as string}`);
    console.log(`  tool_server : ${inv["tool_server"] as string}`);
  } catch {
    console.log("  (failed to decode invocation payload)");
  }
}
