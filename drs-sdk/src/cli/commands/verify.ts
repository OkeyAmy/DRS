import { readFileSync } from "node:fs";
import { VerifyClient } from "../../verify/client.js";
import { parseBundleAuto } from "../../sdk/bundle.js";
import { formatter } from "../formatter.js";
import { DrsError } from "../../sdk/types.js";

export async function verify(args: string[]): Promise<void> {
  const includeTimestamps = args.includes("--include-timestamps");
  const positional = args.filter((a) => !a.startsWith("--"));

  const bundlePath = positional[0];
  if (!bundlePath) {
    console.error("Usage: drs verify [--include-timestamps] <bundle.json>");
    process.exit(1);
  }

  let content: string;
  try {
    content = readFileSync(bundlePath, "utf8");
  } catch (error: unknown) {
    console.error(
      `Cannot read ${bundlePath}: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exit(1);
  }

  const bundle = parseBundleAuto(content);

  const baseUrl = process.env["DRS_VERIFY_URL"] ?? "http://localhost:8080";
  const client = new VerifyClient({ baseUrl });

  try {
    const result = await client.verify(bundle, { includeTimestamps });
    console.log(formatter.verificationResult(result));
    process.exit(result.valid ? 0 : 1);
  } catch (error: unknown) {
    if (error instanceof DrsError) {
      console.error(`[${error.code}] ${error.message}`);
    } else {
      console.error(error instanceof Error ? error.message : String(error));
    }
    process.exit(1);
  }
}
