import { readFileSync } from "node:fs";
import { VerifyClient } from "../../verify/client.js";
import { parseBundleAuto } from "../../sdk/bundle.js";
import { formatter } from "../formatter.js";
import { DrsError } from "../../sdk/types.js";

const USAGE = "Usage: drs verify [--include-timestamps] [--body <request.json>] <bundle.json>";

export interface VerifyArgs {
  bundlePath: string | undefined;
  bodyPath: string | undefined;
  includeTimestamps: boolean;
}

/** Parses `drs verify` arguments. `--body` takes the next argument as its value. */
export function parseVerifyArgs(args: string[]): VerifyArgs {
  const bodyFlag = args.indexOf("--body");
  const bodyPath = bodyFlag >= 0 ? args[bodyFlag + 1] : undefined;
  const positional = args.filter(
    (a, i) => !a.startsWith("--") && !(bodyFlag >= 0 && i === bodyFlag + 1),
  );
  return {
    bundlePath: positional[0],
    bodyPath,
    includeTimestamps: args.includes("--include-timestamps"),
  };
}

export async function verify(args: string[]): Promise<void> {
  const { bundlePath, bodyPath, includeTimestamps } = parseVerifyArgs(args);
  if (!bundlePath) {
    console.error(USAGE);
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

  // drs-verify requires the executed request body by default
  // (DRS_REQUIRE_BINDING); without --body the result is BINDING_REQUIRED.
  let body: unknown;
  if (bodyPath) {
    try {
      body = JSON.parse(readFileSync(bodyPath, "utf8"));
    } catch (error: unknown) {
      console.error(
        `Cannot read --body ${bodyPath}: ${error instanceof Error ? error.message : String(error)}`,
      );
      process.exit(1);
    }
  }

  const baseUrl = process.env["DRS_VERIFY_URL"] ?? "http://localhost:8080";
  const client = new VerifyClient({ baseUrl });

  try {
    const result = await client.verify(
      bundle,
      bodyPath ? { includeTimestamps, body } : { includeTimestamps },
    );
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
