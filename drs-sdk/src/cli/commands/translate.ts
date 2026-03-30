import { readFileSync } from "node:fs";
import { translatePolicy } from "../../sdk/policy.js";
import type { Policy } from "../../sdk/types.js";

export async function translate(args: string[]): Promise<void> {
  const policyPath = args[0];
  if (!policyPath) {
    console.error("Usage: drs translate <policy.json>");
    process.exit(1);
  }

  let json: string;
  try {
    json = readFileSync(policyPath, "utf8");
  } catch (error: unknown) {
    console.error(`Cannot read ${policyPath}: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    console.error("File is not valid JSON.");
    process.exit(1);
  }

  const locale = process.env["DRS_LOCALE"] ?? "en";
  console.log(translatePolicy(parsed as Policy, locale));
}
