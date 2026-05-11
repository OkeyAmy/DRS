import { readFileSync } from "node:fs";
import { translatePolicy } from "../../sdk/policy.js";
import type { Policy } from "../../sdk/types.js";

export async function policy(args: string[]): Promise<void> {
  const receiptPath = args[0];
  if (!receiptPath) {
    console.error("Usage: drs policy <receipt.json>");
    process.exit(1);
  }

  let json: string;
  try {
    json = readFileSync(receiptPath, "utf8");
  } catch (error: unknown) {
    console.error(
      `Cannot read ${receiptPath}: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exit(1);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    console.error("File is not valid JSON.");
    process.exit(1);
  }

  const pol =
    ((parsed as Record<string, unknown>)["policy"] as Policy | undefined) ?? (parsed as Policy);
  console.log(translatePolicy(pol));
}
