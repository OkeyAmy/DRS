#!/usr/bin/env node
/**
 * drs CLI entrypoint.
 * Routes subcommands to their handlers.
 *
 * Usage:
 *   drs verify   <bundle.json>
 *   drs policy   <receipt.json>
 *   drs translate <policy.json>
 *   drs audit    <bundle.json>
 *   drs keygen
 */

import { verify } from "./commands/verify.js";
import { policy } from "./commands/policy.js";
import { translate } from "./commands/translate.js";
import { audit } from "./commands/audit.js";
import { keygen } from "./commands/keygen.js";
import { formatter } from "./formatter.js";

const [, , command, ...args] = process.argv;

async function main(): Promise<void> {
  switch (command) {
    case "verify":
      await verify(args);
      break;
    case "policy":
      await policy(args);
      break;
    case "translate":
      await translate(args);
      break;
    case "audit":
      await audit(args);
      break;
    case "keygen":
      await keygen(args);
      break;
    default:
      console.error(formatter.usage());
      process.exit(1);
  }
}

main().catch((err: unknown) => {
  console.error("Error:", err instanceof Error ? err.message : String(err));
  process.exit(1);
});
