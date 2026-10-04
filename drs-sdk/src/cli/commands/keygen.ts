import { didKeyFromPublicKey } from "../../sdk/did.js";
import { derivePublicKey } from "../../sdk/issue.js";
import { mkdir, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

const defaultKeyPath = join(homedir(), ".drs", "signing.key");

export async function keygen(args: string[]): Promise<void> {
  const keyPath = parseKeyPath(args);
  const privKey = new Uint8Array(32);
  globalThis.crypto.getRandomValues(privKey);
  const pubKey = derivePublicKey(privKey);

  const did = didKeyFromPublicKey(pubKey);

  const privHex = Buffer.from(privKey).toString("hex");
  const pubHex = Buffer.from(pubKey).toString("hex");

  await writePrivateKey(keyPath, privHex);
  privKey.fill(0);

  console.log("Ed25519 keypair generated.");
  console.log("");
  console.log(`DID          : ${did}`);
  console.log(`Public key   : ${pubHex}`);
  console.log(`Private key  : written to ${keyPath}`);
  console.log("");
  console.warn("WARNING: Store the private key file securely. Never commit it to version control.");
}

function parseKeyPath(args: string[]): string {
  if (args.length === 0) return defaultKeyPath;

  const [flag, value, ...rest] = args;
  if ((flag === "--out" || flag === "--output") && value && rest.length === 0) {
    return resolve(value);
  }

  throw new Error("Usage: drs keygen [--out <path>]");
}

async function writePrivateKey(path: string, privateKeyHex: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, privateKeyHex + "\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
}
