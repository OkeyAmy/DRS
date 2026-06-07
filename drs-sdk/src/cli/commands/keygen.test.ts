import { mkdtemp, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keygen } from "./keygen.js";

describe("keygen", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("writes the private key to a 0600 file instead of stdout", async () => {
    const dir = await mkdtemp(join(tmpdir(), "drs-keygen-"));
    const keyPath = join(dir, "signing.key");
    const logs: string[] = [];

    vi.spyOn(console, "log").mockImplementation((message?: unknown) => {
      logs.push(String(message ?? ""));
    });
    vi.spyOn(console, "warn").mockImplementation(() => undefined);

    await keygen(["--out", keyPath]);

    const privateKeyHex = (await readFile(keyPath, "utf8")).trim();
    expect(privateKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(logs.join("\n")).toContain(`Private key  : written to ${keyPath}`);
    expect(logs.join("\n")).not.toContain(privateKeyHex);

    const mode = (await stat(keyPath)).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("refuses to overwrite an existing private key file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "drs-keygen-"));
    const keyPath = join(dir, "signing.key");

    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);

    await keygen(["--out", keyPath]);
    await expect(keygen(["--out", keyPath])).rejects.toThrow();
  });
});
