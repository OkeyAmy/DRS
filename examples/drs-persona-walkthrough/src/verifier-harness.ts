import { spawn } from "node:child_process";
import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

export interface VerifierHarness {
  start(): Promise<void>;
  stop(): Promise<void>;
  baseUrl(): string;
}

const DEFAULT_PORT = 18_080;

export function createVerifierHarness(): VerifierHarness {
  const externalUrl = process.env.DRS_VERIFY_URL;
  if (externalUrl !== undefined && externalUrl.length > 0) {
    return new ExternalVerifierHarness(externalUrl);
  }
  return new ManagedVerifierHarness(randomVerifierPort());
}

class ExternalVerifierHarness implements VerifierHarness {
  constructor(private readonly url: string) {}

  async start(): Promise<void> {
    await waitForReady(this.url);
  }

  async stop(): Promise<void> {}

  baseUrl(): string {
    return this.url;
  }
}

class ManagedVerifierHarness implements VerifierHarness {
  private process: ChildProcessWithoutNullStreams | undefined;
  private stopping = false;

  constructor(private readonly port: number) {}

  async start(): Promise<void> {
    if (this.process !== undefined) return;
    this.stopping = false;

    const verifierDir = resolve(process.cwd(), "../../drs-verify");
    this.process = spawn("go", ["run", "./cmd/server"], {
      cwd: verifierDir,
      detached: true,
      env: {
        ...process.env,
        LISTEN_ADDR: `127.0.0.1:${this.port}`,
        LOG_LEVEL: "error",
        LOG_FORMAT: "text",
        METRICS_ADDR: "",
        RATE_LIMIT_PER_IP: "10000",
        RATE_LIMIT_GLOBAL: "10000",
        NONCE_STORE_BACKEND: "memory",
      },
    });

    this.process.once("exit", (code, signal) => {
      if (this.stopping) return;
      if (code !== null && code !== 0) {
        console.error(`[drs-verify] exited with code ${code}`);
      }
      if (signal !== null) {
        console.error(`[drs-verify] exited with signal ${signal}`);
      }
    });

    try {
      await waitForReady(this.baseUrl());
    } catch (error: unknown) {
      await this.stop();
      throw error;
    }
  }

  async stop(): Promise<void> {
    if (this.process === undefined) return;

    const child = this.process;
    this.process = undefined;
    this.stopping = true;
    terminateProcessGroup(child, "SIGTERM");

    await new Promise<void>((resolveStop) => {
      child.once("exit", () => resolveStop());
      setTimeout(() => {
        terminateProcessGroup(child, "SIGKILL");
        resolveStop();
      }, 5_000).unref();
    });
  }

  baseUrl(): string {
    return `http://127.0.0.1:${this.port}`;
  }
}

function randomVerifierPort(): number {
  return DEFAULT_PORT + Math.floor(Math.random() * 1_000);
}

function terminateProcessGroup(
  child: ChildProcessWithoutNullStreams,
  signal: NodeJS.Signals,
): void {
  if (child.pid === undefined) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error: unknown) {
    if (isMissingProcessError(error)) {
      return;
    }
    throw error;
  }
}

function isMissingProcessError(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ESRCH"
  );
}

async function waitForReady(baseUrl: string): Promise<void> {
  const deadline = Date.now() + 45_000;
  let lastError = "not attempted";

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/readyz`);
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error: unknown) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await delay(500);
  }

  throw new Error(`drs-verify did not become ready at ${baseUrl}: ${lastError}`);
}
