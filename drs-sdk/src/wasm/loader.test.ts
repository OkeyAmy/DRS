import { describe, it, expect, vi, beforeEach } from "vitest";
import { isWasmReady, getWasmModule, _resetWasmForTesting } from "./loader.js";

beforeEach(() => {
  _resetWasmForTesting();
});

describe("loader", () => {
  it("isWasmReady returns false before init", () => {
    expect(isWasmReady()).toBe(false);
  });

  it("getWasmModule throws before init", () => {
    expect(() => getWasmModule()).toThrow("not initialised");
  });

  it("initWasm throws when @drs/wasm is not installed", async () => {
    // @drs/wasm is not installed in this repo — the import will fail
    const { initWasm } = await import("./loader.js");
    await expect(initWasm()).rejects.toThrow("Failed to load @drs/wasm");
    // After failure, isWasmReady must still be false
    expect(isWasmReady()).toBe(false);
  });
});
