import { describe, it, expect } from "vitest";
import { parseOperatorConfig, validateOperatorConfig } from "./operator.js";
import type { OperatorConfig } from "./operator.js";
import { DrsError } from "./types.js";

function validConfig(): OperatorConfig {
  return {
    drs_root_type: "automated-system",
    operator_did: "did:key:z6Mk1234",
    operator_key_management: "file",
    operator_key_path: "/secrets/operator.key",
    standing_policy: { max_cost_usd: 10.0, write_access: false },
    renewal_rules: { auto_renew: true, session_ttl_hours: 8, max_renewal_count: 3 },
    escalation: { target_type: "human", supervisor_did: "did:key:zSuper", fallback: "deny" },
    storage_tier: 1,
  };
}

describe("validateOperatorConfig", () => {
  it("accepts a valid automated-system config", () => {
    expect(() => validateOperatorConfig(validConfig())).not.toThrow();
  });

  it("accepts organisation root type", () => {
    const cfg = { ...validConfig(), drs_root_type: "organisation" as const };
    expect(() => validateOperatorConfig(cfg)).not.toThrow();
  });

  it("rejects human root type", () => {
    const cfg = { ...validConfig(), drs_root_type: "human" as never };
    let err: DrsError | undefined;
    try {
      validateOperatorConfig(cfg);
    } catch (e) {
      err = e as DrsError;
    }
    expect(err?.code).toBe("INVALID_OPERATOR_CONFIG");
  });

  it("rejects empty operator_did", () => {
    const cfg = { ...validConfig(), operator_did: "" };
    let err: DrsError | undefined;
    try {
      validateOperatorConfig(cfg);
    } catch (e) {
      err = e as DrsError;
    }
    expect(err?.code).toBe("INVALID_OPERATOR_CONFIG");
  });

  it("rejects file key management without key path", () => {
    const cfg = { ...validConfig(), operator_key_path: undefined };
    let err: DrsError | undefined;
    try {
      validateOperatorConfig(cfg);
    } catch (e) {
      err = e as DrsError;
    }
    expect(err?.code).toBe("INVALID_OPERATOR_CONFIG");
  });

  it("rejects invalid storage tier", () => {
    const cfg = { ...validConfig(), storage_tier: 6 as never };
    let err: DrsError | undefined;
    try {
      validateOperatorConfig(cfg);
    } catch (e) {
      err = e as DrsError;
    }
    expect(err?.code).toBe("INVALID_OPERATOR_CONFIG");
  });
});

describe("parseOperatorConfig", () => {
  it("accepts a valid config object", () => {
    const cfg = parseOperatorConfig(validConfig());
    expect(cfg.drs_root_type).toBe("automated-system");
    expect(cfg.renewal_rules.session_ttl_hours).toBe(8);
  });

  it("rejects null", () => {
    let err: DrsError | undefined;
    try {
      parseOperatorConfig(null);
    } catch (e) {
      err = e as DrsError;
    }
    expect(err?.code).toBe("INVALID_OPERATOR_CONFIG");
  });
});
