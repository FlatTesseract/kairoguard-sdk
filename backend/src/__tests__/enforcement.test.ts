/**
 * Enforcement Configuration Tests
 */

import { describe, it, expect } from "bun:test";
import {
  EnforcementLevel,
  MAINNET_DEFAULTS,
  TESTNET_DEFAULTS,
  getNetworkDefaults,
  buildEnforcementConfig,
  isCustodyRequired,
  isCustodyEnabled,
  shouldFailOnPolicyError,
  shouldFailOnBindingError,
  getEnforcementSummary,
} from "../config/enforcement.js";
import { CustodyMode } from "../custody-mode.js";

describe("Enforcement Configuration", () => {
  describe("Network Defaults", () => {
    it("should have strict mainnet defaults", () => {
      expect(MAINNET_DEFAULTS.network).toBe("mainnet");
      expect(MAINNET_DEFAULTS.custodyMode).toBe(CustodyMode.REQUIRED);
      expect(MAINNET_DEFAULTS.policyValidation).toBe(EnforcementLevel.STRICT);
      expect(MAINNET_DEFAULTS.policyBindingValidation).toBe(EnforcementLevel.STRICT);
      expect(MAINNET_DEFAULTS.isDevelopment).toBe(false);
    });

    it("should have strict testnet defaults", () => {
      expect(TESTNET_DEFAULTS.network).toBe("testnet");
      expect(TESTNET_DEFAULTS.custodyMode).toBe(CustodyMode.REQUIRED);
      expect(TESTNET_DEFAULTS.policyValidation).toBe(EnforcementLevel.STRICT);
      expect(TESTNET_DEFAULTS.policyBindingValidation).toBe(EnforcementLevel.WARN);
      expect(TESTNET_DEFAULTS.isDevelopment).toBe(true);
    });

    it("should return correct defaults for network", () => {
      expect(getNetworkDefaults("mainnet")).toEqual(MAINNET_DEFAULTS);
      expect(getNetworkDefaults("testnet")).toEqual(TESTNET_DEFAULTS);
    });
  });

  describe("buildEnforcementConfig", () => {
    it("should use network defaults when no overrides", () => {
      const config = buildEnforcementConfig({ network: "mainnet" });
      expect(config.custodyMode).toBe(CustodyMode.REQUIRED);
    });

    it("should apply custody mode override", () => {
      const config = buildEnforcementConfig({
        network: "mainnet",
        custodyModeOverride: CustodyMode.DISABLED,
      });
      expect(config.custodyMode).toBe(CustodyMode.DISABLED);
      // Other settings still from mainnet defaults
      expect(config.policyValidation).toBe(EnforcementLevel.STRICT);
    });

    it("should apply policy validation override", () => {
      const config = buildEnforcementConfig({
        network: "testnet",
        policyValidationOverride: EnforcementLevel.SKIP,
      });
      expect(config.policyValidation).toBe(EnforcementLevel.SKIP);
    });
  });

  describe("Helper Functions", () => {
    describe("isCustodyRequired", () => {
      it("should return true for REQUIRED mode", () => {
        expect(isCustodyRequired(MAINNET_DEFAULTS)).toBe(true);
      });

      it("should return true for testnet REQUIRED mode", () => {
        expect(isCustodyRequired(TESTNET_DEFAULTS)).toBe(true);
      });

      it("should return false for DISABLED mode", () => {
        const config = buildEnforcementConfig({
          network: "testnet",
          custodyModeOverride: CustodyMode.DISABLED,
        });
        expect(isCustodyRequired(config)).toBe(false);
      });
    });

    describe("isCustodyEnabled", () => {
      it("should return true for REQUIRED mode", () => {
        expect(isCustodyEnabled(MAINNET_DEFAULTS)).toBe(true);
      });

      it("should return true for BEST_EFFORT mode", () => {
        expect(isCustodyEnabled(TESTNET_DEFAULTS)).toBe(true);
      });

      it("should return false for DISABLED mode", () => {
        const config = buildEnforcementConfig({
          network: "testnet",
          custodyModeOverride: CustodyMode.DISABLED,
        });
        expect(isCustodyEnabled(config)).toBe(false);
      });
    });

    describe("shouldFailOnPolicyError", () => {
      it("should return true for STRICT validation", () => {
        expect(shouldFailOnPolicyError(MAINNET_DEFAULTS)).toBe(true);
      });

      it("should return false for WARN validation", () => {
        const config = buildEnforcementConfig({
          network: "testnet",
          policyValidationOverride: EnforcementLevel.WARN,
        });
        expect(shouldFailOnPolicyError(config)).toBe(false);
      });
    });

    describe("shouldFailOnBindingError", () => {
      it("should return true for mainnet", () => {
        expect(shouldFailOnBindingError(MAINNET_DEFAULTS)).toBe(true);
      });

      it("should return false for testnet (WARN default)", () => {
        expect(shouldFailOnBindingError(TESTNET_DEFAULTS)).toBe(false);
      });
    });
  });

  describe("getEnforcementSummary", () => {
    it("should produce readable summary", () => {
      const summary = getEnforcementSummary(MAINNET_DEFAULTS);
      expect(summary).toContain("mainnet");
      expect(summary).toContain("REQUIRED");
      expect(summary).toContain("STRICT");
    });
  });
});
