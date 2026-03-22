/**
 * Custody Service Tests
 * 
 * Validates custody append logic and mode enforcement.
 */

import { describe, it, expect, mock } from "bun:test";
import {
  executeCustodyAppend,
  isCustodyCompliant,
  toCustodyResult,
  type CustodyAppendDelegate,
  type CustodyAppendParams,
} from "../services/custody-service.js";
import { CustodyMode } from "../custody-mode.js";

// Mock delegate that succeeds
const successDelegate: CustodyAppendDelegate = {
  appendCustodyEventWithReceipt: async () => ({
    digest: "0xtest-digest",
    custodyEventObjectId: "0xtest-event-id",
  }),
  resolveCustodyChainId: async () => "0xtest-chain-id",
};

// Mock delegate that fails
const failingDelegate: CustodyAppendDelegate = {
  appendCustodyEventWithReceipt: async () => {
    throw new Error("Custody append failed on-chain");
  },
  resolveCustodyChainId: async () => "0xtest-chain-id",
};

// Mock delegate with no custody chain
const noCustodyChainDelegate: CustodyAppendDelegate = {
  appendCustodyEventWithReceipt: async () => ({
    digest: "0xtest-digest",
  }),
  resolveCustodyChainId: async () => null,
};

const baseParams: CustodyAppendParams = {
  receiptObjectId: "0xtest-receipt",
  policyObjectId: "0xtest-policy",
  intentHashHex: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  toEvm: "0x1234567890123456789012345678901234567890",
  mintDigest: "0xtest-mint-digest",
  custodyChainObjectId: "0xtest-chain-id",
  custodyPackageId: "0xtest-package",
};

describe("Custody Service", () => {
  describe("executeCustodyAppend", () => {
    describe("DISABLED mode", () => {
      it("should skip custody and return compliant", async () => {
        const result = await executeCustodyAppend(
          { ...baseParams, custodyMode: CustodyMode.DISABLED },
          successDelegate
        );

        expect(result.status).toBe("disabled");
        expect(result.compliant).toBe(true);
        expect(result.mode).toBe(CustodyMode.DISABLED);
      });
    });

    describe("BEST_EFFORT mode", () => {
      it("should append custody and return compliant on success", async () => {
        const result = await executeCustodyAppend(
          { ...baseParams, custodyMode: CustodyMode.BEST_EFFORT },
          successDelegate
        );

        expect(result.status).toBe("appended");
        expect(result.compliant).toBe(true);
        expect(result.mode).toBe(CustodyMode.BEST_EFFORT);
        expect(result.custodyEventObjectId).toBe("0xtest-event-id");
      });

      it("should return failed but not throw on error", async () => {
        const result = await executeCustodyAppend(
          { ...baseParams, custodyMode: CustodyMode.BEST_EFFORT },
          failingDelegate
        );

        expect(result.status).toBe("failed");
        expect(result.compliant).toBe(false);
        expect(result.mode).toBe(CustodyMode.BEST_EFFORT);
        expect(result.error).toBeDefined();
      });

      it("should return skipped when no custody chain available", async () => {
        const result = await executeCustodyAppend(
          { ...baseParams, custodyChainObjectId: undefined, custodyMode: CustodyMode.BEST_EFFORT },
          noCustodyChainDelegate
        );

        expect(result.status).toBe("skipped");
        expect(result.compliant).toBe(false);
      });
    });

    describe("REQUIRED mode", () => {
      it("should append custody and return compliant on success", async () => {
        const result = await executeCustodyAppend(
          { ...baseParams, custodyMode: CustodyMode.REQUIRED },
          successDelegate
        );

        expect(result.status).toBe("appended");
        expect(result.compliant).toBe(true);
        expect(result.mode).toBe(CustodyMode.REQUIRED);
      });

      it("should throw on error", async () => {
        await expect(
          executeCustodyAppend(
            { ...baseParams, custodyMode: CustodyMode.REQUIRED },
            failingDelegate
          )
        ).rejects.toThrow("Custody append required but failed");
      });

      it("should throw when no custody chain available", async () => {
        await expect(
          executeCustodyAppend(
            { ...baseParams, custodyChainObjectId: undefined, custodyMode: CustodyMode.REQUIRED },
            noCustodyChainDelegate
          )
        ).rejects.toThrow("Custody append required but failed");
      });
    });
  });

  describe("isCustodyCompliant", () => {
    it("should return true when status is appended", () => {
      expect(isCustodyCompliant({
        status: "appended",
        compliant: true,
        mode: CustodyMode.REQUIRED,
      })).toBe(true);
    });

    it("should return true when mode is DISABLED", () => {
      expect(isCustodyCompliant({
        status: "disabled",
        compliant: true,
        mode: CustodyMode.DISABLED,
      })).toBe(true);
    });

    it("should return false when status is failed", () => {
      expect(isCustodyCompliant({
        status: "failed",
        compliant: false,
        mode: CustodyMode.BEST_EFFORT,
        error: "test error",
      })).toBe(false);
    });

    it("should return false when status is skipped", () => {
      expect(isCustodyCompliant({
        status: "skipped",
        compliant: false,
        mode: CustodyMode.BEST_EFFORT,
      })).toBe(false);
    });
  });

  describe("toCustodyResult", () => {
    it("should convert to CustodyResult type", () => {
      const input = {
        status: "appended" as const,
        compliant: true,
        mode: CustodyMode.REQUIRED,
        custodyChainObjectId: "0xchain",
        custodyEventObjectId: "0xevent",
        custodyAppendDigest: "0xdigest",
      };

      const result = toCustodyResult(input);

      expect(result.status).toBe("appended");
      expect(result.compliant).toBe(true);
      expect(result.mode).toBe(CustodyMode.REQUIRED);
      expect(result.custodyChainObjectId).toBe("0xchain");
      expect(result.custodyEventObjectId).toBe("0xevent");
      expect(result.custodyAppendDigest).toBe("0xdigest");
    });
  });
});
