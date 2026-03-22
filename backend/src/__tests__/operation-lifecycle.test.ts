/**
 * Operation Lifecycle Tests
 * 
 * Validates the state machine and transition logic.
 */

import { describe, it, expect } from "bun:test";
import {
  OperationState,
  VALID_TRANSITIONS,
  isValidTransition,
  createOperationContext,
  transitionState,
  contextToResponse,
} from "../types/operation-lifecycle.js";

describe("Operation Lifecycle State Machine", () => {
  describe("OperationState enum", () => {
    it("should have all required states", () => {
      expect(String(OperationState.RECEIVED)).toBe("RECEIVED");
      expect(String(OperationState.POLICY_CHECKED)).toBe("POLICY_CHECKED");
      expect(String(OperationState.CUSTODY_WRITTEN)).toBe("CUSTODY_WRITTEN");
      expect(String(OperationState.SIGNED)).toBe("SIGNED");
      expect(String(OperationState.BROADCAST)).toBe("BROADCAST");
      expect(String(OperationState.RESPONDED)).toBe("RESPONDED");
      expect(String(OperationState.FAILED)).toBe("FAILED");
    });
  });

  describe("Valid Transitions", () => {
    it("should allow RECEIVED -> POLICY_CHECKED", () => {
      expect(isValidTransition(OperationState.RECEIVED, OperationState.POLICY_CHECKED)).toBe(true);
    });

    it("should allow RECEIVED -> FAILED", () => {
      expect(isValidTransition(OperationState.RECEIVED, OperationState.FAILED)).toBe(true);
    });

    it("should allow POLICY_CHECKED -> CUSTODY_WRITTEN", () => {
      expect(isValidTransition(OperationState.POLICY_CHECKED, OperationState.CUSTODY_WRITTEN)).toBe(true);
    });

    it("should allow CUSTODY_WRITTEN -> SIGNED", () => {
      expect(isValidTransition(OperationState.CUSTODY_WRITTEN, OperationState.SIGNED)).toBe(true);
    });

    it("should allow SIGNED -> BROADCAST", () => {
      expect(isValidTransition(OperationState.SIGNED, OperationState.BROADCAST)).toBe(true);
    });

    it("should allow SIGNED -> RESPONDED (no broadcast)", () => {
      expect(isValidTransition(OperationState.SIGNED, OperationState.RESPONDED)).toBe(true);
    });

    it("should allow BROADCAST -> RESPONDED", () => {
      expect(isValidTransition(OperationState.BROADCAST, OperationState.RESPONDED)).toBe(true);
    });

    it("should allow FAILED -> RESPONDED", () => {
      expect(isValidTransition(OperationState.FAILED, OperationState.RESPONDED)).toBe(true);
    });
  });

  describe("Invalid Transitions", () => {
    it("should NOT allow RECEIVED -> SIGNED (skip steps)", () => {
      expect(isValidTransition(OperationState.RECEIVED, OperationState.SIGNED)).toBe(false);
    });

    it("should NOT allow RESPONDED -> anything", () => {
      expect(isValidTransition(OperationState.RESPONDED, OperationState.RECEIVED)).toBe(false);
      expect(isValidTransition(OperationState.RESPONDED, OperationState.FAILED)).toBe(false);
    });

    it("should NOT allow backward transitions", () => {
      expect(isValidTransition(OperationState.SIGNED, OperationState.RECEIVED)).toBe(false);
      expect(isValidTransition(OperationState.CUSTODY_WRITTEN, OperationState.POLICY_CHECKED)).toBe(false);
    });
  });

  describe("createOperationContext", () => {
    it("should create context in RECEIVED state", () => {
      const ctx = createOperationContext("op-123", "0xintent");
      expect(ctx.state).toBe(OperationState.RECEIVED);
      expect(ctx.id).toBe("op-123");
      expect(ctx.intentHash).toBe("0xintent");
      expect(ctx.timestamps[OperationState.RECEIVED]).toBeDefined();
    });

    it("should include request data if provided", () => {
      const ctx = createOperationContext("op-123", "0xintent", { foo: "bar" });
      expect(ctx.requestData).toEqual({ foo: "bar" });
    });
  });

  describe("transitionState", () => {
    it("should transition to valid next state", () => {
      const ctx = createOperationContext("op-123", "0xintent");
      const next = transitionState(ctx, OperationState.POLICY_CHECKED);
      
      expect(next.state).toBe(OperationState.POLICY_CHECKED);
      expect(next.timestamps[OperationState.POLICY_CHECKED]).toBeDefined();
      expect(next.timestamps[OperationState.RECEIVED]).toBe(ctx.timestamps[OperationState.RECEIVED]);
    });

    it("should throw on invalid transition", () => {
      const ctx = createOperationContext("op-123", "0xintent");
      
      expect(() => {
        transitionState(ctx, OperationState.SIGNED);
      }).toThrow("Invalid state transition");
    });

    it("should preserve existing context data", () => {
      const ctx = createOperationContext("op-123", "0xintent");
      ctx.policyResult = {
        success: true,
        allowed: true,
        policyObjectId: "0xpolicy",
        policyVersion: "1.0.0",
        receiptObjectId: "0xreceipt",
        receiptDigest: "0xdigest",
      };
      
      const next = transitionState(ctx, OperationState.POLICY_CHECKED);
      expect(next.policyResult).toEqual(ctx.policyResult);
    });
  });

  describe("contextToResponse", () => {
    it("should convert successful context to response", () => {
      let ctx = createOperationContext("op-123", "0xintent");
      ctx = transitionState(ctx, OperationState.POLICY_CHECKED);
      ctx.policyResult = {
        success: true,
        allowed: true,
        policyObjectId: "0xpolicy",
        policyVersion: "1.0.0",
        receiptObjectId: "0xreceipt",
        receiptDigest: "0xdigest",
      };
      ctx = transitionState(ctx, OperationState.CUSTODY_WRITTEN);
      ctx.custodyResult = {
        status: "appended",
        compliant: true,
        mode: "REQUIRED" as any,
      };
      ctx = transitionState(ctx, OperationState.SIGNED);
      ctx.signatureResult = {
        success: true,
        signatureHex: "0xsig",
        signId: "sig-123",
        digest: "0xdigest",
      };
      ctx = transitionState(ctx, OperationState.RESPONDED);
      
      const response = contextToResponse(ctx);
      
      expect(response.success).toBe(true);
      expect(response.operationId).toBe("op-123");
      expect(response.policyAllowed).toBe(true);
      expect(response.custodyStatus).toBe("appended");
      expect(response.custodyCompliant).toBe(true);
      expect(response.signatureHex).toBe("0xsig");
    });

    it("should convert failed context to error response", () => {
      let ctx = createOperationContext("op-123", "0xintent");
      ctx = transitionState(ctx, OperationState.FAILED);
      ctx.error = {
        code: "POLICY_DENIED",
        message: "Address not in allowlist",
        stage: OperationState.POLICY_CHECKED,
        recoverable: false,
      };
      ctx = transitionState(ctx, OperationState.RESPONDED);
      
      const response = contextToResponse(ctx);
      
      expect(response.success).toBe(false);
      expect(response.error).toBe("Address not in allowlist");
      expect(response.errorCode).toBe("POLICY_DENIED");
    });
  });
});

describe("VALID_TRANSITIONS coverage", () => {
  it("should have transitions from all non-terminal states", () => {
    const nonTerminalStates = [
      OperationState.RECEIVED,
      OperationState.POLICY_CHECKED,
      OperationState.CUSTODY_WRITTEN,
      OperationState.SIGNED,
      OperationState.BROADCAST,
      OperationState.FAILED,
    ];

    for (const state of nonTerminalStates) {
      const hasTransition = VALID_TRANSITIONS.some(t => t.from === state);
      expect(hasTransition).toBe(true);
    }
  });

  it("should have failure paths from all processing states", () => {
    const processingStates = [
      OperationState.RECEIVED,
      OperationState.POLICY_CHECKED,
      OperationState.CUSTODY_WRITTEN,
      OperationState.SIGNED,
      OperationState.BROADCAST,
    ];

    for (const state of processingStates) {
      const canFail = VALID_TRANSITIONS.some(
        t => t.from === state && t.to === OperationState.FAILED
      );
      expect(canFail).toBe(true);
    }
  });
});
