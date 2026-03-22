/**
 * Domain Error Tests
 * 
 * Validates error types and helpers.
 */

import { describe, it, expect } from "bun:test";
import {
  DomainError,
  ErrorCode,
  ConfigError,
  ConfigMissingError,
  ValidationError,
  PolicyDeniedError,
  PolicyMismatchError,
  CustodyRequiredError,
  CustodyAppendFailedError,
  DKGError,
  DWalletNotActiveError,
  PresignNotFoundError,
  SignError,
  InsufficientFundsError,
  SuiRpcError,
  TransactionTimeoutError,
  isDomainError,
  isRecoverableError,
  wrapError,
  getErrorMessage,
} from "../types/errors.js";

describe("Domain Errors", () => {
  describe("DomainError base class", () => {
    it("should create error with code and message", () => {
      const err = new DomainError(ErrorCode.INTERNAL_ERROR, "Test error");
      
      expect(err.code).toBe(ErrorCode.INTERNAL_ERROR);
      expect(err.message).toBe("Test error");
      expect(err.recoverable).toBe(false);
      expect(err.name).toBe("DomainError");
    });

    it("should support recoverable flag", () => {
      const err = new DomainError(ErrorCode.SUI_RPC_ERROR, "RPC failed", {
        recoverable: true,
      });
      
      expect(err.recoverable).toBe(true);
    });

    it("should support cause", () => {
      const cause = new Error("Original error");
      const err = new DomainError(ErrorCode.INTERNAL_ERROR, "Wrapped", {
        cause,
      });
      
      expect(err.cause).toBe(cause);
    });

    it("should support details", () => {
      const err = new DomainError(ErrorCode.INTERNAL_ERROR, "Test", {
        details: { foo: "bar", count: 42 },
      });
      
      expect(err.details).toEqual({ foo: "bar", count: 42 });
    });

    it("should serialize to JSON", () => {
      const err = new DomainError(ErrorCode.POLICY_DENIED, "Denied", {
        recoverable: false,
        details: { reason: 2 },
      });
      
      const json = err.toJSON();
      expect(json.error).toBe(ErrorCode.POLICY_DENIED);
      expect(json.message).toBe("Denied");
      expect(json.recoverable).toBe(false);
      expect(json.details).toEqual({ reason: 2 });
    });
  });

  describe("Configuration Errors", () => {
    it("should create ConfigError", () => {
      const err = new ConfigError("Invalid config");
      expect(err.code).toBe(ErrorCode.CONFIG_INVALID);
      expect(err.name).toBe("ConfigError");
    });

    it("should create ConfigMissingError with key", () => {
      const err = new ConfigMissingError("SUI_ADMIN_SECRET_KEY");
      expect(err.code).toBe(ErrorCode.CONFIG_MISSING);
      expect(err.message).toContain("SUI_ADMIN_SECRET_KEY");
      expect(err.details?.configKey).toBe("SUI_ADMIN_SECRET_KEY");
    });
  });

  describe("Policy Errors", () => {
    it("should create PolicyDeniedError with reason", () => {
      const err = new PolicyDeniedError(2, "DENYLIST");
      
      expect(err.code).toBe(ErrorCode.POLICY_DENIED);
      expect(err.denialReason).toBe(2);
      expect(err.denialReasonName).toBe("DENYLIST");
      expect(err.message).toContain("DENYLIST");
    });

    it("should create PolicyMismatchError", () => {
      const err = new PolicyMismatchError("policy_version", "1.0.0", "2.0.0");
      
      expect(err.code).toBe(ErrorCode.POLICY_MISMATCH);
      expect(err.details?.field).toBe("policy_version");
      expect(err.details?.expected).toBe("1.0.0");
      expect(err.details?.actual).toBe("2.0.0");
    });
  });

  describe("Custody Errors", () => {
    it("should create CustodyRequiredError", () => {
      const err = new CustodyRequiredError("No custody chain available");
      
      expect(err.code).toBe(ErrorCode.CUSTODY_REQUIRED);
      expect(err.recoverable).toBe(false);
    });

    it("should create CustodyAppendFailedError as recoverable", () => {
      const err = new CustodyAppendFailedError();
      
      expect(err.code).toBe(ErrorCode.CUSTODY_APPEND_FAILED);
      expect(err.recoverable).toBe(true);
    });
  });

  describe("DKG/Wallet Errors", () => {
    it("should create DWalletNotActiveError as recoverable", () => {
      const err = new DWalletNotActiveError("0xwallet", "AwaitingKeyHolderSignature");
      
      expect(err.code).toBe(ErrorCode.DWALLET_NOT_ACTIVE);
      expect(err.recoverable).toBe(true);
      expect(err.details?.currentState).toBe("AwaitingKeyHolderSignature");
    });

    it("should create PresignNotFoundError", () => {
      const err = new PresignNotFoundError("0xpresign");
      
      expect(err.code).toBe(ErrorCode.PRESIGN_NOT_FOUND);
      expect(err.details?.presignId).toBe("0xpresign");
    });
  });

  describe("Chain Errors", () => {
    it("should create SuiRpcError as recoverable", () => {
      const err = new SuiRpcError("Connection refused");
      
      expect(err.code).toBe(ErrorCode.SUI_RPC_ERROR);
      expect(err.recoverable).toBe(true);
    });

    it("should create TransactionTimeoutError with timing details", () => {
      const err = new TransactionTimeoutError("Presign completion", 60000);
      
      expect(err.code).toBe(ErrorCode.TRANSACTION_TIMEOUT);
      expect(err.details?.operation).toBe("Presign completion");
      expect(err.details?.timeoutMs).toBe(60000);
    });
  });

  describe("Error Helpers", () => {
    describe("isDomainError", () => {
      it("should return true for DomainError instances", () => {
        expect(isDomainError(new DomainError(ErrorCode.INTERNAL_ERROR, "test"))).toBe(true);
        expect(isDomainError(new PolicyDeniedError(1))).toBe(true);
        expect(isDomainError(new SuiRpcError("test"))).toBe(true);
      });

      it("should return false for non-DomainError", () => {
        expect(isDomainError(new Error("test"))).toBe(false);
        expect(isDomainError("test")).toBe(false);
        expect(isDomainError(null)).toBe(false);
        expect(isDomainError(undefined)).toBe(false);
      });
    });

    describe("isRecoverableError", () => {
      it("should check recoverable flag", () => {
        expect(isRecoverableError(new SuiRpcError("test"))).toBe(true);
        expect(isRecoverableError(new PolicyDeniedError(1))).toBe(false);
        expect(isRecoverableError(new Error("test"))).toBe(false);
      });
    });

    describe("wrapError", () => {
      it("should return DomainError unchanged", () => {
        const original = new PolicyDeniedError(2);
        const wrapped = wrapError(original);
        
        expect(wrapped).toBe(original);
      });

      it("should wrap Error", () => {
        const original = new Error("Original message");
        const wrapped = wrapError(original);
        
        expect(wrapped.code).toBe(ErrorCode.INTERNAL_ERROR);
        expect(wrapped.message).toBe("Original message");
        expect(wrapped.cause).toBe(original);
      });

      it("should wrap string", () => {
        const wrapped = wrapError("Something went wrong");
        
        expect(wrapped.message).toBe("Something went wrong");
        expect(wrapped.cause).toBeUndefined();
      });

      it("should use custom error code", () => {
        const wrapped = wrapError(new Error("test"), ErrorCode.SIGN_FAILED);
        
        expect(wrapped.code).toBe(ErrorCode.SIGN_FAILED);
      });
    });

    describe("getErrorMessage", () => {
      it("should extract message from Error", () => {
        expect(getErrorMessage(new Error("Test message"))).toBe("Test message");
      });

      it("should convert non-Error to string", () => {
        expect(getErrorMessage("string error")).toBe("string error");
        expect(getErrorMessage(42)).toBe("42");
        expect(getErrorMessage({ foo: "bar" })).toBe("[object Object]");
      });
    });
  });
});

describe("ErrorCode enum", () => {
  it("should have unique values", () => {
    const values = Object.values(ErrorCode);
    const uniqueValues = new Set(values);
    expect(values.length).toBe(uniqueValues.size);
  });

  it("should have expected categories", () => {
    // Config errors
    expect(ErrorCode.CONFIG_INVALID).toBeDefined();
    expect(ErrorCode.CONFIG_MISSING).toBeDefined();
    
    // Policy errors
    expect(ErrorCode.POLICY_DENIED).toBeDefined();
    expect(ErrorCode.POLICY_MISMATCH).toBeDefined();
    
    // Custody errors
    expect(ErrorCode.CUSTODY_APPEND_FAILED).toBeDefined();
    expect(ErrorCode.CUSTODY_REQUIRED).toBeDefined();
    
    // Chain errors
    expect(ErrorCode.SUI_RPC_ERROR).toBeDefined();
    expect(ErrorCode.EVM_RPC_ERROR).toBeDefined();
  });
});
