/**
 * Domain Error Types
 * 
 * Consistent error types for the Kairo backend.
 * 
 * Categories:
 * - Configuration errors (setup-time)
 * - Validation errors (input validation)
 * - Policy errors (policy gate violations)
 * - Custody errors (custody append failures)
 * - Signing errors (MPC sign failures)
 * - Broadcast errors (EVM tx failures)
 * - Chain errors (Sui/EVM RPC failures)
 */

/**
 * Error codes for domain errors.
 * These should remain stable for API consumers.
 */
export enum ErrorCode {
  // Configuration errors (1xx)
  CONFIG_INVALID = "CONFIG_INVALID",
  CONFIG_MISSING = "CONFIG_MISSING",
  
  // Validation errors (2xx)
  VALIDATION_FAILED = "VALIDATION_FAILED",
  INVALID_INPUT = "INVALID_INPUT",
  INVALID_HEX = "INVALID_HEX",
  INVALID_ADDRESS = "INVALID_ADDRESS",
  
  // Policy errors (3xx)
  POLICY_DENIED = "POLICY_DENIED",
  POLICY_MISMATCH = "POLICY_MISMATCH",
  POLICY_EXPIRED = "POLICY_EXPIRED",
  POLICY_NOT_FOUND = "POLICY_NOT_FOUND",
  RECEIPT_INVALID = "RECEIPT_INVALID",
  RECEIPT_MISMATCH = "RECEIPT_MISMATCH",
  POLICY_BINDING_MISMATCH = "POLICY_BINDING_MISMATCH",
  POLICY_UPDATE_REQUIRED = "POLICY_UPDATE_REQUIRED",
  
  // Custody errors (4xx)
  CUSTODY_APPEND_FAILED = "CUSTODY_APPEND_FAILED",
  CUSTODY_CHAIN_NOT_FOUND = "CUSTODY_CHAIN_NOT_FOUND",
  CUSTODY_REQUIRED = "CUSTODY_REQUIRED",
  
  // DKG/Wallet errors (5xx)
  DKG_FAILED = "DKG_FAILED",
  DWALLET_NOT_FOUND = "DWALLET_NOT_FOUND",
  DWALLET_NOT_ACTIVE = "DWALLET_NOT_ACTIVE",
  PRESIGN_FAILED = "PRESIGN_FAILED",
  PRESIGN_NOT_FOUND = "PRESIGN_NOT_FOUND",
  PRESIGN_NOT_COMPLETED = "PRESIGN_NOT_COMPLETED",
  
  // Signing errors (6xx)
  SIGN_FAILED = "SIGN_FAILED",
  SIGNATURE_INVALID = "SIGNATURE_INVALID",
  
  // Broadcast errors (7xx)
  BROADCAST_FAILED = "BROADCAST_FAILED",
  TX_REJECTED = "TX_REJECTED",
  INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS",
  
  // Chain errors (8xx)
  SUI_RPC_ERROR = "SUI_RPC_ERROR",
  EVM_RPC_ERROR = "EVM_RPC_ERROR",
  TRANSACTION_TIMEOUT = "TRANSACTION_TIMEOUT",
  
  // Internal errors (9xx)
  INTERNAL_ERROR = "INTERNAL_ERROR",
  NOT_IMPLEMENTED = "NOT_IMPLEMENTED",
}

/**
 * Base domain error class.
 * All domain-specific errors should extend this.
 */
export class DomainError extends Error {
  readonly code: ErrorCode;
  readonly recoverable: boolean;
  readonly cause?: Error;
  readonly details?: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message: string,
    options?: {
      recoverable?: boolean;
      cause?: Error;
      details?: Record<string, unknown>;
    }
  ) {
    super(message);
    this.name = "DomainError";
    this.code = code;
    this.recoverable = options?.recoverable ?? false;
    this.cause = options?.cause;
    this.details = options?.details;

    // Maintain proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }

  /**
   * Convert to JSON for API responses.
   */
  toJSON(): Record<string, unknown> {
    return {
      error: this.code,
      message: this.message,
      recoverable: this.recoverable,
      details: this.details,
    };
  }
}

// ============================================================
// Configuration Errors
// ============================================================

export class ConfigError extends DomainError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCode.CONFIG_INVALID, message, { recoverable: false, details });
    this.name = "ConfigError";
  }
}

export class ConfigMissingError extends DomainError {
  constructor(configKey: string) {
    super(ErrorCode.CONFIG_MISSING, `Missing required configuration: ${configKey}`, {
      recoverable: false,
      details: { configKey },
    });
    this.name = "ConfigMissingError";
  }
}

// ============================================================
// Validation Errors
// ============================================================

export class ValidationError extends DomainError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(ErrorCode.VALIDATION_FAILED, message, { recoverable: false, details });
    this.name = "ValidationError";
  }
}

export class InvalidInputError extends DomainError {
  constructor(field: string, message: string) {
    super(ErrorCode.INVALID_INPUT, `Invalid ${field}: ${message}`, {
      recoverable: false,
      details: { field },
    });
    this.name = "InvalidInputError";
  }
}

// ============================================================
// Policy Errors
// ============================================================

export class PolicyError extends DomainError {
  constructor(
    code: ErrorCode,
    message: string,
    options?: {
      denialReason?: number;
      details?: Record<string, unknown>;
    }
  ) {
    super(code, message, {
      recoverable: false,
      details: { denialReason: options?.denialReason, ...options?.details },
    });
    this.name = "PolicyError";
  }
}

/**
 * Human-readable denial reason map.
 * Mirrors the Move contract constants in kairo_policy_engine::policy_registry.
 */
export const DENIAL_REASON_MAP: Record<number, string> = {
  0: "No denial",
  1: "Policy has expired",
  2: "Destination address is on the denylist",
  3: "Destination address is not in the allowlist",
  4: "Invalid intent format",
  10: "This chain/network is not allowed by policy",
  11: "Invalid EVM function selector format",
  12: "This contract function is on the denylist",
  13: "This contract function is not in the allowlist",
  14: "Invalid ERC20 amount format",
  15: "ERC20 transfer amount exceeds policy limit",
  16: "No active policy version found",
  20: "This blockchain type is not allowed",
  21: "Bitcoin address type not allowed by policy",
  22: "Bitcoin fee rate exceeds policy limit",
  23: "Solana program is on the denylist",
  24: "Solana program is not in the allowlist",
};

/**
 * Look up a human-readable name for a denial reason code.
 * Falls back to "Unknown denial reason (<code>)" for unmapped codes.
 */
export function getDenialReasonName(code: number): string {
  return DENIAL_REASON_MAP[code] ?? `Unknown denial reason (${code})`;
}

export class PolicyDeniedError extends PolicyError {
  readonly denialReason: number;
  readonly denialReasonName: string;

  constructor(denialReason: number, denialReasonName?: string) {
    const name = denialReasonName ?? getDenialReasonName(denialReason);
    super(ErrorCode.POLICY_DENIED, `Policy denied: ${name}`, {
      denialReason,
      details: { denialReasonName: name },
    });
    this.name = "PolicyDeniedError";
    this.denialReason = denialReason;
    this.denialReasonName = name;
  }
}

export class PolicyMismatchError extends PolicyError {
  constructor(field: string, expected: string, actual: string) {
    super(ErrorCode.POLICY_MISMATCH, `PolicyReceipt ${field} mismatch`, {
      details: { field, expected, actual },
    });
    this.name = "PolicyMismatchError";
  }
}

export class PolicyNotFoundError extends PolicyError {
  constructor(policyId: string) {
    super(ErrorCode.POLICY_NOT_FOUND, `Policy not found: ${policyId}`, {
      details: { policyId },
    });
    this.name = "PolicyNotFoundError";
  }
}

export class ReceiptInvalidError extends PolicyError {
  constructor(message: string, receiptId?: string) {
    super(ErrorCode.RECEIPT_INVALID, message, {
      details: { receiptId },
    });
    this.name = "ReceiptInvalidError";
  }
}

export class PolicyUpdateRequiredError extends PolicyError {
  constructor() {
    super(
      ErrorCode.POLICY_UPDATE_REQUIRED,
      "Policy updated and requires confirmation (reaffirm PolicyBinding to continue)"
    );
    this.name = "PolicyUpdateRequiredError";
  }
}

// ============================================================
// Custody Errors
// ============================================================

export class CustodyError extends DomainError {
  constructor(
    code: ErrorCode,
    message: string,
    options?: {
      recoverable?: boolean;
      cause?: Error;
      details?: Record<string, unknown>;
    }
  ) {
    super(code, message, options);
    this.name = "CustodyError";
  }
}

export class CustodyAppendFailedError extends CustodyError {
  constructor(cause?: Error, details?: Record<string, unknown>) {
    super(ErrorCode.CUSTODY_APPEND_FAILED, "Custody append failed", {
      recoverable: true,
      cause,
      details,
    });
    this.name = "CustodyAppendFailedError";
  }
}

export class CustodyRequiredError extends CustodyError {
  constructor(reason: string) {
    super(ErrorCode.CUSTODY_REQUIRED, `Custody append required but failed: ${reason}`, {
      recoverable: false,
      details: { reason },
    });
    this.name = "CustodyRequiredError";
  }
}

// ============================================================
// DKG/Wallet Errors
// ============================================================

export class DKGError extends DomainError {
  constructor(message: string, cause?: Error) {
    super(ErrorCode.DKG_FAILED, message, { recoverable: false, cause });
    this.name = "DKGError";
  }
}

export class DWalletNotFoundError extends DomainError {
  constructor(dWalletId: string) {
    super(ErrorCode.DWALLET_NOT_FOUND, `dWallet not found: ${dWalletId}`, {
      recoverable: false,
      details: { dWalletId },
    });
    this.name = "DWalletNotFoundError";
  }
}

export class DWalletNotActiveError extends DomainError {
  constructor(dWalletId: string, currentState: string) {
    super(
      ErrorCode.DWALLET_NOT_ACTIVE,
      `dWallet is not active yet (state=${currentState})`,
      {
        recoverable: true,
        details: { dWalletId, currentState },
      }
    );
    this.name = "DWalletNotActiveError";
  }
}

export class PresignError extends DomainError {
  constructor(message: string, cause?: Error) {
    super(ErrorCode.PRESIGN_FAILED, message, { recoverable: false, cause });
    this.name = "PresignError";
  }
}

export class PresignNotFoundError extends DomainError {
  constructor(presignId: string) {
    super(ErrorCode.PRESIGN_NOT_FOUND, `Presign not found: ${presignId}`, {
      recoverable: false,
      details: { presignId },
    });
    this.name = "PresignNotFoundError";
  }
}

// ============================================================
// Signing Errors
// ============================================================

export class SignError extends DomainError {
  constructor(message: string, cause?: Error) {
    super(ErrorCode.SIGN_FAILED, message, { recoverable: false, cause });
    this.name = "SignError";
  }
}

// ============================================================
// Broadcast Errors
// ============================================================

export class BroadcastError extends DomainError {
  constructor(
    code: ErrorCode,
    message: string,
    options?: {
      txHash?: string;
      cause?: Error;
      details?: Record<string, unknown>;
    }
  ) {
    super(code, message, {
      recoverable: code === ErrorCode.EVM_RPC_ERROR,
      cause: options?.cause,
      details: { txHash: options?.txHash, ...options?.details },
    });
    this.name = "BroadcastError";
  }
}

export class InsufficientFundsError extends BroadcastError {
  constructor(address: string, required?: string, available?: string) {
    super(ErrorCode.INSUFFICIENT_FUNDS, `Insufficient funds for transaction`, {
      details: { address, required, available },
    });
    this.name = "InsufficientFundsError";
  }
}

// ============================================================
// Chain Errors
// ============================================================

export class ChainError extends DomainError {
  constructor(
    code: ErrorCode,
    message: string,
    options?: {
      recoverable?: boolean;
      cause?: Error;
      details?: Record<string, unknown>;
    }
  ) {
    super(code, message, { recoverable: options?.recoverable ?? true, ...options });
    this.name = "ChainError";
  }
}

export class SuiRpcError extends ChainError {
  constructor(message: string, cause?: Error) {
    super(ErrorCode.SUI_RPC_ERROR, message, { recoverable: true, cause });
    this.name = "SuiRpcError";
  }
}

export class EvmRpcError extends ChainError {
  constructor(message: string, chainId: number, cause?: Error) {
    super(ErrorCode.EVM_RPC_ERROR, message, {
      recoverable: true,
      cause,
      details: { chainId },
    });
    this.name = "EvmRpcError";
  }
}

export class TransactionTimeoutError extends ChainError {
  constructor(operation: string, timeoutMs: number) {
    super(ErrorCode.TRANSACTION_TIMEOUT, `${operation} timed out after ${timeoutMs}ms`, {
      recoverable: true,
      details: { operation, timeoutMs },
    });
    this.name = "TransactionTimeoutError";
  }
}

// ============================================================
// Error Helpers
// ============================================================

/**
 * Check if an error is a domain error.
 */
export function isDomainError(err: unknown): err is DomainError {
  return err instanceof DomainError;
}

/**
 * Check if an error is recoverable.
 */
export function isRecoverableError(err: unknown): boolean {
  if (isDomainError(err)) {
    return err.recoverable;
  }
  return false;
}

/**
 * Wrap an unknown error as a domain error.
 */
export function wrapError(err: unknown, code: ErrorCode = ErrorCode.INTERNAL_ERROR): DomainError {
  if (isDomainError(err)) {
    return err;
  }
  
  const message = err instanceof Error ? err.message : String(err);
  const cause = err instanceof Error ? err : undefined;
  
  return new DomainError(code, message, { cause, recoverable: false });
}

/**
 * Extract error message from unknown error.
 */
export function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}
