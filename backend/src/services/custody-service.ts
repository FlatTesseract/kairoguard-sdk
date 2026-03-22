/**
 * Custody Service
 * 
 * Consolidated custody append logic with configurable enforcement modes.
 * This is the single source of truth for custody operations.
 * 
 * Key responsibilities:
 * 1. Execute custody append operations
 * 2. Enforce custody modes (REQUIRED, BEST_EFFORT, DISABLED)
 * 3. Determine compliance status
 * 4. Provide consistent logging and error handling
 */

import { CustodyMode, CustodyStatus, resolveEffectiveCustodyMode } from "../custody-mode.js";
import type { CustodyResult } from "../types/operation-lifecycle.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import type { Hex } from "viem";

/**
 * Input parameters for custody append operation.
 */
export interface CustodyAppendParams {
  /** Policy receipt object ID (required for custody event) */
  receiptObjectId: string;
  /** Policy object ID */
  policyObjectId: string;
  /** Intent hash (32 bytes hex) */
  intentHashHex: Hex;
  /** Target EVM address */
  toEvm: string;
  /** Digest from the receipt mint transaction */
  mintDigest: string;
  /** Optional: custody chain object ID (if not provided, will be looked up) */
  custodyChainObjectId?: string;
  /** Optional: custody package ID (defaults to config) */
  custodyPackageId?: string;
  /** Optional: override custody mode for this operation */
  custodyMode?: CustodyMode;
  /** Context for logging (e.g., "post-broadcast", "receipt-mint") */
  operationContext?: string;
}

/**
 * Delegate interface for the actual Sui transaction execution.
 * This allows the service to be tested independently.
 */
export interface CustodyAppendDelegate {
  appendCustodyEventWithReceipt(args: {
    custodyPackageId: string;
    custodyChainObjectId: string;
    receiptObjectId: string;
    policyObjectId: string;
    intentHashHex: Hex;
    toEvm: string;
    mintDigest: string;
  }): Promise<{ digest: string; custodyEventObjectId?: string }>;

  resolveCustodyChainId(policyObjectId: string): Promise<string | null>;
}

/**
 * Result of custody append with enforcement.
 */
export interface CustodyAppendResult {
  /** Final custody status */
  status: CustodyStatus;
  /** Whether custody requirements were met */
  compliant: boolean;
  /** Effective custody mode used */
  mode: CustodyMode;
  /** Custody chain object ID (if available) */
  custodyChainObjectId?: string;
  /** Created custody event object ID */
  custodyEventObjectId?: string;
  /** Transaction digest for the custody append */
  custodyAppendDigest?: string;
  /** Error message if append failed */
  error?: string;
}

/**
 * Execute custody append with mode enforcement.
 * 
 * This is the main entry point for all custody operations.
 * Callers should use this instead of directly calling appendCustodyEventWithReceipt.
 * 
 * @param params - Custody append parameters
 * @param delegate - Delegate for actual Sui operations
 * @returns Custody result with status and compliance
 * @throws Only in REQUIRED mode when append fails
 */
export async function executeCustodyAppend(
  params: CustodyAppendParams,
  delegate: CustodyAppendDelegate
): Promise<CustodyAppendResult> {
  const effectiveMode = resolveEffectiveCustodyMode(
    params.custodyMode,
    config.kairo.custodyMode
  );

  const context = params.operationContext ?? "operation";

  // Handle DISABLED mode - no custody operations
  if (effectiveMode === CustodyMode.DISABLED) {
    logger.debug(
      { receiptObjectId: params.receiptObjectId, context },
      "Custody append disabled for this operation"
    );
    return {
      status: "disabled",
      compliant: true,
      mode: effectiveMode,
    };
  }

  // Resolve custody chain ID if not provided
  let custodyChainObjectId = params.custodyChainObjectId;
  if (!custodyChainObjectId || !custodyChainObjectId.startsWith("0x")) {
    try {
      const resolved = await delegate.resolveCustodyChainId(params.policyObjectId);
      if (resolved) {
        custodyChainObjectId = resolved;
      }
    } catch (err) {
      logger.debug(
        { err, policyObjectId: params.policyObjectId },
        "Could not resolve custody chain ID"
      );
    }
  }

  // No custody chain available - skip or fail based on mode
  if (!custodyChainObjectId || !custodyChainObjectId.startsWith("0x")) {
    if (effectiveMode === CustodyMode.REQUIRED) {
      const error = "No custody chain available for policy";
      logger.error(
        { receiptObjectId: params.receiptObjectId, context, custodyMode: effectiveMode },
        `Custody append failed (REQUIRED mode) - ${error}`
      );
      throw new Error(`Custody append required but failed: ${error}`);
    }

    logger.warn(
      { receiptObjectId: params.receiptObjectId, context, custodyMode: effectiveMode },
      "No custody chain available - skipping custody append (BEST_EFFORT mode)"
    );
    return {
      status: "skipped",
      compliant: false,
      mode: effectiveMode,
      error: "No custody chain available for policy",
    };
  }

  // Resolve custody package ID
  const custodyPackageId = (
    params.custodyPackageId ??
    config.kairo.custodyPackageId ??
    config.kairo.policyMintPackageId ??
    ""
  ).trim();

  if (!custodyPackageId.startsWith("0x")) {
    if (effectiveMode === CustodyMode.REQUIRED) {
      const error = "No custody package ID configured";
      logger.error(
        { receiptObjectId: params.receiptObjectId, context, custodyMode: effectiveMode },
        `Custody append failed (REQUIRED mode) - ${error}`
      );
      throw new Error(`Custody append required but failed: ${error}`);
    }

    logger.warn(
      { receiptObjectId: params.receiptObjectId, context, custodyMode: effectiveMode },
      "No custody package ID - skipping custody append (BEST_EFFORT mode)"
    );
    return {
      status: "skipped",
      compliant: false,
      mode: effectiveMode,
      error: "No custody package ID configured",
    };
  }

  // Attempt custody append
  try {
    const result = await delegate.appendCustodyEventWithReceipt({
      custodyPackageId,
      custodyChainObjectId,
      receiptObjectId: params.receiptObjectId,
      policyObjectId: params.policyObjectId,
      intentHashHex: params.intentHashHex,
      toEvm: params.toEvm,
      mintDigest: params.mintDigest,
    });

    logger.info(
      {
        receiptObjectId: params.receiptObjectId,
        custodyChainObjectId,
        custodyEventObjectId: result.custodyEventObjectId,
        custodyAppendDigest: result.digest,
        custodyMode: effectiveMode,
        context,
      },
      "Custody event appended successfully"
    );

    return {
      status: "appended",
      compliant: true,
      mode: effectiveMode,
      custodyChainObjectId,
      custodyEventObjectId: result.custodyEventObjectId,
      custodyAppendDigest: result.digest,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);

    if (effectiveMode === CustodyMode.REQUIRED) {
      logger.error(
        { err, receiptObjectId: params.receiptObjectId, context, custodyMode: effectiveMode },
        "Custody append failed (REQUIRED mode) - operation cannot complete"
      );
      throw new Error(`Custody append required but failed: ${error}`);
    }

    // BEST_EFFORT: log warning and continue (non-compliant)
    logger.warn(
      { err, receiptObjectId: params.receiptObjectId, context, custodyMode: effectiveMode },
      "Custody append failed (BEST_EFFORT mode) - continuing without custody event"
    );

    return {
      status: "failed",
      compliant: false,
      mode: effectiveMode,
      custodyChainObjectId,
      error,
    };
  }
}

/**
 * Determine if a custody result is compliant.
 * 
 * Compliance is true when:
 * - status is "appended" (custody event was written)
 * - OR mode is DISABLED (custody intentionally skipped)
 */
export function isCustodyCompliant(result: CustodyAppendResult): boolean {
  return result.status === "appended" || result.mode === CustodyMode.DISABLED;
}

/**
 * Convert CustodyAppendResult to the coordinator's CustodyResult type.
 */
export function toCustodyResult(result: CustodyAppendResult): CustodyResult {
  return {
    status: result.status,
    compliant: result.compliant,
    mode: result.mode,
    custodyChainObjectId: result.custodyChainObjectId,
    custodyEventObjectId: result.custodyEventObjectId,
    custodyAppendDigest: result.custodyAppendDigest,
    error: result.error,
  };
}

/**
 * Log a CRITICAL custody gap for post-broadcast failures.
 * 
 * This is a special case where we've already broadcast an EVM transaction
 * and can't undo it, but custody append failed. We log a critical error
 * but don't throw because the user needs to know about the successful tx.
 */
export function logPostBroadcastCustodyGap(params: {
  ethTxHash: string;
  receiptObjectId: string;
  error: string;
  custodyMode: CustodyMode;
}): void {
  if (params.custodyMode === CustodyMode.REQUIRED) {
    logger.error(
      {
        ethTxHash: params.ethTxHash,
        receiptObjectId: params.receiptObjectId,
        error: params.error,
        custodyMode: params.custodyMode,
      },
      "CRITICAL: Post-broadcast custody append failed (REQUIRED mode) - custody gap in audit trail"
    );
  } else {
    logger.warn(
      {
        ethTxHash: params.ethTxHash,
        receiptObjectId: params.receiptObjectId,
        error: params.error,
        custodyMode: params.custodyMode,
      },
      "Post-broadcast custody append failed (BEST_EFFORT mode)"
    );
  }
}
