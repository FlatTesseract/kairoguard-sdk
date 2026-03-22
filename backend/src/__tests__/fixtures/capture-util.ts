/**
 * Fixture Capture Utility
 * 
 * This utility helps capture real request/response pairs from the running system
 * to populate the golden-path test fixtures.
 * 
 * USAGE (in development):
 * 1. Import captureFixture in dkg-executor.ts temporarily
 * 2. Call captureFixture() after a real operation completes
 * 3. Copy the logged JSON to fixtures/golden-paths.ts
 * 4. Remove the capture code before committing
 */

import type { PolicyReceiptMintFixture, DeniedOperationFixture, CustodyExpectation } from "./types.js";
import type { CustodyStatus, CustodyMode } from "../../custody-mode.js";

export type CapturedMintRequest = {
  policyId: string;
  policyVersion: string;
  evmChainId: number;
  toEvm: string;
  intentHashHex: string;
  evmSelectorHex?: string;
  erc20AmountHex?: string;
  custodyMode?: CustodyMode;
};

export type CapturedMintResponse = {
  receiptObjectId: string;
  digest: string;
  custodyStatus: CustodyStatus;
  custodyCompliant: boolean;
  custodyChainObjectId?: string;
  custodyAppendDigest?: string;
  custodyEventObjectId?: string;
  custodyAppendError?: string;
};

/**
 * Capture a policy receipt mint operation as a fixture.
 */
export function captureMintFixture(
  name: string,
  description: string,
  request: CapturedMintRequest,
  response: CapturedMintResponse,
  allowed: boolean,
  denialReason?: number
): PolicyReceiptMintFixture {
  const fixture: PolicyReceiptMintFixture = {
    name,
    description,
    input: {
      policyId: request.policyId,
      policyVersion: request.policyVersion,
      evmChainId: request.evmChainId,
      toEvm: request.toEvm,
      intentHashHex: request.intentHashHex,
      evmSelectorHex: request.evmSelectorHex,
      erc20AmountHex: request.erc20AmountHex,
      custodyMode: request.custodyMode,
    },
    expected: {
      policy: {
        allowed,
        denialReason,
        policyObjectId: request.policyId,
        policyVersion: request.policyVersion,
      },
      custody: {
        status: response.custodyStatus,
        compliant: response.custodyCompliant,
        custodyEventObjectId: response.custodyEventObjectId,
        error: response.custodyAppendError,
      },
      receiptObjectId: response.receiptObjectId,
    },
  };

  // Log for easy copy-paste
  console.log("\n=== CAPTURED FIXTURE ===");
  console.log(JSON.stringify(fixture, null, 2));
  console.log("========================\n");

  return fixture;
}

/**
 * Capture a denied operation as a fixture.
 */
export function captureDeniedFixture(
  name: string,
  description: string,
  request: CapturedMintRequest,
  denialReason: number,
  denialReasonName: string
): DeniedOperationFixture {
  const fixture: DeniedOperationFixture = {
    name,
    description,
    input: {
      policyId: request.policyId,
      policyVersion: request.policyVersion,
      evmChainId: request.evmChainId,
      toEvm: request.toEvm,
      intentHashHex: request.intentHashHex,
    },
    expected: {
      allowed: false,
      denialReason,
      denialReasonName,
    },
  };

  // Log for easy copy-paste
  console.log("\n=== CAPTURED DENIED FIXTURE ===");
  console.log(JSON.stringify(fixture, null, 2));
  console.log("===============================\n");

  return fixture;
}

/**
 * Middleware-style wrapper to capture fixtures during development.
 * 
 * Example usage in dkg-executor.ts:
 * 
 * ```typescript
 * import { wrapWithCapture } from "./__tests__/fixtures/capture-util.js";
 * 
 * // Temporarily wrap the mint function
 * const originalMint = this.mintPolicyReceipt.bind(this);
 * this.mintPolicyReceipt = wrapWithCapture(originalMint, "mint-operation");
 * ```
 */
export function wrapWithCapture<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  operationName: string
): T {
  return (async (...args: Parameters<T>) => {
    console.log(`\n[CAPTURE] Starting ${operationName}`, { args: JSON.stringify(args[0]) });
    const startTime = Date.now();
    
    try {
      const result = await fn(...args);
      console.log(`[CAPTURE] Completed ${operationName} in ${Date.now() - startTime}ms`, {
        result: JSON.stringify(result),
      });
      return result;
    } catch (err) {
      console.log(`[CAPTURE] Failed ${operationName} in ${Date.now() - startTime}ms`, {
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  }) as T;
}
