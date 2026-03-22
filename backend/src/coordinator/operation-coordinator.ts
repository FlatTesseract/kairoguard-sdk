/**
 * Operation Coordinator Interface
 * 
 * The coordinator owns the operation lifecycle and orchestrates calls to services.
 * Services are pure-ish (deterministic given inputs) and do NOT call each other.
 * All orchestration flows through the coordinator.
 * 
 * Key responsibilities:
 * 1. Create and manage operation context
 * 2. Enforce state machine transitions
 * 3. Call services in correct order
 * 4. Handle errors and determine recoverability
 * 5. Produce final response
 */

import type {
  OperationContext,
  OperationResponse,
  PolicyResult,
  CustodyResult,
  SignatureResult,
  BroadcastResult,
  OperationError,
} from "../types/operation-lifecycle.js";
import type { CustodyMode } from "../custody-mode.js";
import type { Hex } from "viem";

/**
 * Input for starting a sign operation.
 */
export type SignOperationInput = {
  // dWallet identifiers
  dWalletId: string;
  dWalletCapId: string;
  
  // Signing data
  presignId: string;
  messageHex: string;
  userSignMessage: number[];
  
  // Policy gating
  policyReceiptId: string;
  policyObjectId?: string;
  policyVersion?: string;
  policyBindingObjectId?: string;
  
  // Custody
  custodyChainObjectId?: string;
  custodyPackageId?: string;
  custodyMode?: CustodyMode;
  
  // Optional EVM broadcast
  ethTx?: {
    to: string;
    value: string;
    nonce: number;
    gasLimit: string;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
    chainId: number;
    from: string;
  };
};

/**
 * Input for minting a policy receipt.
 */
export type MintReceiptInput = {
  policyId: string;
  policyVersion: string;
  evmChainId: number;
  toEvm: string;
  intentHashHex: Hex;
  evmSelectorHex?: Hex | null;
  erc20AmountHex?: Hex | null;
  policyBindingObjectId?: string;
  custodyChainObjectId?: string;
  custodyPackageId?: string;
  custodyMode?: CustodyMode;
};

/**
 * Operation Coordinator Interface
 * 
 * Implementations must ensure:
 * 1. State transitions follow the valid transition graph
 * 2. Services are called in order: policy → custody → sign → broadcast
 * 3. Errors at any stage transition to FAILED state
 * 4. REQUIRED custody mode failures block the entire operation
 */
export interface IOperationCoordinator {
  /**
   * Begin a new operation, creating context in RECEIVED state.
   */
  beginOperation(request: SignOperationInput): OperationContext;
  
  /**
   * Evaluate policy for the operation.
   * Transitions: RECEIVED → POLICY_CHECKED (or FAILED)
   * 
   * This verifies the PolicyReceipt is valid for the intent.
   */
  evaluatePolicy(ctx: OperationContext): Promise<PolicyResult>;
  
  /**
   * Append custody event for the operation.
   * Transitions: POLICY_CHECKED → CUSTODY_WRITTEN (or FAILED)
   * 
   * Respects custody mode:
   * - REQUIRED: failure transitions to FAILED
   * - BEST_EFFORT: failure logs warning, continues
   * - DISABLED: skips entirely
   */
  appendCustody(ctx: OperationContext): Promise<CustodyResult>;
  
  /**
   * Execute MPC signing.
   * Transitions: CUSTODY_WRITTEN → SIGNED (or FAILED)
   */
  executeSign(ctx: OperationContext): Promise<SignatureResult>;
  
  /**
   * Broadcast transaction to target chain.
   * Transitions: SIGNED → BROADCAST (or FAILED)
   * 
   * Only called if ethTx was provided in the request.
   */
  broadcast(ctx: OperationContext): Promise<BroadcastResult>;
  
  /**
   * Complete the operation successfully.
   * Transitions: SIGNED|BROADCAST → RESPONDED
   */
  completeOperation(ctx: OperationContext): OperationResponse;
  
  /**
   * Fail the operation with an error.
   * Transitions: any → FAILED → RESPONDED
   */
  failOperation(ctx: OperationContext, error: OperationError): OperationResponse;
  
  /**
   * Execute the full operation lifecycle.
   * This is the main entry point that orchestrates all steps.
   */
  executeOperation(input: SignOperationInput): Promise<OperationResponse>;
}

/**
 * Policy Service Interface
 * 
 * Pure policy evaluation - no side effects beyond reading chain state.
 */
export interface IPolicyService {
  /**
   * Verify a PolicyReceipt matches the expected intent.
   */
  verifyReceipt(params: {
    receiptId: string;
    expectedPolicyId: string;
    expectedPolicyVersion: string;
    policyBindingObjectId?: string;
    evmChainId: number;
    toEvm: string;
    intentHashHex: Hex;
  }): Promise<PolicyResult>;
  
  /**
   * Mint a new PolicyReceipt for an intent.
   */
  mintReceipt(params: MintReceiptInput): Promise<PolicyResult>;
}

/**
 * Custody Service Interface
 * 
 * Manages custody chain operations.
 */
export interface ICustodyService {
  /**
   * Append a custody event with the configured mode.
   */
  appendEvent(params: {
    receiptObjectId: string;
    policyObjectId: string;
    intentHashHex: string;
    toEvm: string;
    custodyMode: CustodyMode;
    custodyChainObjectId?: string;
    custodyPackageId?: string;
    mintDigest: string;
  }): Promise<CustodyResult>;
  
  /**
   * Create a new custody chain for a policy.
   */
  createChain(params: {
    policyObjectId: string;
    custodyPackageId: string;
  }): Promise<{ custodyChainObjectId: string; digest: string }>;
}

/**
 * Sign Service Interface
 * 
 * Handles MPC signing operations.
 */
export interface ISignService {
  /**
   * Execute MPC sign operation.
   */
  sign(params: {
    dWalletId: string;
    dWalletCapId: string;
    presignId: string;
    messageHex: string;
    userSignMessage: number[];
    encryptedUserSecretKeyShareId?: string;
    userOutputSignature?: number[];
  }): Promise<SignatureResult>;
}

/**
 * Broadcast Service Interface
 * 
 * Handles transaction broadcast to target chains.
 */
export interface IBroadcastService {
  /**
   * Broadcast a signed transaction to an EVM chain.
   */
  broadcastEvm(params: {
    ethTx: NonNullable<SignOperationInput["ethTx"]>;
    signatureBytes: Uint8Array;
  }): Promise<BroadcastResult>;
}
