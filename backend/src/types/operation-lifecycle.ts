/**
 * Operation Lifecycle Types
 * 
 * Defines the explicit state machine for Kairo signing operations.
 * Every operation flows through these states, ensuring consistent
 * handling of policy checks, custody, and signing.
 * 
 * State flow:
 *   RECEIVED → POLICY_CHECKED → CUSTODY_WRITTEN → SIGNED → BROADCAST → RESPONDED
 *                    ↓                ↓              ↓          ↓
 *                  FAILED          FAILED        FAILED     FAILED
 */

import type { CustodyMode, CustodyStatus } from "../custody-mode.js";
import type { Hex } from "viem";

/**
 * Operation states in the lifecycle.
 */
export enum OperationState {
  /** Request received, not yet processed */
  RECEIVED = "RECEIVED",
  /** Policy evaluated (allowed or denied) */
  POLICY_CHECKED = "POLICY_CHECKED",
  /** Custody event written (or skipped if DISABLED) */
  CUSTODY_WRITTEN = "CUSTODY_WRITTEN",
  /** MPC signature obtained */
  SIGNED = "SIGNED",
  /** Transaction broadcast to target chain */
  BROADCAST = "BROADCAST",
  /** Response sent to caller */
  RESPONDED = "RESPONDED",
  /** Operation failed at some stage */
  FAILED = "FAILED",
}

/**
 * Result of policy evaluation.
 */
export type PolicyResult = {
  success: boolean;
  allowed: boolean;
  denialReason?: number;
  denialReasonName?: string;
  policyId?: string;
  policyObjectId?: string;
  policyVersion?: string;
  policyVersionId?: string;
  policyRoot?: string;
  receiptId?: string;
  receiptObjectId?: string;
  receiptDigest?: string;
  digest?: string;
  error?: string;
};

/**
 * Result of custody append operation.
 */
export type CustodyResult = {
  status: CustodyStatus;
  compliant: boolean;
  mode: CustodyMode;
  custodyChainObjectId?: string;
  custodyEventObjectId?: string;
  custodyAppendDigest?: string;
  error?: string;
};

/**
 * Result of MPC signing operation.
 */
export type SignatureResult = {
  success: boolean;
  signatureHex?: string;
  signatureBytes?: Uint8Array;
  signId?: string;
  digest?: string;
  error?: string;
};

/**
 * Result of transaction broadcast.
 */
export type BroadcastResult = {
  success: boolean;
  txHash?: string;
  blockNumber?: number;
  chainId?: number;
  chainName?: string;
  error?: string;
};

/**
 * Operation error that occurred during processing.
 * Note: For full error handling, use DomainError from ./errors.ts
 */
export type OperationError = {
  code: string;
  message: string;
  stage: OperationState;
  cause?: Error;
  recoverable: boolean;
};

/**
 * Timestamps for each state transition.
 */
export type StateTimestamps = Partial<Record<OperationState, number>>;

/**
 * Context for a single operation, tracking its progress through the lifecycle.
 */
export type OperationContext = {
  /** Unique operation identifier */
  id: string;
  
  /** Current state in the lifecycle */
  state: OperationState;
  
  /** Intent hash (keccak256 of unsigned tx bytes) */
  intentHash: string;
  
  /** Policy evaluation result */
  policyResult?: PolicyResult;
  
  /** Custody append result */
  custodyResult?: CustodyResult;
  
  /** Signature result */
  signatureResult?: SignatureResult;
  
  /** Broadcast result */
  broadcastResult?: BroadcastResult;
  
  /** Error if operation failed */
  error?: OperationError;
  
  /** Timestamps for state transitions */
  timestamps: StateTimestamps;
  
  /** Original request data (for replay/debugging) */
  requestData?: Record<string, unknown>;
};

/**
 * State transition definition.
 */
export type StateTransition = {
  from: OperationState;
  to: OperationState;
  /** Optional guard condition */
  guard?: (ctx: OperationContext) => boolean;
  /** Optional side effect */
  effect?: (ctx: OperationContext) => void;
};

/**
 * Valid state transitions.
 */
export const VALID_TRANSITIONS: StateTransition[] = [
  { from: OperationState.RECEIVED, to: OperationState.POLICY_CHECKED },
  { from: OperationState.RECEIVED, to: OperationState.FAILED },
  
  { from: OperationState.POLICY_CHECKED, to: OperationState.CUSTODY_WRITTEN },
  { from: OperationState.POLICY_CHECKED, to: OperationState.FAILED },
  
  { from: OperationState.CUSTODY_WRITTEN, to: OperationState.SIGNED },
  { from: OperationState.CUSTODY_WRITTEN, to: OperationState.FAILED },
  
  { from: OperationState.SIGNED, to: OperationState.BROADCAST },
  { from: OperationState.SIGNED, to: OperationState.RESPONDED }, // No broadcast requested
  { from: OperationState.SIGNED, to: OperationState.FAILED },
  
  { from: OperationState.BROADCAST, to: OperationState.RESPONDED },
  { from: OperationState.BROADCAST, to: OperationState.FAILED },
  
  { from: OperationState.FAILED, to: OperationState.RESPONDED },
];

/**
 * Check if a state transition is valid.
 */
export function isValidTransition(from: OperationState, to: OperationState): boolean {
  return VALID_TRANSITIONS.some(t => t.from === from && t.to === to);
}

/**
 * Create a new operation context.
 */
export function createOperationContext(
  id: string,
  intentHash: string,
  requestData?: Record<string, unknown>
): OperationContext {
  return {
    id,
    state: OperationState.RECEIVED,
    intentHash,
    timestamps: {
      [OperationState.RECEIVED]: Date.now(),
    },
    requestData,
  };
}

/**
 * Transition an operation to a new state.
 * Throws if transition is invalid.
 */
export function transitionState(
  ctx: OperationContext,
  to: OperationState
): OperationContext {
  if (!isValidTransition(ctx.state, to)) {
    throw new Error(
      `Invalid state transition: ${ctx.state} -> ${to} for operation ${ctx.id}`
    );
  }
  
  return {
    ...ctx,
    state: to,
    timestamps: {
      ...ctx.timestamps,
      [to]: Date.now(),
    },
  };
}

/**
 * Final response structure for an operation.
 */
export type OperationResponse = {
  success: boolean;
  operationId: string;
  
  // Policy
  policyAllowed?: boolean;
  policyDenialReason?: number;
  receiptObjectId?: string;
  
  // Custody
  custodyStatus?: CustodyStatus;
  custodyCompliant?: boolean;
  custodyEventObjectId?: string;
  
  // Signature
  signatureHex?: string;
  signId?: string;
  
  // Broadcast
  txHash?: string;
  blockNumber?: number;
  
  // Error
  error?: string;
  errorCode?: string;
};

/**
 * Convert operation context to response.
 */
export function contextToResponse(ctx: OperationContext): OperationResponse {
  const success = ctx.state === OperationState.RESPONDED && !ctx.error;
  
  return {
    success,
    operationId: ctx.id,
    
    policyAllowed: ctx.policyResult?.allowed,
    policyDenialReason: ctx.policyResult?.denialReason,
    receiptObjectId: ctx.policyResult?.receiptObjectId,
    
    custodyStatus: ctx.custodyResult?.status,
    custodyCompliant: ctx.custodyResult?.compliant,
    custodyEventObjectId: ctx.custodyResult?.custodyEventObjectId,
    
    signatureHex: ctx.signatureResult?.signatureHex,
    signId: ctx.signatureResult?.signId,
    
    txHash: ctx.broadcastResult?.txHash,
    blockNumber: ctx.broadcastResult?.blockNumber,
    
    error: ctx.error?.message,
    errorCode: ctx.error?.code,
  };
}
