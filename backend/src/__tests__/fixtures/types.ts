/**
 * Golden-path test fixture types.
 * 
 * These fixtures capture real operation flows to ensure refactoring
 * doesn't change security-critical behavior.
 */

import type { CustodyMode, CustodyStatus } from "../../custody-mode.js";

/**
 * Policy evaluation result expected from a fixture.
 */
export type PolicyExpectation = {
  allowed: boolean;
  denialReason?: number;
  policyObjectId: string;
  policyVersion: string;
};

/**
 * Custody operation result expected from a fixture.
 */
export type CustodyExpectation = {
  status: CustodyStatus;
  compliant: boolean;
  custodyEventObjectId?: string;
  error?: string;
};

/**
 * Signing result expected from a fixture.
 */
export type SigningExpectation = {
  success: boolean;
  signatureHex?: string;
  error?: string;
};

/**
 * Broadcast result expected from a fixture.
 */
export type BroadcastExpectation = {
  success: boolean;
  txHash?: string;
  blockNumber?: number;
  error?: string;
};

/**
 * Complete fixture for a policy receipt mint operation.
 */
export type PolicyReceiptMintFixture = {
  name: string;
  description: string;
  input: {
    policyId: string;
    policyVersion: string;
    evmChainId: number;
    toEvm: string;
    intentHashHex: string;
    evmSelectorHex?: string;
    erc20AmountHex?: string;
    custodyMode?: CustodyMode;
  };
  expected: {
    policy: PolicyExpectation;
    custody: CustodyExpectation;
    receiptObjectId?: string;
  };
};

/**
 * Complete fixture for a sign + broadcast operation.
 */
export type SignOperationFixture = {
  name: string;
  description: string;
  input: {
    dWalletId: string;
    dWalletCapId: string;
    presignId: string;
    messageHex: string;
    policyReceiptId: string;
    policyObjectId?: string;
    policyVersion?: string;
    custodyMode?: CustodyMode;
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
  expected: {
    policy: PolicyExpectation;
    signing: SigningExpectation;
    broadcast?: BroadcastExpectation;
    custody?: CustodyExpectation;
  };
};

/**
 * Fixture for a blocked (denied) operation.
 */
export type DeniedOperationFixture = {
  name: string;
  description: string;
  input: {
    policyId: string;
    policyVersion: string;
    evmChainId: number;
    toEvm: string;
    intentHashHex: string;
  };
  expected: {
    allowed: false;
    denialReason: number;
    denialReasonName: string;
  };
};

/**
 * All fixture types union.
 */
export type GoldenPathFixture =
  | { type: "policy-receipt-mint"; fixture: PolicyReceiptMintFixture }
  | { type: "sign-operation"; fixture: SignOperationFixture }
  | { type: "denied-operation"; fixture: DeniedOperationFixture };

/**
 * Fixture collection for the test harness.
 */
export type FixtureCollection = {
  version: string;
  createdAt: string;
  description: string;
  fixtures: GoldenPathFixture[];
};
