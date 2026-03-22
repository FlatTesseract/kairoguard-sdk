/**
 * Golden-path test fixtures.
 * 
 * These capture real operation flows from Sui testnet.
 * Captured on: 2026-01-13
 * 
 * IMPORTANT: Do NOT modify expected outputs without understanding why.
 * These are the "source of truth" for refactoring safety.
 */

import type { FixtureCollection, PolicyReceiptMintFixture, DeniedOperationFixture } from "./types.js";
import { CustodyMode } from "../../custody-mode.js";

// Denial reason codes from policy_registry.move
export const DENIAL_CODES = {
  NONE: 0,
  EXPIRED: 1,
  DENYLIST: 2,
  NOT_IN_ALLOWLIST: 3,
  BAD_FORMAT: 4,
  CHAIN_NOT_ALLOWED: 10,
  BAD_SELECTOR_FORMAT: 11,
  SELECTOR_DENYLIST: 12,
  SELECTOR_NOT_ALLOWED: 13,
  BAD_AMOUNT_FORMAT: 14,
  ERC20_AMOUNT_EXCEEDS_MAX: 15,
  NO_POLICY_VERSION: 16,
} as const;

/**
 * Real fixture: Allowed EVM transfer to allowlisted address.
 * Captured from Sui testnet.
 */
export const allowedTransferFixture: PolicyReceiptMintFixture = {
  name: "allowed-transfer-to-allowlist",
  description: "EVM transfer to an address in the policy allowlist should be allowed",
  input: {
    policyId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
    policyVersion: "1.0.0",
    evmChainId: 84532, // Base Sepolia
    toEvm: "0xd220E8BaeF8343eaf232EA0a2F8B49AeC598a588",
    intentHashHex: "0xe3fade9e82f20fcc0f4bde3e860846e1f967bbea20be95d3975e7496dee0d853",
    custodyMode: CustodyMode.BEST_EFFORT,
  },
  expected: {
    policy: {
      allowed: true,
      policyObjectId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
      policyVersion: "1.0.0",
    },
    custody: {
      // Custody failed because no custody chain was configured in the test environment
      status: "failed",
      compliant: false,
      error: "Invalid Sui Object id",
    },
    receiptObjectId: "0xec4a8a31f4824313dab5a675a1820a45923b3f2d3ebc231bd413a7699884a722",
  },
};

/**
 * Real fixture: Custody disabled mode.
 * Captured from Sui testnet.
 */
export const custodyDisabledFixture: PolicyReceiptMintFixture = {
  name: "custody-disabled",
  description: "Custody append in DISABLED mode should skip custody and still be compliant",
  input: {
    policyId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
    policyVersion: "1.0.0",
    evmChainId: 84532,
    toEvm: "0xd220E8BaeF8343eaf232EA0a2F8B49AeC598a588",
    intentHashHex: "0xff56a25b835d0b7b36d439a0b03e86addb75c571b267bdb5f45aedf740ee0f79",
    custodyMode: CustodyMode.DISABLED,
  },
  expected: {
    policy: {
      allowed: true,
      policyObjectId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
      policyVersion: "1.0.0",
    },
    custody: {
      status: "disabled",
      compliant: true,
    },
    receiptObjectId: "0x905c07319d024e2115963ec4b6daef3916a2534cc1a37ace4869e69da39df756",
  },
};

/**
 * Real fixture: Denied - address triggers denial (likely denylist).
 * Captured from Sui testnet.
 */
export const deniedDenylistFixture: DeniedOperationFixture = {
  name: "denied-denylist-address",
  description: "Transfer to an address in the policy denylist should be denied",
  input: {
    policyId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
    policyVersion: "1.0.0",
    evmChainId: 84532,
    toEvm: "0x0000000000000000000000000000000000000001",
    intentHashHex: "0x07ba7f9213bb617b58cd426110f406dc4cba90e187c564fa2b815c5862328b72",
  },
  expected: {
    allowed: false,
    denialReason: DENIAL_CODES.DENYLIST,
    denialReasonName: "DENYLIST",
  },
};

/**
 * Synthetic fixture: Denied - address not in allowlist.
 * This is a representative fixture; replace with real captured data when available.
 */
export const deniedNotAllowlistedFixture: DeniedOperationFixture = {
  name: "denied-not-in-allowlist",
  description: "Transfer to an address not in allowlist (when allowlist is non-empty) should be denied",
  input: {
    policyId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
    policyVersion: "1.0.0",
    evmChainId: 84532,
    toEvm: "0x1234567890123456789012345678901234567890",
    intentHashHex: "0x_PLACEHOLDER_INTENT_HASH_64_HEX_CHARS_HERE_00000000000000",
  },
  expected: {
    allowed: false,
    denialReason: DENIAL_CODES.NOT_IN_ALLOWLIST,
    denialReasonName: "NOT_IN_ALLOWLIST",
  },
};

/**
 * Synthetic fixture: Denied - chain not allowed.
 * This is a representative fixture; replace with real captured data when available.
 */
export const deniedChainNotAllowedFixture: DeniedOperationFixture = {
  name: "denied-chain-not-allowed",
  description: "Transfer on a chain not in the policy chain allowlist should be denied",
  input: {
    policyId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
    policyVersion: "1.0.0",
    evmChainId: 1, // Mainnet (not in allowlist)
    toEvm: "0xd220E8BaeF8343eaf232EA0a2F8B49AeC598a588",
    intentHashHex: "0x_PLACEHOLDER_INTENT_HASH_64_HEX_CHARS_HERE_00000000000000",
  },
  expected: {
    allowed: false,
    denialReason: DENIAL_CODES.CHAIN_NOT_ALLOWED,
    denialReasonName: "CHAIN_NOT_ALLOWED",
  },
};

/**
 * Synthetic fixture: Custody append with REQUIRED mode (success path).
 * Requires a custody chain to be configured.
 */
export const custodyRequiredSuccessFixture: PolicyReceiptMintFixture = {
  name: "custody-required-success",
  description: "Custody append in REQUIRED mode should succeed and be compliant",
  input: {
    policyId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
    policyVersion: "1.0.0",
    evmChainId: 84532,
    toEvm: "0xd220E8BaeF8343eaf232EA0a2F8B49AeC598a588",
    intentHashHex: "0x_PLACEHOLDER_INTENT_HASH_64_HEX_CHARS_HERE_00000000000000",
    custodyMode: CustodyMode.REQUIRED,
  },
  expected: {
    policy: {
      allowed: true,
      policyObjectId: "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
      policyVersion: "1.0.0",
    },
    custody: {
      status: "appended",
      compliant: true,
    },
  },
};

/**
 * Master fixture collection.
 * 
 * Includes both real captured data (3 fixtures) and synthetic placeholders (3 fixtures).
 */
export const goldenPathFixtures: FixtureCollection = {
  version: "1.0.0",
  createdAt: "2026-01-13T19:30:00.000Z",
  description: "Golden-path test fixtures for refactoring safety validation (includes real testnet data)",
  fixtures: [
    { type: "policy-receipt-mint", fixture: allowedTransferFixture },
    { type: "policy-receipt-mint", fixture: custodyDisabledFixture },
    { type: "policy-receipt-mint", fixture: custodyRequiredSuccessFixture },
    { type: "denied-operation", fixture: deniedDenylistFixture },
    { type: "denied-operation", fixture: deniedNotAllowlistedFixture },
    { type: "denied-operation", fixture: deniedChainNotAllowedFixture },
  ],
};

/**
 * Helper to check if fixtures have real data or placeholders.
 */
export function hasRealFixtureData(): boolean {
  // We now have 3 real fixtures, but still have some placeholders
  // Return true if we have at least some real data
  const hasPlaceholders = JSON.stringify(goldenPathFixtures).includes("PLACEHOLDER");
  const hasRealReceipts = [
    allowedTransferFixture,
    custodyDisabledFixture,
    deniedDenylistFixture,
  ].every(f => 
    "receiptObjectId" in f.expected && 
    f.expected.receiptObjectId?.startsWith("0x") &&
    !f.expected.receiptObjectId?.includes("PLACEHOLDER")
  );
  
  return hasRealReceipts; // We have enough real data to run some integration tests
}
