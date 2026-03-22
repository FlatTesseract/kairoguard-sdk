#!/usr/bin/env bun
/**
 * Fixture Capture Script
 * 
 * Captures real request/response pairs from the running backend
 * to populate golden-path test fixtures.
 * 
 * USAGE:
 *   1. Start the backend: `bun run dev`
 *   2. Run this script: `bun run src/__tests__/fixtures/capture-fixtures.ts`
 *   3. Copy the output JSON to golden-paths.ts
 * 
 * REQUIREMENTS:
 *   - Backend running on localhost:3001
 *   - Valid policy ID and custody chain configured
 */

import { CustodyMode } from "../../custody-mode.js";
import type { PolicyReceiptMintFixture, DeniedOperationFixture } from "./types.js";

const BACKEND_URL = process.env.BACKEND_URL ?? "http://localhost:3001";

// Known test addresses for different scenarios
const TEST_DATA = {
  // Get these from your environment or previous runs
  policyId: process.env.TEST_POLICY_ID ?? "0xfc50a15eb602985c8295cc94993be79b09afec8daff604dd221c0918d57f287a",
  policyVersion: process.env.TEST_POLICY_VERSION ?? "1.0.0",
  policyBindingObjectId: process.env.TEST_POLICY_BINDING_ID,
  custodyChainObjectId: process.env.TEST_CUSTODY_CHAIN_ID,
  custodyPackageId: process.env.TEST_CUSTODY_PKG_ID,
  
  // EVM test data
  evmChainId: 84532, // Base Sepolia
  
  // Test addresses - replace with addresses in your policy's allowlist/denylist
  allowedAddress: process.env.TEST_ALLOWED_ADDRESS ?? "0xd220E8BaeF8343eaf232EA0a2F8B49AeC598a588",
  deniedAddress: process.env.TEST_DENIED_ADDRESS ?? "0x0000000000000000000000000000000000000001", // Usually denylisted
  unknownAddress: "0x1234567890123456789012345678901234567890", // Not in allowlist
};

// Generate a random intent hash
function randomIntentHash(): `0x${string}` {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("")}`;
}

// Call the mint receipt endpoint
async function mintReceipt(params: {
  policyId: string;
  policyVersion: string;
  evmChainId: number;
  toEvm: string;
  intentHashHex: string;
  custodyMode?: CustodyMode;
  policyBindingObjectId?: string;
  custodyChainObjectId?: string;
  custodyPackageId?: string;
}): Promise<{
  success: boolean;
  data?: any;
  error?: string;
}> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/policy/receipt/mint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    });
    
    const data = await response.json();
    return { success: response.ok, data };
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : String(err) };
  }
}

// Capture an allowed transfer fixture
async function captureAllowedTransfer(): Promise<PolicyReceiptMintFixture | null> {
  console.log("\n📝 Capturing: Allowed transfer to allowlisted address...");
  
  const intentHash = randomIntentHash();
  const result = await mintReceipt({
    policyId: TEST_DATA.policyId,
    policyVersion: TEST_DATA.policyVersion,
    evmChainId: TEST_DATA.evmChainId,
    toEvm: TEST_DATA.allowedAddress,
    intentHashHex: intentHash,
    custodyMode: CustodyMode.BEST_EFFORT,
    policyBindingObjectId: TEST_DATA.policyBindingObjectId,
    custodyChainObjectId: TEST_DATA.custodyChainObjectId,
    custodyPackageId: TEST_DATA.custodyPackageId,
  });
  
  if (!result.success || !result.data) {
    console.log("❌ Failed:", result.error ?? result.data?.error);
    return null;
  }
  
  const d = result.data;
  console.log("✅ Success! Receipt:", d.receiptObjectId);
  
  const fixture: PolicyReceiptMintFixture = {
    name: "allowed-transfer-to-allowlist",
    description: "EVM transfer to an address in the policy allowlist should be allowed",
    input: {
      policyId: TEST_DATA.policyId,
      policyVersion: TEST_DATA.policyVersion,
      evmChainId: TEST_DATA.evmChainId,
      toEvm: TEST_DATA.allowedAddress,
      intentHashHex: intentHash,
      custodyMode: CustodyMode.BEST_EFFORT,
    },
    expected: {
      policy: {
        allowed: true,
        policyObjectId: TEST_DATA.policyId,
        policyVersion: TEST_DATA.policyVersion,
      },
      custody: {
        status: d.custodyStatus,
        compliant: d.custodyCompliant,
        custodyEventObjectId: d.custodyEventObjectId,
        error: d.custodyAppendError,
      },
      receiptObjectId: d.receiptObjectId,
    },
  };
  
  return fixture;
}

// Capture a denied (denylist) fixture
async function captureDeniedDenylist(): Promise<DeniedOperationFixture | null> {
  console.log("\n📝 Capturing: Denied transfer to denylisted address...");
  
  const intentHash = randomIntentHash();
  const result = await mintReceipt({
    policyId: TEST_DATA.policyId,
    policyVersion: TEST_DATA.policyVersion,
    evmChainId: TEST_DATA.evmChainId,
    toEvm: TEST_DATA.deniedAddress,
    intentHashHex: intentHash,
    custodyMode: CustodyMode.BEST_EFFORT,
  });
  
  // Even denied mints may succeed (receipt is minted with denial_reason set)
  if (!result.success && !result.data?.receiptObjectId) {
    console.log("❌ Failed to mint (expected for denylist):", result.error ?? result.data?.error);
    // This might be expected if the policy rejects the transaction outright
    return null;
  }
  
  // Check if it's actually denied in the receipt
  const d = result.data;
  console.log("Receipt:", d.receiptObjectId, "Denial reason:", d.denialReason);
  
  if (d.denialReason === 0) {
    console.log("⚠️ Address was allowed, not denied. Check your denylist.");
    return null;
  }
  
  const fixture: DeniedOperationFixture = {
    name: "denied-denylist-address",
    description: "Transfer to an address in the policy denylist should be denied",
    input: {
      policyId: TEST_DATA.policyId,
      policyVersion: TEST_DATA.policyVersion,
      evmChainId: TEST_DATA.evmChainId,
      toEvm: TEST_DATA.deniedAddress,
      intentHashHex: intentHash,
    },
    expected: {
      allowed: false,
      denialReason: d.denialReason ?? 2,
      denialReasonName: "DENYLIST",
    },
  };
  
  return fixture;
}

// Capture custody required success
async function captureCustodyRequired(): Promise<PolicyReceiptMintFixture | null> {
  console.log("\n📝 Capturing: Custody REQUIRED mode success...");
  
  const intentHash = randomIntentHash();
  const result = await mintReceipt({
    policyId: TEST_DATA.policyId,
    policyVersion: TEST_DATA.policyVersion,
    evmChainId: TEST_DATA.evmChainId,
    toEvm: TEST_DATA.allowedAddress,
    intentHashHex: intentHash,
    custodyMode: CustodyMode.REQUIRED,
    policyBindingObjectId: TEST_DATA.policyBindingObjectId,
    custodyChainObjectId: TEST_DATA.custodyChainObjectId,
    custodyPackageId: TEST_DATA.custodyPackageId,
  });
  
  if (!result.success || !result.data) {
    console.log("❌ Failed (custody REQUIRED may fail if no chain):", result.error ?? result.data?.error);
    return null;
  }
  
  const d = result.data;
  console.log("✅ Success! Receipt:", d.receiptObjectId, "Custody:", d.custodyStatus);
  
  const fixture: PolicyReceiptMintFixture = {
    name: "custody-required-success",
    description: "Custody append in REQUIRED mode should succeed and be compliant",
    input: {
      policyId: TEST_DATA.policyId,
      policyVersion: TEST_DATA.policyVersion,
      evmChainId: TEST_DATA.evmChainId,
      toEvm: TEST_DATA.allowedAddress,
      intentHashHex: intentHash,
      custodyMode: CustodyMode.REQUIRED,
    },
    expected: {
      policy: {
        allowed: true,
        policyObjectId: TEST_DATA.policyId,
        policyVersion: TEST_DATA.policyVersion,
      },
      custody: {
        status: d.custodyStatus,
        compliant: d.custodyCompliant,
        custodyEventObjectId: d.custodyEventObjectId,
      },
      receiptObjectId: d.receiptObjectId,
    },
  };
  
  return fixture;
}

// Capture custody disabled
async function captureCustodyDisabled(): Promise<PolicyReceiptMintFixture | null> {
  console.log("\n📝 Capturing: Custody DISABLED mode...");
  
  const intentHash = randomIntentHash();
  const result = await mintReceipt({
    policyId: TEST_DATA.policyId,
    policyVersion: TEST_DATA.policyVersion,
    evmChainId: TEST_DATA.evmChainId,
    toEvm: TEST_DATA.allowedAddress,
    intentHashHex: intentHash,
    custodyMode: CustodyMode.DISABLED,
  });
  
  if (!result.success || !result.data) {
    console.log("❌ Failed:", result.error ?? result.data?.error);
    return null;
  }
  
  const d = result.data;
  console.log("✅ Success! Receipt:", d.receiptObjectId, "Custody status:", d.custodyStatus);
  
  const fixture: PolicyReceiptMintFixture = {
    name: "custody-disabled",
    description: "Custody append in DISABLED mode should skip custody and still be compliant",
    input: {
      policyId: TEST_DATA.policyId,
      policyVersion: TEST_DATA.policyVersion,
      evmChainId: TEST_DATA.evmChainId,
      toEvm: TEST_DATA.allowedAddress,
      intentHashHex: intentHash,
      custodyMode: CustodyMode.DISABLED,
    },
    expected: {
      policy: {
        allowed: true,
        policyObjectId: TEST_DATA.policyId,
        policyVersion: TEST_DATA.policyVersion,
      },
      custody: {
        status: "disabled",
        compliant: true,
      },
      receiptObjectId: d.receiptObjectId,
    },
  };
  
  return fixture;
}

// Main capture flow
async function main() {
  console.log("🔧 Fixture Capture Script");
  console.log("========================");
  console.log(`Backend URL: ${BACKEND_URL}`);
  console.log(`Policy ID: ${TEST_DATA.policyId}`);
  console.log(`Allowed Address: ${TEST_DATA.allowedAddress}`);
  console.log("");
  
  // Check backend health
  try {
    const health = await fetch(`${BACKEND_URL}/health`);
    if (!health.ok) throw new Error("Backend not healthy");
    console.log("✅ Backend is running\n");
  } catch {
    console.error("❌ Backend not available at", BACKEND_URL);
    console.error("   Start it with: bun run dev");
    process.exit(1);
  }
  
  const fixtures: (PolicyReceiptMintFixture | DeniedOperationFixture)[] = [];
  
  // Capture all scenarios
  const allowed = await captureAllowedTransfer();
  if (allowed) fixtures.push(allowed);
  
  const custodyRequired = await captureCustodyRequired();
  if (custodyRequired) fixtures.push(custodyRequired);
  
  const custodyDisabled = await captureCustodyDisabled();
  if (custodyDisabled) fixtures.push(custodyDisabled);
  
  const denied = await captureDeniedDenylist();
  if (denied) fixtures.push(denied);
  
  // Output
  console.log("\n\n========== CAPTURED FIXTURES ==========");
  console.log(JSON.stringify(fixtures, null, 2));
  console.log("========================================\n");
  
  console.log(`✅ Captured ${fixtures.length} fixtures`);
  console.log("Copy the JSON above to golden-paths.ts");
}

main().catch(console.error);
