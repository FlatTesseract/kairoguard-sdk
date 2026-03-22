import type { Hex } from "./types.js";
import { fetchAndValidatePolicyReceipt } from "./suiReceipts.js";

export type AuditBundle = {
  v: 1;
  network: "testnet" | "mainnet";
  // Minimal v1 bundle: receipt ids + expected commitments.
  receipts: Array<{
    receiptObjectId: string;
    expected: {
      policyId: string;
      policyVersion: string;
      evmChainId: number;
      intentHash: Hex;
      toEvm: Hex;
    };
  }>;
};

/**
 * Minimal verifier for an audit bundle (v1).
 * This intentionally verifies only receipt commitments using on-chain receipt contents.
 */
export async function verifyAuditBundle(args: {
  suiRpcUrl: string;
  bundle: AuditBundle;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  try {
    for (const r of args.bundle.receipts) {
      await fetchAndValidatePolicyReceipt({
        suiRpcUrl: args.suiRpcUrl,
        receiptObjectId: r.receiptObjectId,
        expected: r.expected,
      });
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

