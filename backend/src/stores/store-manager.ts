/**
 * Store Manager
 * 
 * Central manager for all request stores.
 * Handles cleanup, monitoring, and diagnostics across all stores.
 */

import { dkgStore } from "./dkg-store.js";
import { presignStore } from "./presign-store.js";
import { signStore } from "./sign-store.js";
import { importedVerifyStore, importedSignStore } from "./imported-key-store.js";
import type { IRequestStore, BaseRequest } from "./request-store.js";

/**
 * All registered stores.
 */
const stores: IRequestStore<BaseRequest>[] = [
  dkgStore as IRequestStore<BaseRequest>,
  presignStore as IRequestStore<BaseRequest>,
  signStore as IRequestStore<BaseRequest>,
  importedVerifyStore as IRequestStore<BaseRequest>,
  importedSignStore as IRequestStore<BaseRequest>,
];

/**
 * Run cleanup on all stores.
 * @returns Total number of requests cleaned up
 */
export function cleanupAllStores(): number {
  let total = 0;
  for (const store of stores) {
    total += store.cleanup();
  }
  return total;
}

/**
 * Get diagnostics for all stores.
 */
export function getStoreDiagnostics(): {
  name: string;
  total: number;
  pending: number;
  processing: number;
  completed: number;
  failed: number;
}[] {
  return stores.map(store => {
    const values = Array.from(store.values());
    return {
      name: (store as any).getName?.() ?? "unknown",
      total: store.size(),
      pending: values.filter(r => r.status === "pending").length,
      processing: values.filter(r => r.status === "processing").length,
      completed: values.filter(r => r.status === "completed").length,
      failed: values.filter(r => r.status === "failed").length,
    };
  });
}

/**
 * Export all requests for monitoring/debugging.
 */
export function exportAllRequests(): {
  kind: string;
  id: string;
  status: string;
  createdAtMs: number;
  error?: string;
  [key: string]: unknown;
}[] {
  const out: any[] = [];

  for (const r of dkgStore.values()) {
    out.push({
      kind: "dkg",
      id: r.id,
      status: r.status,
      createdAtMs: r.createdAt.getTime(),
      dWalletCapObjectId: r.dWalletCapObjectId,
      dWalletObjectId: r.dWalletObjectId,
      ethereumAddress: r.ethereumAddress,
      error: r.error,
    });
  }

  for (const r of importedVerifyStore.values()) {
    out.push({
      kind: "imported_verify",
      id: r.id,
      status: r.status,
      createdAtMs: r.createdAt.getTime(),
      dWalletCapObjectId: r.dWalletCapObjectId,
      dWalletObjectId: r.dWalletObjectId,
      ethereumAddress: r.ethereumAddress,
      expectedEvmAddress: r.data.expectedEvmAddress,
      error: r.error,
    });
  }

  for (const r of presignStore.values()) {
    out.push({
      kind: "presign",
      id: r.id,
      status: r.status,
      createdAtMs: r.createdAt.getTime(),
      dWalletId: r.dWalletId,
      error: r.error,
    });
  }

  for (const r of signStore.values()) {
    out.push({
      kind: "sign",
      id: r.id,
      status: r.status,
      createdAtMs: r.createdAt.getTime(),
      dWalletId: r.data.dWalletId,
      signatureHex: r.signatureHex,
      ethTxHash: r.ethTxHash,
      error: r.error,
    });
  }

  for (const r of importedSignStore.values()) {
    out.push({
      kind: "imported_sign",
      id: r.id,
      status: r.status,
      createdAtMs: r.createdAt.getTime(),
      dWalletId: r.data.dWalletId,
      signatureHex: r.signatureHex,
      ethTxHash: r.ethTxHash,
      error: r.error,
    });
  }

  return out;
}

/**
 * Clear all stores (for testing).
 */
export function clearAllStores(): void {
  for (const store of stores) {
    store.clear();
  }
}
