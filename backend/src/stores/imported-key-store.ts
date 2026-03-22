/**
 * Imported Key Request Stores
 * 
 * Manages in-memory storage for imported key verification and signing requests.
 */

import type {
  ImportedKeyVerifyRequest,
  ImportedKeyVerifySubmitInput,
  ImportedKeySignRequest,
  ImportedKeySignRequestInput,
} from "../types.js";
import { InMemoryRequestStore } from "./request-store.js";

// ============================================================
// Imported Key Verification Store
// ============================================================

/**
 * Create a new imported key verification request.
 */
export function createImportedVerifyRequest(
  id: string,
  data: ImportedKeyVerifySubmitInput
): ImportedKeyVerifyRequest {
  return {
    id,
    status: "pending",
    data,
    createdAt: new Date(),
  };
}

/**
 * Imported Key Verification Store singleton.
 */
export const importedVerifyStore = new InMemoryRequestStore<ImportedKeyVerifyRequest>(
  "imported-verify"
);

/**
 * Type-safe result setter for imported key verification completion.
 */
export function completeImportedVerifyRequest(
  id: string,
  results: {
    dWalletCapObjectId: string;
    dWalletObjectId: string;
    encryptedUserSecretKeyShareId: string | null;
    ethereumAddress: string;
    digest: string;
  }
): boolean {
  return importedVerifyStore.markCompleted(id, results);
}

// ============================================================
// Imported Key Sign Store
// ============================================================

/**
 * Create a new imported key sign request.
 */
export function createImportedSignRequest(
  id: string,
  data: ImportedKeySignRequestInput
): ImportedKeySignRequest {
  return {
    id,
    status: "pending",
    data,
    createdAt: new Date(),
  };
}

/**
 * Imported Key Sign Store singleton.
 */
export const importedSignStore = new InMemoryRequestStore<ImportedKeySignRequest>(
  "imported-sign"
);

/**
 * Type-safe result setter for imported key sign completion.
 */
export function completeImportedSignRequest(
  id: string,
  results: {
    signatureHex: string;
    signId: string;
    digest: string;
    ethTxHash?: string;
    ethBlockNumber?: number;
  }
): boolean {
  return importedSignStore.markCompleted(id, results);
}
