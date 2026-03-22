/**
 * DKG Request Store
 * 
 * Manages in-memory storage for DKG (Distributed Key Generation) requests.
 */

import type { DKGRequest, DKGSubmitInput } from "../types.js";
import { InMemoryRequestStore } from "./request-store.js";

/**
 * Create a new DKG request from input data.
 */
export function createDKGRequest(id: string, data: DKGSubmitInput): DKGRequest {
  return {
    id,
    status: "pending",
    data,
    createdAt: new Date(),
  };
}

/**
 * DKG Request Store singleton.
 */
export const dkgStore = new InMemoryRequestStore<DKGRequest>("dkg");

/**
 * Type-safe result setter for DKG completion.
 */
export function completeDKGRequest(
  id: string,
  results: {
    dWalletCapObjectId: string;
    dWalletObjectId: string;
    encryptedUserSecretKeyShareId: string | null;
    ethereumAddress: string;
    digest: string;
  }
): boolean {
  return dkgStore.markCompleted(id, results);
}
