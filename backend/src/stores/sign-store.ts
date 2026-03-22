/**
 * Sign Request Store
 * 
 * Manages in-memory storage for MPC sign requests.
 */

import type { SignRequest, SignRequestInput } from "../types.js";
import { InMemoryRequestStore } from "./request-store.js";

/**
 * Create a new sign request from input data.
 */
export function createSignRequest(id: string, data: SignRequestInput): SignRequest {
  return {
    id,
    status: "pending",
    data,
    createdAt: new Date(),
  };
}

/**
 * Sign Request Store singleton.
 */
export const signStore = new InMemoryRequestStore<SignRequest>("sign");

/**
 * Type-safe result setter for sign completion.
 */
export function completeSignRequest(
  id: string,
  results: {
    signatureHex: string;
    signId: string;
    digest: string;
    ethTxHash?: string;
    ethBlockNumber?: number;
  }
): boolean {
  return signStore.markCompleted(id, results);
}
