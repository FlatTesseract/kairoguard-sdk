/**
 * Presign Request Store
 * 
 * Manages in-memory storage for MPC presign requests.
 */

import type { PresignRequest } from "../types.js";
import { InMemoryRequestStore } from "./request-store.js";

/**
 * Input for creating a presign request.
 */
export type PresignRequestInput = {
  dWalletId: string;
  encryptedUserSecretKeyShareId: string;
  userOutputSignature: number[];
};

/**
 * Create a new presign request from input data.
 */
export function createPresignRequest(id: string, input: PresignRequestInput): PresignRequest {
  return {
    id,
    status: "pending",
    dWalletId: input.dWalletId,
    encryptedUserSecretKeyShareId: input.encryptedUserSecretKeyShareId,
    userOutputSignature: input.userOutputSignature,
    createdAt: new Date(),
  };
}

/**
 * Presign Request Store singleton.
 */
export const presignStore = new InMemoryRequestStore<PresignRequest>("presign");

/**
 * Type-safe result setter for presign completion.
 */
export function completePresignRequest(
  id: string,
  results: {
    presignId: string;
    presignBytes?: number[];
  }
): boolean {
  return presignStore.markCompleted(id, results);
}
