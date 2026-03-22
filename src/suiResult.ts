import type { SuiTransactionBlockResponse } from "@mysten/sui/client";

/**
 * Extract created object IDs from a Sui transaction response.
 *
 * Wallet adapters differ in what they return; for hard-gating we want to reliably
 * recover the newly created `PolicyReceipt` object id.
 */
export function getCreatedObjectIds(result: SuiTransactionBlockResponse): string[] {
  const created = result.effects?.created ?? [];
  return created
    .map((c) => c.reference?.objectId)
    .filter((x): x is string => typeof x === "string" && x.length > 0);
}












