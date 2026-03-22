import { Transaction } from "@mysten/sui/transactions";
import type { Hex, KairoPolicyId } from "./types.js";

/**
 * Build a Sui Transaction that calls the Move policy engine to mint a hard-gating receipt.
 *
 * You can have the user sign this tx with their Sui wallet, then pass the resulting receipt object id
 * into the EVM signing flow.
 */
export function buildMintEvmReceiptTx(params: {
  packageId: string; // published package address
  policyObjectId: KairoPolicyId;
  evmChainId: number;
  intentHash: Hex; // 0x + 32 bytes
  toEvm: Hex; // 0x + 20 bytes
}): Transaction {
  const tx = new Transaction();

  const intentBytes = hexToBytes(params.intentHash, 32);
  const toBytes = hexToBytes(params.toEvm, 20);

  tx.moveCall({
    // Use *_to_sender to avoid UnusedValueWithoutDrop in Sui PTB semantics.
    // This function transfers the created PolicyReceipt to the tx sender and returns its id (droppable).
    target: `${params.packageId}::policy_registry::mint_receipt_evm_to_sender`,
    arguments: [
      tx.object(params.policyObjectId),
      tx.object("0x6"), // Clock object (standard)
      tx.pure.u64(BigInt(params.evmChainId)),
      tx.pure.vector("u8", [...intentBytes]),
      tx.pure.vector("u8", [...toBytes]),
    ],
  });

  // The receipt is returned as a newly created object; callers should inspect execution effects
  // and extract the created object id of type `PolicyReceipt`.
  return tx;
}

function hexToBytes(hex: Hex, expectedLen: number): Uint8Array {
  const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (raw.length !== expectedLen * 2) {
    throw new Error(`Expected ${expectedLen} bytes, got ${raw.length / 2}`);
  }
  const out = new Uint8Array(expectedLen);
  for (let i = 0; i < expectedLen; i++) {
    out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}












