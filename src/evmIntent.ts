import { keccak256, toBytes, type Hex as ViemHex } from "viem";
import type { EvmChainId, EvmIntent, Hex } from "./types.js";

/**
 * Compute the EVM intent hash from the serialized unsigned tx bytes.
 *
 * In the reference ETH demo, the MPC signs over the raw serialized unsigned tx bytes,
 * and the hash scheme used for ECDSA is KECCAK256.
 */
export function computeEvmIntentFromUnsignedTxBytes(params: {
  chainId: EvmChainId;
  unsignedTxBytesHex: Hex; // 0x-prefixed hex bytes of serialized unsigned tx
}): EvmIntent {
  const bytes = toBytes(params.unsignedTxBytesHex as ViemHex);
  const intentHash = keccak256(bytes) as Hex;
  return { chainId: params.chainId, intentHash };
}












