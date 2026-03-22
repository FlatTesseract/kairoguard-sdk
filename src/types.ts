export type Hex = `0x${string}`;
export type EvmChainId = number;

export type KairoPolicyId = string;
export type KairoPolicyReceiptId = string;

export interface EvmIntent {
  chainId: EvmChainId;
  /**
   * Keccak256 hash of the unsigned tx bytes (EIP-1559 serialized unsigned tx).
   * 32 bytes, hex with 0x prefix.
   */
  intentHash: Hex;
}

export interface PolicyReceiptCommitment {
  policyId: KairoPolicyId;
  policyVersion: string;
  evmChainId: EvmChainId;
  intentHash: Hex;
  /**
   * Optional EVM destination address if the policy checks destination gating.
   * 20 bytes, hex with 0x prefix.
   */
  to?: Hex;
}

/**
 * Expected commitment for PolicyReceiptV2.
 *
 * Note:
 * - `policyId` remains the on-chain *policy object id* (receipt field: `policy_object_id`).
 * - `policyStableId` is the human-readable stable id (receipt field: `policy_stable_id`).
 * - Selector/amount are optional and depend on the policy + intent.
 */
export interface PolicyReceiptV2Commitment extends PolicyReceiptCommitment {
  policyStableId?: string;
  policyRoot?: Hex; // 32 bytes
  policyVersionId?: string; // Sui object id (0x...)
  evmSelector?: Hex; // 4 bytes
  erc20Amount?: Hex; // 32 bytes
}
