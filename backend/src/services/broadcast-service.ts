/**
 * Broadcast Service - Handles EVM transaction broadcasting
 *
 * Responsible for:
 * - Broadcasting signed transactions to EVM chains
 * - Getting transaction parameters (nonce, gas prices)
 * - Signature recovery for proper yParity detection
 */

import {
  serializeTransaction,
  type TransactionSerializableEIP1559,
  type Hex,
  recoverTransactionAddress,
} from "viem";
import { logger } from "../logger.js";
import { getEvmChainName, getEvmPublicClient } from "../evm-chains.js";
import { withTimeout, TIMEOUTS } from "./utils.js";
import type { IBroadcastService, SignOperationInput } from "../coordinator/operation-coordinator.js";
import type { BroadcastResult } from "../types/operation-lifecycle.js";

/**
 * EVM transaction parameters
 */
export interface EvmTxParams {
  nonce: number;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  gasLimit: string;
}

/**
 * Broadcast result from EVM chain
 */
export interface BroadcastResultInternal {
  txHash: string;
  blockNumber: number;
}

/**
 * Broadcast Service handles EVM transaction broadcasting.
 */
export class BroadcastService implements IBroadcastService {
  /**
   * Broadcast a signed transaction to an EVM chain.
   * Implements IBroadcastService interface.
   */
  async broadcastEvm(params: {
    ethTx: NonNullable<SignOperationInput["ethTx"]>;
    signatureBytes: Uint8Array;
  }): Promise<BroadcastResult> {
    try {
      const result = await this.broadcastToEthereum(params.ethTx, params.signatureBytes);
      return {
        success: true,
        txHash: result.txHash,
        blockNumber: result.blockNumber,
        chainId: params.ethTx.chainId,
      };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
        chainId: params.ethTx.chainId,
      };
    }
  }

  /**
   * Broadcast a signed transaction to the requested EVM chain.
   *
   * @param ethTx - Transaction parameters (must match what was signed)
   * @param signatureBytes - Raw signature bytes (r || s, 64 bytes)
   * @returns Transaction hash and block number
   */
  async broadcastToEthereum(
    ethTx: {
      to: string;
      value: string;
      nonce: number;
      gasLimit: string;
      maxFeePerGas: string;
      maxPriorityFeePerGas: string;
      chainId: number;
      from: string;
    },
    signatureBytes: Uint8Array
  ): Promise<BroadcastResultInternal> {
    const chainId = Number(ethTx.chainId);
    const chainName = getEvmChainName(chainId);
    const ethClient = getEvmPublicClient(chainId);

    // Use the EXACT values from ethTx that were signed by the frontend
    // Do NOT fetch fresh nonce/gas - the signature was computed over these specific values
    logger.info(
      {
        from: ethTx.from,
        nonce: ethTx.nonce,
        maxFeePerGas: ethTx.maxFeePerGas,
        maxPriorityFeePerGas: ethTx.maxPriorityFeePerGas,
        chainId: ethTx.chainId,
      },
      "Using signed transaction values for broadcast"
    );

    // Parse signature (r, s from ECDSA signature)
    // Format: r[32-byte]-s[32-byte] (no v/recovery ID from Ika)
    const r = `0x${Buffer.from(signatureBytes.slice(0, 32)).toString("hex")}` as Hex;
    const s = `0x${Buffer.from(signatureBytes.slice(32, 64)).toString("hex")}` as Hex;

    // Create the transaction object with the EXACT values that were signed
    const unsignedTx: TransactionSerializableEIP1559 = {
      type: "eip1559",
      chainId: ethTx.chainId,
      nonce: ethTx.nonce,
      to: ethTx.to as Hex,
      value: BigInt(ethTx.value),
      maxFeePerGas: BigInt(ethTx.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(ethTx.maxPriorityFeePerGas),
      gas: BigInt(ethTx.gasLimit),
    };

    // Fail fast with a clear error if the sender doesn't have enough ETH
    const balanceWei = await ethClient.getBalance({ address: ethTx.from as Hex });
    const valueWei = BigInt(ethTx.value);
    const maxGasCostWei = BigInt(ethTx.gasLimit) * BigInt(ethTx.maxFeePerGas);
    const requiredWei = valueWei + maxGasCostWei;
    if (balanceWei < requiredWei) {
      throw new Error(
        `Insufficient ETH to send. Need at least ${requiredWei.toString()} wei (value + max gas), have ${balanceWei.toString()} wei. Fund ${ethTx.from} on ${chainName} and retry.`
      );
    }

    // No recovery ID (v) from Ika - try both yParity values (0 and 1)
    // and use the one that recovers to the correct address
    let signedTx: Hex | null = null;
    for (const yParity of [0, 1] as const) {
      const candidateTx = serializeTransaction(unsignedTx, { r, s, yParity });
      try {
        const recoveredAddress = await recoverTransactionAddress({
          serializedTransaction: candidateTx,
        });
        if (recoveredAddress.toLowerCase() === ethTx.from.toLowerCase()) {
          signedTx = candidateTx;
          logger.info({ yParity }, "Found correct yParity for signature");
          break;
        }
      } catch {
        // This yParity didn't work, try the other
        continue;
      }
    }

    if (!signedTx) {
      throw new Error(
        "Failed to recover correct signer address with either yParity value"
      );
    }

    logger.info(
      {
        to: ethTx.to,
        value: ethTx.value,
        chainId: ethTx.chainId,
        nonce: ethTx.nonce,
        signedTxLength: signedTx.length,
      },
      `Broadcasting signed transaction to ${chainName}`
    );

    // Send the raw transaction
    const txHash = await ethClient.sendRawTransaction({
      serializedTransaction: signedTx,
    });

    // Wait for transaction receipt (with timeout)
    const receipt = await withTimeout(
      ethClient.waitForTransactionReceipt({
        hash: txHash,
        confirmations: 1,
      }),
      TIMEOUTS.ETH_RECEIPT_WAIT,
      "Ethereum transaction receipt"
    );

    return {
      txHash,
      blockNumber: Number(receipt.blockNumber),
    };
  }

  /**
   * Get Ethereum transaction parameters (nonce, gas prices) for an address.
   * Frontend calls this before signing to get actual values.
   *
   * @param address - The EVM address
   * @returns Transaction parameters
   */
  async getEthTxParams(address: string): Promise<EvmTxParams> {
    // Back-compat default (previously: Base Sepolia only)
    const chainId = 84532;
    return this.getEvmTxParams({ address, chainId });
  }

  /**
   * Get EVM transaction parameters for any supported chain.
   *
   * @param args.address - The EVM address
   * @param args.chainId - The chain ID
   * @returns Transaction parameters
   */
  async getEvmTxParams(args: { address: string; chainId: number }): Promise<EvmTxParams> {
    const { address, chainId } = args;
    const ethClient = getEvmPublicClient(chainId);
    const [nonce, feeData] = await Promise.all([
      ethClient.getTransactionCount({ address: address as Hex }),
      ethClient.estimateFeesPerGas(),
    ]);

    return {
      nonce,
      maxFeePerGas: (feeData.maxFeePerGas || BigInt("50000000000")).toString(),
      maxPriorityFeePerGas: (
        feeData.maxPriorityFeePerGas || BigInt("2000000000")
      ).toString(),
      gasLimit: "21000", // Standard ETH transfer
    };
  }
}
