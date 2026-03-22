/**
 * Solana Chain Connector
 *
 * Implements the ChainConnector interface for Solana.
 * Handles transaction parsing, signature injection, and broadcasting.
 */

import { sha256 } from "@noble/hashes/sha256";
import bs58 from "bs58";
import { logger } from "../../logger.js";
import {
  type ChainConnector,
  type ParsedTransaction,
  type TxParams,
  type BroadcastResult,
  type SolanaInstruction,
  ChainNamespace,
  Curve,
  SignatureAlgorithm,
  type SolanaCluster,
} from "../types.js";
import { getSolanaNetworkConfig, getSolanaRpcUrl, type SolanaNetworkConfig } from "./config.js";
import { SYSTEM_PROGRAM_ID, getProgramName } from "./programs.js";

/**
 * Solana message header.
 */
interface MessageHeader {
  numRequiredSignatures: number;
  numReadonlySignedAccounts: number;
  numReadonlyUnsignedAccounts: number;
}

/**
 * Compiled instruction.
 */
interface CompiledInstruction {
  programIdIndex: number;
  accountKeyIndexes: number[];
  data: Uint8Array;
}

/**
 * Parsed Solana message.
 */
interface ParsedMessage {
  header: MessageHeader;
  accountKeys: string[];
  recentBlockhash: string;
  instructions: CompiledInstruction[];
  addressTableLookups?: AddressTableLookup[];
}

/**
 * Address table lookup.
 */
interface AddressTableLookup {
  accountKey: string;
  writableIndexes: number[];
  readonlyIndexes: number[];
}

/**
 * Solana connector implementation.
 */
export class SolanaConnector implements ChainConnector {
  readonly namespace = ChainNamespace.SOLANA;
  readonly curve = Curve.ED25519;
  readonly signatureAlgorithm = SignatureAlgorithm.ED25519;

  private config: SolanaNetworkConfig;
  private rpcUrl: string;

  constructor(
    readonly chainId: SolanaCluster,
    customRpcUrl?: string
  ) {
    this.config = getSolanaNetworkConfig(chainId);
    this.rpcUrl = getSolanaRpcUrl(chainId, customRpcUrl);
  }

  /**
   * Parse a Solana transaction and extract policy-relevant fields.
   */
  async parseTransaction(rawTx: Uint8Array | string): Promise<ParsedTransaction> {
    const txBytes = typeof rawTx === "string" ? bs58.decode(rawTx) : rawTx;

    // Parse the transaction structure
    const { message, signatureCount } = this.parseTransactionBytes(txBytes);

    // Compute intent hash (message bytes hash)
    const messageBytes = this.serializeMessage(message);
    const intentHash = sha256(messageBytes);

    // Extract instructions
    const instructions: SolanaInstruction[] = message.instructions.map((ix) => ({
      programId: message.accountKeys[ix.programIdIndex],
      accounts: ix.accountKeyIndexes.map((i) => message.accountKeys[i]),
      data: ix.data,
    }));

    // Extract unique program IDs
    const programIds = [...new Set(instructions.map((ix) => ix.programId))];

    // Extract destinations and amounts from System Program transfers
    const { destinations, amounts } = this.extractTransfers(message, instructions);

    return {
      namespace: this.namespace,
      chainId: this.chainId,
      destinations,
      amounts,
      intentHash,
      rawBytes: txBytes,
      from: message.accountKeys[0], // First signer is the fee payer
      sol: {
        programIds,
        instructions,
        recentBlockhash: message.recentBlockhash,
      },
    };
  }

  /**
   * Extract the canonical Solana message bytes for signing.
   * This is the payload that should be signed by the fee payer (first required signer).
   */
  getMessageBytes(rawTx: Uint8Array | string): Uint8Array {
    const txBytes = typeof rawTx === "string" ? bs58.decode(rawTx) : rawTx;
    const { message } = this.parseTransactionBytes(txBytes);
    return this.serializeMessage(message);
  }

  /**
   * Parse transaction bytes into message structure.
   */
  private parseTransactionBytes(bytes: Uint8Array): {
    message: ParsedMessage;
    signatureCount: number;
  } {
    let offset = 0;

    // Read signature count (compact-u16)
    const { value: signatureCount, bytesRead } = this.readCompactU16(bytes, offset);
    offset += bytesRead;

    // Skip signatures (each is 64 bytes)
    offset += signatureCount * 64;

    // Parse message
    const message = this.parseMessage(bytes.slice(offset));

    return { message, signatureCount };
  }

  /**
   * Parse message bytes.
   */
  private parseMessage(bytes: Uint8Array): ParsedMessage {
    let offset = 0;

    // Check for versioned transaction
    const prefix = bytes[0];
    let isVersioned = false;
    if ((prefix & 0x80) !== 0) {
      // Versioned transaction (v0)
      isVersioned = true;
      offset += 1;
    }

    // Header
    const header: MessageHeader = {
      numRequiredSignatures: bytes[offset++],
      numReadonlySignedAccounts: bytes[offset++],
      numReadonlyUnsignedAccounts: bytes[offset++],
    };

    // Account keys
    const { value: numAccountKeys, bytesRead: accountKeysBytes } = this.readCompactU16(
      bytes,
      offset
    );
    offset += accountKeysBytes;

    const accountKeys: string[] = [];
    for (let i = 0; i < numAccountKeys; i++) {
      const pubkey = bytes.slice(offset, offset + 32);
      accountKeys.push(bs58.encode(pubkey));
      offset += 32;
    }

    // Recent blockhash
    const recentBlockhash = bs58.encode(bytes.slice(offset, offset + 32));
    offset += 32;

    // Instructions
    const { value: numInstructions, bytesRead: instructionsBytes } = this.readCompactU16(
      bytes,
      offset
    );
    offset += instructionsBytes;

    const instructions: CompiledInstruction[] = [];
    for (let i = 0; i < numInstructions; i++) {
      const programIdIndex = bytes[offset++];

      const { value: numAccounts, bytesRead: accountsBytes } = this.readCompactU16(bytes, offset);
      offset += accountsBytes;

      const accountKeyIndexes: number[] = [];
      for (let j = 0; j < numAccounts; j++) {
        accountKeyIndexes.push(bytes[offset++]);
      }

      const { value: dataLen, bytesRead: dataLenBytes } = this.readCompactU16(bytes, offset);
      offset += dataLenBytes;

      const data = bytes.slice(offset, offset + dataLen);
      offset += dataLen;

      instructions.push({ programIdIndex, accountKeyIndexes, data });
    }

    // Address table lookups (for versioned transactions)
    let addressTableLookups: AddressTableLookup[] | undefined;
    if (isVersioned && offset < bytes.length) {
      const { value: numLookups, bytesRead: lookupsBytes } = this.readCompactU16(bytes, offset);
      offset += lookupsBytes;

      addressTableLookups = [];
      for (let i = 0; i < numLookups; i++) {
        const accountKey = bs58.encode(bytes.slice(offset, offset + 32));
        offset += 32;

        const { value: numWritable, bytesRead: writableBytes } = this.readCompactU16(bytes, offset);
        offset += writableBytes;
        const writableIndexes: number[] = [];
        for (let j = 0; j < numWritable; j++) {
          writableIndexes.push(bytes[offset++]);
        }

        const { value: numReadonly, bytesRead: readonlyBytes } = this.readCompactU16(bytes, offset);
        offset += readonlyBytes;
        const readonlyIndexes: number[] = [];
        for (let j = 0; j < numReadonly; j++) {
          readonlyIndexes.push(bytes[offset++]);
        }

        addressTableLookups.push({ accountKey, writableIndexes, readonlyIndexes });
      }
    }

    return { header, accountKeys, recentBlockhash, instructions, addressTableLookups };
  }

  /**
   * Serialize message for signing.
   */
  private serializeMessage(message: ParsedMessage): Uint8Array {
    const parts: Uint8Array[] = [];

    // Header
    parts.push(
      new Uint8Array([
        message.header.numRequiredSignatures,
        message.header.numReadonlySignedAccounts,
        message.header.numReadonlyUnsignedAccounts,
      ])
    );

    // Account keys
    parts.push(this.writeCompactU16(message.accountKeys.length));
    for (const key of message.accountKeys) {
      parts.push(bs58.decode(key));
    }

    // Recent blockhash
    parts.push(bs58.decode(message.recentBlockhash));

    // Instructions
    parts.push(this.writeCompactU16(message.instructions.length));
    for (const ix of message.instructions) {
      parts.push(new Uint8Array([ix.programIdIndex]));
      parts.push(this.writeCompactU16(ix.accountKeyIndexes.length));
      parts.push(new Uint8Array(ix.accountKeyIndexes));
      parts.push(this.writeCompactU16(ix.data.length));
      parts.push(ix.data);
    }

    return this.concatBytes(...parts);
  }

  /**
   * Extract transfer destinations and amounts from System Program instructions.
   */
  private extractTransfers(
    message: ParsedMessage,
    instructions: SolanaInstruction[]
  ): { destinations: string[]; amounts: bigint[] } {
    const destinations: string[] = [];
    const amounts: bigint[] = [];

    for (const ix of instructions) {
      if (ix.programId === SYSTEM_PROGRAM_ID && ix.data.length >= 12) {
        // System Program Transfer instruction
        const instructionType = this.readU32LE(ix.data, 0);
        if (instructionType === 2) {
          // Transfer
          const lamports = this.readU64LE(ix.data, 4);
          const destination = ix.accounts[1]; // Second account is destination
          destinations.push(destination);
          amounts.push(lamports);
        }
      }
    }

    return { destinations, amounts };
  }

  /**
   * Read compact-u16 (1-3 bytes).
   */
  private readCompactU16(
    bytes: Uint8Array,
    offset: number
  ): { value: number; bytesRead: number } {
    let value = 0;
    let bytesRead = 0;

    for (let i = 0; i < 3; i++) {
      const byte = bytes[offset + i];
      value |= (byte & 0x7f) << (7 * i);
      bytesRead++;
      if ((byte & 0x80) === 0) {
        break;
      }
    }

    return { value, bytesRead };
  }

  /**
   * Write compact-u16.
   */
  private writeCompactU16(value: number): Uint8Array {
    const bytes: number[] = [];
    let v = value;

    while (v >= 0x80) {
      bytes.push((v & 0x7f) | 0x80);
      v >>= 7;
    }
    bytes.push(v);

    return new Uint8Array(bytes);
  }

  /**
   * Read u32 little-endian.
   */
  private readU32LE(bytes: Uint8Array, offset: number): number {
    return (
      bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)
    ) >>> 0;
  }

  /**
   * Read u64 little-endian as bigint.
   */
  private readU64LE(bytes: Uint8Array, offset: number): bigint {
    const low = this.readU32LE(bytes, offset);
    const high = this.readU32LE(bytes, offset + 4);
    return BigInt(low) | (BigInt(high) << 32n);
  }

  /**
   * Concatenate byte arrays.
   */
  private concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  /**
   * Compute intent hash.
   */
  computeIntentHash(parsedTx: ParsedTransaction): Uint8Array {
    return parsedTx.intentHash;
  }

  /**
   * Derive Solana address from Ed25519 public key.
   */
  deriveAddress(publicKey: Uint8Array, _options?: Record<string, unknown>): string {
    if (publicKey.length !== 32) {
      throw new Error(`Invalid Ed25519 public key length: ${publicKey.length}`);
    }
    return bs58.encode(publicKey);
  }

  /**
   * Format Ed25519 signature.
   * Ed25519 signatures are 64 bytes and don't need formatting.
   */
  formatSignature(rawSig: Uint8Array, _parsedTx: ParsedTransaction): Uint8Array {
    if (rawSig.length !== 64) {
      throw new Error(`Invalid Ed25519 signature length: ${rawSig.length}`);
    }
    return rawSig;
  }

  /**
   * Inject signature into transaction.
   */
  injectSignature(parsedTx: ParsedTransaction, signature: Uint8Array): Uint8Array {
    const txBytes = parsedTx.rawBytes;

    // Read signature count
    const { value: signatureCount, bytesRead } = this.readCompactU16(txBytes, 0);

    // Create new transaction with signature injected
    // The first signature slot is for the fee payer (first signer)
    const signedTx = new Uint8Array(txBytes.length);
    signedTx.set(txBytes);

    // Inject signature at the first signature position
    signedTx.set(signature, bytesRead);

    return signedTx;
  }

  /**
   * Broadcast transaction to Solana network.
   */
  async broadcast(signedTx: Uint8Array): Promise<BroadcastResult> {
    try {
      const encodedTx = bs58.encode(signedTx);

      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "sendTransaction",
          params: [
            encodedTx,
            {
              encoding: "base58",
              skipPreflight: false,
              preflightCommitment: "confirmed",
            },
          ],
        }),
      });

      const result = await response.json();

      if (result.error) {
        logger.error({ error: result.error }, "Solana RPC error");
        return {
          success: false,
          txHash: "",
          error: result.error.message || JSON.stringify(result.error),
        };
      }

      const signature = result.result;
      logger.info({ signature, cluster: this.chainId }, "Solana transaction broadcast successful");

      // Wait for confirmation
      const confirmed = await this.confirmTransaction(signature);

      return {
        success: true,
        txHash: signature,
        blockNumber: confirmed.slot,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error({ error }, "Failed to broadcast Solana transaction");
      return { success: false, txHash: "", error: message };
    }
  }

  /**
   * Confirm transaction.
   */
  private async confirmTransaction(
    signature: string,
    maxRetries = 30
  ): Promise<{ slot: number }> {
    for (let i = 0; i < maxRetries; i++) {
      const response = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getSignatureStatuses",
          params: [[signature]],
        }),
      });

      const result = await response.json();
      const status = result.result?.value?.[0];

      if (status) {
        if (status.err) {
          throw new Error(`Transaction failed: ${JSON.stringify(status.err)}`);
        }
        if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") {
          return { slot: status.slot };
        }
      }

      // Wait before retrying
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    throw new Error("Transaction confirmation timeout");
  }

  /**
   * Get transaction parameters (recent blockhash, priority fee).
   */
  async getTxParams(address: string): Promise<TxParams> {
    try {
      // Get recent blockhash
      const blockhashResponse = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getLatestBlockhash",
          params: [{ commitment: "confirmed" }],
        }),
      });

      const blockhashResult = await blockhashResponse.json();
      const recentBlockhash = blockhashResult.result?.value?.blockhash;

      // Get priority fee estimate
      const feeResponse = await fetch(this.rpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "getRecentPrioritizationFees",
          params: [],
        }),
      });

      const feeResult = await feeResponse.json();
      const fees = feeResult.result || [];

      // Calculate median priority fee
      const priorityFees = fees
        .map((f: { prioritizationFee: number }) => f.prioritizationFee)
        .filter((f: number) => f > 0)
        .sort((a: number, b: number) => a - b);

      const medianFee = priorityFees.length > 0
        ? priorityFees[Math.floor(priorityFees.length / 2)]
        : 0;

      return {
        fee: {
          suggested: String(medianFee || 1000), // micro-lamports per compute unit
          minimum: "0",
          maximum: String(Math.max(medianFee * 2, 10000)),
        },
        recentBlockhash,
      };
    } catch (error) {
      logger.warn({ error }, "Failed to get Solana tx params");
      return {
        fee: {
          suggested: "1000",
          minimum: "0",
          maximum: "10000",
        },
      };
    }
  }

  /**
   * Validate a Solana address.
   */
  validateAddress(address: string): boolean {
    try {
      const decoded = bs58.decode(address);
      return decoded.length === 32;
    } catch {
      return false;
    }
  }
}

/**
 * Create a Solana connector for the specified cluster.
 */
export function createSolanaConnector(
  cluster: SolanaCluster,
  customRpcUrl?: string
): SolanaConnector {
  return new SolanaConnector(cluster, customRpcUrl);
}
