/**
 * Multi-Chain Connector Types
 *
 * Unified interface for Bitcoin, Solana, and EVM chain connectors.
 * Each connector implements chain-specific transaction parsing, signing, and broadcasting
 * while sharing the core policy verification and custody tracking infrastructure.
 */

import type { Hex } from "viem";

/**
 * Chain namespace identifiers matching the Move custody_ledger constants.
 */
export enum ChainNamespace {
  EVM = 1,
  BITCOIN = 2,
  SOLANA = 3,
}

/**
 * Bitcoin script types for address derivation and signing.
 */
export enum BitcoinScriptType {
  P2PKH = 0, // Legacy Pay-to-Public-Key-Hash
  P2WPKH = 1, // Native SegWit (bech32)
  P2TR = 2, // Taproot (bech32m)
}

/**
 * Bitcoin network identifiers.
 */
export type BitcoinNetwork = "mainnet" | "testnet" | "signet" | "regtest";

/**
 * Solana cluster identifiers.
 */
export type SolanaCluster = "mainnet-beta" | "devnet" | "testnet";

/**
 * Unified chain identifier.
 */
export type ChainId = number | string;

/**
 * Bitcoin UTXO (Unspent Transaction Output).
 */
export interface BitcoinUTXO {
  txid: string;
  vout: number;
  value: bigint;
  scriptPubKey: Uint8Array;
  witnessUtxo?: {
    script: Uint8Array;
    value: bigint;
  };
}

/**
 * Solana instruction representation.
 */
export interface SolanaInstruction {
  programId: string;
  accounts: string[];
  data: Uint8Array;
}

/**
 * Chain-specific transaction extras.
 */
export interface BitcoinTxExtras {
  utxos: BitcoinUTXO[];
  scriptType: BitcoinScriptType;
  feeRate?: number; // sat/vByte
  locktime?: number;
}

export interface SolanaTxExtras {
  programIds: string[];
  instructions: SolanaInstruction[];
  recentBlockhash?: string;
}

export interface EvmTxExtras {
  selector?: Hex;
  data?: Hex;
  gasLimit?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
}

/**
 * Parsed transaction with policy-relevant fields.
 */
export interface ParsedTransaction {
  /** Chain namespace (EVM, Bitcoin, Solana) */
  namespace: ChainNamespace;
  /** Chain-specific identifier (chainId for EVM, network for BTC, cluster for SOL) */
  chainId: ChainId;
  /** Recipient addresses in chain-native format */
  destinations: string[];
  /** Amounts per destination in smallest unit (wei, satoshi, lamports) */
  amounts: bigint[];
  /** 32-byte intent hash for signing */
  intentHash: Uint8Array;
  /** Raw transaction bytes */
  rawBytes: Uint8Array;
  /** Sender address */
  from?: string;
  /** Chain-specific extras */
  btc?: BitcoinTxExtras;
  sol?: SolanaTxExtras;
  evm?: EvmTxExtras;
}

/**
 * Transaction parameters for fee estimation.
 */
export interface TxParams {
  /** Suggested fee/gas parameters */
  fee: {
    /** For Bitcoin: sat/vByte, For EVM: maxFeePerGas, For Solana: priorityFee */
    suggested: string;
    /** Minimum acceptable fee */
    minimum?: string;
    /** Maximum recommended fee */
    maximum?: string;
  };
  /** For EVM: current nonce */
  nonce?: number;
  /** For Solana: recent blockhash */
  recentBlockhash?: string;
}

/**
 * Broadcast result from chain.
 */
export interface BroadcastResult {
  success: boolean;
  /** Transaction hash/signature */
  txHash: string;
  /** Block number/slot (if confirmed) */
  blockNumber?: number;
  /** Error message if failed */
  error?: string;
}

/**
 * Cryptographic curve for dWallet.
 */
export enum Curve {
  SECP256K1 = 0,
  ED25519 = 2,
}

/**
 * Signature algorithm.
 */
export enum SignatureAlgorithm {
  ECDSA = 0,
  SCHNORR = 1,
  ED25519 = 2,
}

/**
 * Chain connector interface.
 * Each chain (EVM, Bitcoin, Solana) implements this interface.
 */
export interface ChainConnector {
  /** Chain namespace identifier */
  readonly namespace: ChainNamespace;
  /** Chain-specific identifier */
  readonly chainId: ChainId;
  /** Cryptographic curve used by this chain */
  readonly curve: Curve;
  /** Signature algorithm used by this chain */
  readonly signatureAlgorithm: SignatureAlgorithm;

  /**
   * Parse raw transaction and extract policy-relevant fields.
   * @param rawTx - Raw transaction bytes or hex string
   * @returns Parsed transaction with destinations, amounts, intent hash
   */
  parseTransaction(rawTx: Uint8Array | string): Promise<ParsedTransaction>;

  /**
   * Compute intent hash for signing.
   * @param parsedTx - Parsed transaction
   * @returns 32-byte intent hash
   */
  computeIntentHash(parsedTx: ParsedTransaction): Uint8Array;

  /**
   * Derive address from public key.
   * @param publicKey - Public key bytes
   * @param options - Chain-specific options (e.g., script type for Bitcoin)
   * @returns Address in chain-native format
   */
  deriveAddress(publicKey: Uint8Array, options?: Record<string, unknown>): string;

  /**
   * Format raw signature for broadcast.
   * @param rawSig - Raw signature bytes from MPC
   * @param parsedTx - Parsed transaction
   * @returns Formatted signature bytes ready for injection
   */
  formatSignature(rawSig: Uint8Array, parsedTx: ParsedTransaction): Uint8Array;

  /**
   * Inject signature into transaction and return signed transaction.
   * @param parsedTx - Parsed transaction
   * @param signature - Formatted signature
   * @returns Signed transaction bytes
   */
  injectSignature(parsedTx: ParsedTransaction, signature: Uint8Array): Uint8Array;

  /**
   * Broadcast signed transaction to the network.
   * @param signedTx - Signed transaction bytes
   * @returns Broadcast result with transaction hash
   */
  broadcast(signedTx: Uint8Array): Promise<BroadcastResult>;

  /**
   * Get current transaction parameters (fees, nonce, blockhash).
   * @param address - Sender address
   * @returns Transaction parameters
   */
  getTxParams(address: string): Promise<TxParams>;

  /**
   * Validate an address for this chain.
   * @param address - Address to validate
   * @returns True if valid
   */
  validateAddress(address: string): boolean;
}

/**
 * Policy receipt mint parameters (chain-agnostic).
 */
export interface PolicyReceiptMintParams {
  /** Chain namespace */
  namespace: ChainNamespace;
  /** Chain-specific identifier */
  chainId: ChainId;
  /** Policy object ID on Sui */
  policyId: string;
  /** Policy version string */
  policyVersion: string;
  /** 32-byte intent hash */
  intentHash: Uint8Array;
  /** Destination addresses (chain-native format, converted to bytes) */
  destinations: Uint8Array[];
  /** Bitcoin-specific: script type */
  btcScriptType?: BitcoinScriptType;
  /** Solana-specific: program IDs involved */
  solProgramIds?: Uint8Array[];
  /** EVM-specific: function selector */
  evmSelector?: Uint8Array;
  /** EVM-specific: ERC20 amount */
  erc20Amount?: Uint8Array;
}

/**
 * Custody event append parameters (chain-agnostic).
 */
export interface CustodyEventParams {
  /** Chain namespace */
  namespace: ChainNamespace;
  /** Chain-specific identifier */
  chainId: ChainId;
  /** Policy receipt object ID */
  receiptObjectId: string;
  /** Policy object ID */
  policyObjectId: string;
  /** 32-byte intent hash */
  intentHash: Uint8Array;
  /** Destination address (first destination, converted to bytes) */
  toAddr: Uint8Array;
  /** Transaction hash on source chain */
  srcTxHash: Uint8Array;
  /** Event kind (transfer, mint, etc.) */
  kind: CustodyEventKind;
  /** Optional payload */
  payload?: Uint8Array;
}

/**
 * Custody event kinds matching Move constants.
 */
export enum CustodyEventKind {
  MINT = 1,
  TRANSFER = 2,
  BURN = 3,
  LOCK = 4,
  UNLOCK = 5,
  POLICY_CHECKPOINT = 6,
}

/**
 * Registry of chain connectors.
 */
export interface ChainConnectorRegistry {
  /**
   * Get connector for a specific chain.
   * @param namespace - Chain namespace
   * @param chainId - Chain-specific identifier
   * @returns Chain connector or undefined
   */
  getConnector(namespace: ChainNamespace, chainId: ChainId): ChainConnector | undefined;

  /**
   * Register a chain connector.
   * @param connector - Chain connector to register
   */
  registerConnector(connector: ChainConnector): void;

  /**
   * List all registered connectors.
   * @returns Array of registered connectors
   */
  listConnectors(): ChainConnector[];
}

/**
 * Helper to convert chain namespace to string.
 */
export function namespaceToString(namespace: ChainNamespace): string {
  switch (namespace) {
    case ChainNamespace.EVM:
      return "evm";
    case ChainNamespace.BITCOIN:
      return "bitcoin";
    case ChainNamespace.SOLANA:
      return "solana";
    default:
      return `unknown-${namespace}`;
  }
}

/**
 * Helper to parse namespace from string.
 */
export function parseNamespace(str: string): ChainNamespace | null {
  switch (str.toLowerCase()) {
    case "evm":
    case "ethereum":
      return ChainNamespace.EVM;
    case "bitcoin":
    case "btc":
      return ChainNamespace.BITCOIN;
    case "solana":
    case "sol":
      return ChainNamespace.SOLANA;
    default:
      return null;
  }
}

/**
 * Helper to get curve for namespace.
 */
export function getCurveForNamespace(namespace: ChainNamespace): Curve {
  switch (namespace) {
    case ChainNamespace.EVM:
    case ChainNamespace.BITCOIN:
      return Curve.SECP256K1;
    case ChainNamespace.SOLANA:
      return Curve.ED25519;
    default:
      throw new Error(`Unknown namespace: ${namespace}`);
  }
}

/**
 * Helper to get signature algorithm for namespace.
 */
export function getSignatureAlgorithmForNamespace(
  namespace: ChainNamespace,
  options?: { btcScriptType?: BitcoinScriptType }
): SignatureAlgorithm {
  switch (namespace) {
    case ChainNamespace.EVM:
      return SignatureAlgorithm.ECDSA;
    case ChainNamespace.BITCOIN:
      // Taproot uses Schnorr, others use ECDSA
      if (options?.btcScriptType === BitcoinScriptType.P2TR) {
        return SignatureAlgorithm.SCHNORR;
      }
      return SignatureAlgorithm.ECDSA;
    case ChainNamespace.SOLANA:
      return SignatureAlgorithm.ED25519;
    default:
      throw new Error(`Unknown namespace: ${namespace}`);
  }
}
