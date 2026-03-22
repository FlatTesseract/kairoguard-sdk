/**
 * Bitcoin Network Configuration
 *
 * Network parameters for mainnet, testnet, signet, and regtest.
 */

import type { BitcoinNetwork } from "../types.js";

/**
 * Bitcoin network configuration.
 */
export interface BitcoinNetworkConfig {
  /** Network identifier */
  network: BitcoinNetwork;
  /** Message prefix for signing */
  messagePrefix: string;
  /** Bech32 prefix */
  bech32: string;
  /** Bech32m prefix (Taproot) */
  bech32m: string;
  /** BIP32 version bytes */
  bip32: {
    public: number;
    private: number;
  };
  /** P2PKH version byte */
  pubKeyHash: number;
  /** P2SH version byte */
  scriptHash: number;
  /** WIF version byte */
  wif: number;
  /** Default API endpoints */
  apiEndpoints: {
    blockstream?: string;
    mempool?: string;
    electrum?: string;
  };
}

/**
 * Bitcoin mainnet configuration.
 */
export const BITCOIN_MAINNET: BitcoinNetworkConfig = {
  network: "mainnet",
  messagePrefix: "\x18Bitcoin Signed Message:\n",
  bech32: "bc",
  bech32m: "bc",
  bip32: {
    public: 0x0488b21e,
    private: 0x0488ade4,
  },
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
  apiEndpoints: {
    blockstream: "https://blockstream.info/api",
    mempool: "https://mempool.space/api",
  },
};

/**
 * Bitcoin testnet configuration.
 */
export const BITCOIN_TESTNET: BitcoinNetworkConfig = {
  network: "testnet",
  messagePrefix: "\x18Bitcoin Signed Message:\n",
  bech32: "tb",
  bech32m: "tb",
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
  apiEndpoints: {
    blockstream: "https://blockstream.info/testnet/api",
    mempool: "https://mempool.space/testnet/api",
  },
};

/**
 * Bitcoin signet configuration.
 */
export const BITCOIN_SIGNET: BitcoinNetworkConfig = {
  network: "signet",
  messagePrefix: "\x18Bitcoin Signed Message:\n",
  bech32: "tb",
  bech32m: "tb",
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
  apiEndpoints: {
    mempool: "https://mempool.space/signet/api",
  },
};

/**
 * Bitcoin regtest configuration.
 */
export const BITCOIN_REGTEST: BitcoinNetworkConfig = {
  network: "regtest",
  messagePrefix: "\x18Bitcoin Signed Message:\n",
  bech32: "bcrt",
  bech32m: "bcrt",
  bip32: {
    public: 0x043587cf,
    private: 0x04358394,
  },
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
  apiEndpoints: {},
};

/**
 * Get network config by name.
 */
export function getBitcoinNetworkConfig(network: BitcoinNetwork): BitcoinNetworkConfig {
  switch (network) {
    case "mainnet":
      return BITCOIN_MAINNET;
    case "testnet":
      return BITCOIN_TESTNET;
    case "signet":
      return BITCOIN_SIGNET;
    case "regtest":
      return BITCOIN_REGTEST;
    default:
      throw new Error(`Unknown Bitcoin network: ${network}`);
  }
}

/**
 * Supported Bitcoin networks.
 */
export const SUPPORTED_BITCOIN_NETWORKS: BitcoinNetwork[] = [
  "mainnet",
  "testnet",
  "signet",
  "regtest",
];

/**
 * Check if a network is supported.
 */
export function isSupportedBitcoinNetwork(network: string): network is BitcoinNetwork {
  return SUPPORTED_BITCOIN_NETWORKS.includes(network as BitcoinNetwork);
}

/**
 * Get API URL for broadcasting transactions.
 */
export function getBroadcastUrl(config: BitcoinNetworkConfig): string {
  if (config.apiEndpoints.blockstream) {
    return `${config.apiEndpoints.blockstream}/tx`;
  }
  if (config.apiEndpoints.mempool) {
    return `${config.apiEndpoints.mempool}/tx`;
  }
  throw new Error(`No broadcast endpoint configured for ${config.network}`);
}

/**
 * Get API URL for fetching fee estimates.
 */
export function getFeeEstimateUrl(config: BitcoinNetworkConfig): string {
  if (config.apiEndpoints.mempool) {
    return `${config.apiEndpoints.mempool}/v1/fees/recommended`;
  }
  if (config.apiEndpoints.blockstream) {
    return `${config.apiEndpoints.blockstream}/fee-estimates`;
  }
  throw new Error(`No fee estimate endpoint configured for ${config.network}`);
}

/**
 * Get API URL for fetching UTXO data.
 */
export function getUtxoUrl(config: BitcoinNetworkConfig, address: string): string {
  if (config.apiEndpoints.blockstream) {
    return `${config.apiEndpoints.blockstream}/address/${address}/utxo`;
  }
  if (config.apiEndpoints.mempool) {
    return `${config.apiEndpoints.mempool}/address/${address}/utxo`;
  }
  throw new Error(`No UTXO endpoint configured for ${config.network}`);
}

/**
 * Get API URL for fetching transaction hex.
 */
export function getTxHexUrl(config: BitcoinNetworkConfig, txid: string): string {
  if (config.apiEndpoints.blockstream) {
    return `${config.apiEndpoints.blockstream}/tx/${txid}/hex`;
  }
  if (config.apiEndpoints.mempool) {
    return `${config.apiEndpoints.mempool}/tx/${txid}/hex`;
  }
  throw new Error(`No transaction endpoint configured for ${config.network}`);
}
