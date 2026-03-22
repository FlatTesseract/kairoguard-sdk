/**
 * Solana Network Configuration
 *
 * Network parameters for mainnet-beta, devnet, and testnet.
 */

import type { SolanaCluster } from "../types.js";

/**
 * Solana network configuration.
 */
export interface SolanaNetworkConfig {
  /** Cluster identifier */
  cluster: SolanaCluster;
  /** Display name */
  name: string;
  /** RPC endpoint */
  rpcUrl: string;
  /** WebSocket endpoint */
  wsUrl?: string;
  /** Explorer URL template */
  explorerUrl?: string;
}

/**
 * Solana mainnet-beta configuration.
 */
export const SOLANA_MAINNET: SolanaNetworkConfig = {
  cluster: "mainnet-beta",
  name: "Mainnet Beta",
  rpcUrl: "https://api.mainnet-beta.solana.com",
  wsUrl: "wss://api.mainnet-beta.solana.com",
  explorerUrl: "https://explorer.solana.com",
};

/**
 * Solana devnet configuration.
 */
export const SOLANA_DEVNET: SolanaNetworkConfig = {
  cluster: "devnet",
  name: "Devnet",
  rpcUrl: "https://api.devnet.solana.com",
  wsUrl: "wss://api.devnet.solana.com",
  explorerUrl: "https://explorer.solana.com?cluster=devnet",
};

/**
 * Solana testnet configuration.
 */
export const SOLANA_TESTNET: SolanaNetworkConfig = {
  cluster: "testnet",
  name: "Testnet",
  rpcUrl: "https://api.testnet.solana.com",
  wsUrl: "wss://api.testnet.solana.com",
  explorerUrl: "https://explorer.solana.com?cluster=testnet",
};

/**
 * Get network config by cluster name.
 */
export function getSolanaNetworkConfig(cluster: SolanaCluster): SolanaNetworkConfig {
  switch (cluster) {
    case "mainnet-beta":
      return SOLANA_MAINNET;
    case "devnet":
      return SOLANA_DEVNET;
    case "testnet":
      return SOLANA_TESTNET;
    default:
      throw new Error(`Unknown Solana cluster: ${cluster}`);
  }
}

/**
 * Supported Solana clusters.
 */
export const SUPPORTED_SOLANA_CLUSTERS: SolanaCluster[] = [
  "mainnet-beta",
  "devnet",
  "testnet",
];

/**
 * Check if a cluster is supported.
 */
export function isSupportedSolanaCluster(cluster: string): cluster is SolanaCluster {
  return SUPPORTED_SOLANA_CLUSTERS.includes(cluster as SolanaCluster);
}

/**
 * Get RPC URL with optional custom endpoint.
 */
export function getSolanaRpcUrl(cluster: SolanaCluster, customUrl?: string): string {
  if (customUrl) return customUrl;
  return getSolanaNetworkConfig(cluster).rpcUrl;
}

/**
 * Lamports per SOL.
 */
export const LAMPORTS_PER_SOL = 1_000_000_000n;

/**
 * Convert SOL to lamports.
 */
export function solToLamports(sol: number): bigint {
  return BigInt(Math.floor(sol * Number(LAMPORTS_PER_SOL)));
}

/**
 * Convert lamports to SOL.
 */
export function lamportsToSol(lamports: bigint): number {
  return Number(lamports) / Number(LAMPORTS_PER_SOL);
}
