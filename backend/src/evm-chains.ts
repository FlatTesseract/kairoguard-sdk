import { createPublicClient, http, type PublicClient } from "viem";
import {
  arbitrumSepolia,
  baseSepolia,
  optimismSepolia,
  sepolia,
  type Chain,
} from "viem/chains";

export type SupportedEvmChainId = 84532 | 11155111 | 11155420 | 421614;

export type EvmChainConfig = {
  chain: Chain;
  /** Public RPC fallback; prefer env overrides in production. */
  defaultRpcUrl: string;
};

export const SUPPORTED_EVM_CHAINS: Record<SupportedEvmChainId, EvmChainConfig> = {
  84532: {
    chain: baseSepolia,
    defaultRpcUrl:
      baseSepolia.rpcUrls.default.http[0] ?? "https://sepolia.base.org",
  },
  11155111: {
    chain: sepolia,
    defaultRpcUrl:
      sepolia.rpcUrls.default.http[0] ?? "https://rpc.sepolia.org",
  },
  11155420: {
    chain: optimismSepolia,
    defaultRpcUrl:
      optimismSepolia.rpcUrls.default.http[0] ?? "https://sepolia.optimism.io",
  },
  421614: {
    chain: arbitrumSepolia,
    defaultRpcUrl:
      arbitrumSepolia.rpcUrls.default.http[0] ??
      "https://sepolia-rollup.arbitrum.io/rpc",
  },
} as const;

export function isSupportedEvmChainId(
  v: number
): v is SupportedEvmChainId {
  return Object.prototype.hasOwnProperty.call(SUPPORTED_EVM_CHAINS, v);
}

export function getEvmChainConfigOrThrow(chainId: number): EvmChainConfig {
  if (!Number.isFinite(chainId)) throw new Error("Invalid chainId");
  const id = Math.floor(chainId);
  if (!isSupportedEvmChainId(id)) {
    throw new Error(
      `Unsupported EVM chainId=${chainId}. Supported: ${Object.keys(SUPPORTED_EVM_CHAINS).join(
        ", "
      )}`
    );
  }
  return SUPPORTED_EVM_CHAINS[id];
}

export function getEvmRpcUrl(chainId: number): string {
  const { defaultRpcUrl } = getEvmChainConfigOrThrow(chainId);
  const envKey = `EVM_RPC_${chainId}`;
  const override = process.env[envKey];
  return (override && override.trim()) || defaultRpcUrl;
}

const publicClientCache = new Map<number, PublicClient>();

export function getEvmPublicClient(chainId: number): PublicClient {
  const cached = publicClientCache.get(chainId);
  if (cached) return cached;

  const { chain } = getEvmChainConfigOrThrow(chainId);
  const client = createPublicClient({
    chain,
    transport: http(getEvmRpcUrl(chainId)),
  });
  publicClientCache.set(chainId, client);
  return client;
}

export function getEvmChainName(chainId: number): string {
  try {
    const { chain } = getEvmChainConfigOrThrow(chainId);
    return chain.name ?? `chainId=${chainId}`;
  } catch {
    return `chainId=${chainId}`;
  }
}

