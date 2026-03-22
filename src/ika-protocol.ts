/**
 * Ika Protocol helpers -- wraps @ika.xyz/sdk internals into clean functions.
 *
 * All Ika-specific crypto runs on the caller's machine (agent/client).
 * The agent's secret share never leaves this process.
 */

import {
  prepareDKG,
  UserShareEncryptionKeys,
  createRandomSessionIdentifier,
  createUserSignMessageWithPublicOutput,
  Curve,
  Hash,
  IkaClient,
  getNetworkConfig,
  SignatureAlgorithm,
} from "@ika.xyz/sdk";
import { SuiClient } from "@mysten/sui/client";
import { randomBytes } from "node:crypto";

export type SupportedCurve = "secp256k1" | "ed25519";

function resolveCurve(curve: SupportedCurve): Curve {
  return curve === "ed25519" ? Curve.ED25519 : Curve.SECP256K1;
}

// Protocol params are large (~MB). Cache per curve to avoid refetching.
const paramsCache = new Map<string, Uint8Array>();

// Reuse a single initialized Ika client per (network + RPC URL) to avoid
// repeated initialize() bursts that can trigger upstream rate limits.
const clientCache = new Map<
  string,
  {
    ikaClient: IkaClient;
    ready: Promise<void>;
  }
>();

function getClientCacheKey(network: "testnet" | "mainnet", suiRpcUrl: string): string {
  return `${network}:${suiRpcUrl}`;
}

function getOrCreateIkaClient(
  network: "testnet" | "mainnet",
  suiRpcUrl: string,
): {
  ikaClient: IkaClient;
  ready: Promise<void>;
} {
  const key = getClientCacheKey(network, suiRpcUrl);
  const cached = clientCache.get(key);
  if (cached) return cached;

  const suiClient = new SuiClient({ url: suiRpcUrl });
  const ikaConfig = getNetworkConfig(network);
  const ikaClient = new IkaClient({ suiClient, config: ikaConfig });
  const ready = ikaClient.initialize().catch((err) => {
    clientCache.delete(key);
    throw err;
  });

  const created = { ikaClient, ready };
  clientCache.set(key, created);
  return created;
}

/**
 * Fetch Ika protocol public parameters for a given curve.
 * Uses the IkaClient which reads from the Ika coordinator on Sui.
 */
export async function fetchProtocolParams(
  curve: SupportedCurve,
  suiRpcUrl: string,
  network: "testnet" | "mainnet" = "testnet",
): Promise<Uint8Array> {
  const ikaCurve = resolveCurve(curve);
  const paramsCacheKey = `${getClientCacheKey(network, suiRpcUrl)}:${ikaCurve}`;
  const cached = paramsCache.get(paramsCacheKey);
  if (cached) return cached;

  const { ikaClient, ready } = getOrCreateIkaClient(network, suiRpcUrl);
  await ready;

  // First arg is dWallet (undefined for new wallets), second is curve
  const params = await ikaClient.getProtocolPublicParameters(undefined, ikaCurve);
  paramsCache.set(paramsCacheKey, params);
  return params;
}

/**
 * Derive encryption keys from a random seed (replaces browser wallet signature).
 */
export async function deriveEncryptionKeys(
  seed: Uint8Array,
  curve: SupportedCurve,
): Promise<UserShareEncryptionKeys> {
  return UserShareEncryptionKeys.fromRootSeedKey(seed, resolveCurve(curve));
}

/**
 * Generate a random 32-byte seed for encryption key derivation.
 */
export function generateSeed(): Uint8Array {
  return new Uint8Array(randomBytes(32));
}

export interface DKGOutputs {
  userPublicOutput: number[];
  userSecretKeyShare: number[];
  userDKGMessage: number[];
  encryptedUserShareAndProof: number[];
}

/**
 * Run the client-side DKG computation.
 * This generates the user's share of the dWallet key pair.
 */
export async function runDKG(params: {
  protocolPublicParameters: Uint8Array;
  curve: SupportedCurve;
  encryptionKey: Uint8Array;
  sessionIdentifier: Uint8Array;
  adminAddress: string;
}): Promise<DKGOutputs> {
  const ikaCurve = resolveCurve(params.curve);
  const result = await prepareDKG(
    params.protocolPublicParameters,
    ikaCurve,
    params.encryptionKey,
    params.sessionIdentifier,
    params.adminAddress,
  );

  return {
    userPublicOutput: Array.from(result.userPublicOutput),
    userSecretKeyShare: Array.from(result.userSecretKeyShare),
    userDKGMessage: Array.from(result.userDKGMessage),
    encryptedUserShareAndProof: Array.from(result.encryptedUserShareAndProof),
  };
}

/**
 * Generate a fresh random session identifier (32 bytes).
 */
export function generateSessionIdentifier(): Uint8Array {
  return createRandomSessionIdentifier();
}

/**
 * Compute the user output signature needed to activate a dWallet.
 * Requires the dWallet object (fetched from chain) and the user's public output.
 */
export async function computeUserOutputSignature(params: {
  encryptionKeys: UserShareEncryptionKeys;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dWallet: any;
  userPublicOutput: Uint8Array;
}): Promise<Uint8Array> {
  return params.encryptionKeys.getUserOutputSignature(
    params.dWallet,
    params.userPublicOutput,
  );
}

/**
 * Fetch the dWallet object from Ika network for activation.
 */
export async function fetchDWallet(
  suiRpcUrl: string,
  network: "testnet" | "mainnet",
  dwalletId: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> {
  const { ikaClient, ready } = getOrCreateIkaClient(network, suiRpcUrl);
  await ready;
  return ikaClient.getDWallet(dwalletId);
}

/**
 * Poll until the dWallet reaches `targetState` using the Ika SDK's native
 * getDWalletInParticularState, which handles reindexing/lag gracefully.
 */
export async function waitForDWalletState(
  suiRpcUrl: string,
  network: "testnet" | "mainnet",
  dwalletId: string,
  targetState: "AwaitingKeyHolderSignature" | "Active",
  opts?: { timeout?: number; interval?: number },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> {
  const { ikaClient, ready } = getOrCreateIkaClient(network, suiRpcUrl);
  await ready;
  return ikaClient.getDWalletInParticularState(dwalletId, targetState, {
    timeout: opts?.timeout ?? 90_000,
    interval: opts?.interval ?? 3_000,
  });
}

export interface ComputeUserSignMessageParams {
  protocolPublicParameters: Uint8Array;
  userPublicOutput: Uint8Array;
  userSecretKeyShare: Uint8Array;
  presignBytes: Uint8Array;
  message: Uint8Array;
  hash?: Hash;
  signatureAlgorithm?: SignatureAlgorithm;
  curve?: Curve;
}

/**
 * Build the user-side sign message used by IKA MPC signing.
 */
export async function computeUserSignMessage(
  params: ComputeUserSignMessageParams,
): Promise<Uint8Array> {
  return createUserSignMessageWithPublicOutput(
    params.protocolPublicParameters,
    params.userPublicOutput,
    params.userSecretKeyShare,
    params.presignBytes,
    params.message,
    params.hash ?? Hash.KECCAK256,
    params.signatureAlgorithm ?? SignatureAlgorithm.ECDSASecp256k1,
    params.curve ?? Curve.SECP256K1,
  );
}

/**
 * Decode presign bytes from common backend/network payload formats.
 */
export function decodePresignBytes(value: unknown): Uint8Array {
  const decoded = coerceBytes(value);
  if (!decoded) {
    throw new Error("Invalid presign bytes format");
  }
  return decoded;
}

/**
 * Decode and validate presign result objects returned by polling APIs.
 */
export function decodePresignResult(value: {
  presignId?: string;
  presignBytes?: unknown;
}): { presignId: string; presignBytes: Uint8Array } {
  if (!value.presignId) {
    throw new Error("Missing presignId");
  }
  return {
    presignId: value.presignId,
    presignBytes: decodePresignBytes(value.presignBytes),
  };
}

function coerceBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
    return Uint8Array.from(v as number[]);
  }
  if (typeof v === "string") {
    if (/^0x[0-9a-fA-F]*$/.test(v)) {
      const raw = v.slice(2);
      if (raw.length % 2 !== 0) return null;
      const out = new Uint8Array(raw.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    return base64ToBytes(v);
  }
  if (v && typeof v === "object") {
    const obj = v as Record<string, unknown>;
    if (typeof obj.bytes === "string") return coerceBytes(obj.bytes);
    if (typeof obj.data === "string") return coerceBytes(obj.data);
    if (typeof obj.value === "string") return coerceBytes(obj.value);
    if (Array.isArray(obj.bytes)) return coerceBytes(obj.bytes);
    if (Array.isArray(obj.data)) return coerceBytes(obj.data);
    if (Array.isArray(obj.value)) return coerceBytes(obj.value);
  }
  return null;
}

function base64ToBytes(s: string): Uint8Array | null {
  try {
    const buf = Buffer.from(s, "base64");
    if (buf.length === 0 && s.length > 0) return null;
    return Uint8Array.from(buf);
  } catch {
    return null;
  }
}

export { Curve, resolveCurve };
