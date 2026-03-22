/**
 * Shared utility functions for Kairo services
 *
 * Pure helper functions with no dependencies on service state.
 */

import { bcs } from "@mysten/sui/bcs";
import { toBytes } from "viem";
import { computeAddress } from "ethers";
import { bytesToHex } from "@noble/hashes/utils";

// ============================================================================
// Timeout utilities
// ============================================================================

/**
 * Operation timeouts (in milliseconds)
 */
export const TIMEOUTS = {
  TRANSACTION_WAIT: 60_000, // 60 seconds for transaction confirmation
  SIGN_WAIT: 120_000, // 2 minutes for signature from network
  PRESIGN_WAIT: 120_000, // 2 minutes for presign completion
  ETH_RECEIPT_WAIT: 60_000, // 60 seconds for ETH transaction receipt
} as const;

/**
 * Wrap a promise with a timeout.
 * Rejects with a descriptive error if the timeout is reached.
 *
 * @param promise - The promise to wrap
 * @param timeoutMs - Timeout in milliseconds
 * @param operation - Description of the operation (for error message)
 * @returns The resolved value of the promise
 * @throws Error if the timeout is reached
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)),
        timeoutMs
      )
    ),
  ]);
}

// ============================================================================
// Curve constants
// ============================================================================

/**
 * Curve constants for dWallet operations
 */
export const CURVE_SECP256K1 = 0; // For Ethereum, Bitcoin
export const CURVE_ED25519 = 2; // For Solana

/**
 * Signature algorithm constants
 */
export const SIGALG_ECDSA = 0;
export const SIGALG_SCHNORR = 1; // For Bitcoin Taproot
export const SIGALG_ED25519 = 2; // For Solana

// ============================================================================
// BCS schemas for Ika pricing
// ============================================================================

/**
 * Minimal BCS decoding for `ika_dwallet_2pc_mpc::pricing::PricingInfo`
 * Used for better error messages & coin selection.
 */
export const PricingInfoKeyBcs = bcs.struct("PricingInfoKey", {
  curve: bcs.u32(),
  signature_algorithm: bcs.option(bcs.u32()),
  protocol: bcs.u32(),
});

export const PricingInfoValueBcs = bcs.struct("PricingInfoValue", {
  fee_ika: bcs.u64(),
  gas_fee_reimbursement_sui: bcs.u64(),
  gas_fee_reimbursement_sui_for_system_calls: bcs.u64(),
});

export const PricingInfoEntryBcs = bcs.struct("VecMapEntry", {
  key: PricingInfoKeyBcs,
  value: PricingInfoValueBcs,
});

export const PricingInfoVecMapBcs = bcs.struct("VecMap", {
  contents: bcs.vector(PricingInfoEntryBcs),
});

export const PricingInfoBcs = bcs.struct("PricingInfo", {
  pricing_map: PricingInfoVecMapBcs,
});

// ============================================================================
// Address derivation
// ============================================================================

/**
 * Derive Ethereum address from BCS-encoded SECP256K1 public key
 * Accepts 33B compressed or 65B uncompressed (with 0x04 prefix) formats.
 *
 * @param publicKeyBytes - The public key bytes
 * @returns The Ethereum address (0x-prefixed)
 */
export function deriveEthereumAddress(publicKeyBytes: Uint8Array): string {
  return computeAddress(("0x" + bytesToHex(publicKeyBytes)) as `0x${string}`);
}

/**
 * Derive Solana address from Ed25519 public key.
 * The Solana address is simply the base58-encoded public key.
 *
 * @param publicKeyBytes - The Ed25519 public key (32 bytes)
 * @returns The Solana address (base58)
 */
export function deriveSolanaAddress(publicKeyBytes: Uint8Array): string {
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: expected 32, got ${publicKeyBytes.length}`);
  }
  return base58Encode(publicKeyBytes);
}

/**
 * Base58 alphabet (Bitcoin/Solana variant)
 */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode bytes to base58.
 */
function base58Encode(data: Uint8Array): string {
  const digits = [0];
  for (const byte of data) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let result = "";
  for (const byte of data) {
    if (byte !== 0) break;
    result += "1";
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

/**
 * Derive Bitcoin address from SECP256K1 public key.
 * Script type determines address format (P2PKH, P2WPKH, P2TR).
 *
 * @param publicKeyBytes - The public key bytes (33 bytes compressed or 65 bytes uncompressed)
 * @param scriptType - 0=P2PKH, 1=P2WPKH, 2=P2TR
 * @param network - "mainnet" or "testnet"
 * @returns The Bitcoin address
 */
export function deriveBitcoinAddress(
  publicKeyBytes: Uint8Array,
  scriptType: number = 1,
  network: "mainnet" | "testnet" = "mainnet"
): string {
  // For now, delegate to the chain connector implementation
  // This is a placeholder - full implementation is in chains/bitcoin/address.ts
  throw new Error("Use chains/bitcoin/address.ts for Bitcoin address derivation");
}

// ============================================================================
// Sui/Move bytes field parsing
// ============================================================================

/**
 * Parse a Sui JSON `vector<u8>` field to Uint8Array.
 *
 * Sui JSON can represent `vector<u8>` in multiple shapes depending on RPC/version:
 * - number[] (most common)
 * - { bytes: number[] } / { data: number[] } / { value: number[] }
 * - base64 string (some RPCs)
 * - 0x-prefixed hex string (rare, but accepted)
 *
 * @param v - The field value to parse
 * @returns Uint8Array if parseable, null otherwise
 */
export function bytesFieldToU8(v: unknown): Uint8Array | null {
  if (!v) return null;
  if (v instanceof Uint8Array) return v;
  if (
    Array.isArray(v) &&
    v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)
  ) {
    return Uint8Array.from(v as number[]);
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (!s) return null;
    if (/^0x[0-9a-fA-F]*$/.test(s)) {
      try {
        return toBytes(s as `0x${string}`);
      } catch {
        return null;
      }
    }
    // base64 fallback
    try {
      return Uint8Array.from(Buffer.from(s, "base64"));
    } catch {
      return null;
    }
  }
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    // common wrappers
    if (o.bytes != null) return bytesFieldToU8(o.bytes);
    if (o.data != null) return bytesFieldToU8(o.data);
    if (o.value != null) return bytesFieldToU8(o.value);
    if (o.fields != null) return bytesFieldToU8(o.fields);
  }
  return null;
}

/**
 * Parse a Sui JSON `vector<u8>` field to hex string.
 *
 * @param v - The field value to parse
 * @returns 0x-prefixed hex string if parseable and non-empty, null otherwise
 */
export function bytesFieldToHex(v: unknown): string | null {
  const bytes = bytesFieldToU8(v);
  if (!bytes) return null;
  if (bytes.length === 0) return null;
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

/**
 * Parse a Sui JSON `vector<u8>` field to UTF-8 string.
 *
 * @param v - The field value to parse
 * @returns UTF-8 decoded string, empty string if not parseable
 */
export function bytesFieldToUtf8(v: unknown): string {
  const bytes = bytesFieldToU8(v);
  if (!bytes) return "";
  return new TextDecoder().decode(bytes);
}
