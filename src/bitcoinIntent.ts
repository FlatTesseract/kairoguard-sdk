/**
 * Bitcoin Intent Utilities
 *
 * Client-side helpers for Bitcoin transaction intent hashing and validation.
 */

import { sha256 } from "@noble/hashes/sha256";
import type { Hex } from "./types.js";

/**
 * Bitcoin script types.
 */
export enum BitcoinScriptType {
  P2PKH = 0,
  P2WPKH = 1,
  P2TR = 2,
}

/**
 * Bitcoin network types.
 */
export type BitcoinNetwork = "mainnet" | "testnet" | "signet";

/**
 * Parsed PSBT output.
 */
export interface PSBTOutput {
  address: string;
  value: bigint;
}

/**
 * Parsed PSBT input (UTXO).
 */
export interface PSBTInput {
  txid: string;
  vout: number;
  value: bigint;
  scriptType?: BitcoinScriptType;
}

/**
 * Parsed PSBT structure.
 */
export interface ParsedPSBT {
  inputs: PSBTInput[];
  outputs: PSBTOutput[];
  fee: bigint;
  scriptType: BitcoinScriptType;
}

/**
 * Bitcoin intent for policy verification.
 */
export interface BitcoinIntent {
  network: BitcoinNetwork;
  /** 32-byte intent hash (sighash) */
  intentHash: Hex;
  /** Destination addresses */
  destinations: string[];
  /** Amounts in satoshis */
  amounts: bigint[];
  /** Script type */
  scriptType: BitcoinScriptType;
  /** Raw PSBT hex */
  psbtHex: string;
}

/**
 * Compute double SHA256 (hash256).
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * Compute BIP340 tagged hash for Taproot.
 */
export function taggedHash(tag: string, data: Uint8Array): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode(tag));
  const combined = new Uint8Array(tagHash.length * 2 + data.length);
  combined.set(tagHash, 0);
  combined.set(tagHash, tagHash.length);
  combined.set(data, tagHash.length * 2);
  return sha256(combined);
}

/**
 * Convert hex string to bytes.
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleanHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to hex string.
 */
export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")}` as Hex;
}

/**
 * Validate a Bitcoin address format.
 * This is a basic check - full validation requires network context.
 */
export function validateBitcoinAddress(
  address: string,
  network: BitcoinNetwork = "mainnet"
): boolean {
  // Bech32/Bech32m addresses
  if (network === "mainnet") {
    if (address.startsWith("bc1q") || address.startsWith("bc1p")) {
      return address.length >= 42 && address.length <= 62;
    }
    // Legacy P2PKH
    if (address.startsWith("1") || address.startsWith("3")) {
      return address.length >= 26 && address.length <= 35;
    }
  } else {
    // Testnet/Signet
    if (address.startsWith("tb1q") || address.startsWith("tb1p")) {
      return address.length >= 42 && address.length <= 62;
    }
    if (address.startsWith("m") || address.startsWith("n") || address.startsWith("2")) {
      return address.length >= 26 && address.length <= 35;
    }
  }
  return false;
}

/**
 * Detect script type from address format.
 */
export function detectScriptTypeFromAddress(address: string): BitcoinScriptType {
  // Taproot (bech32m)
  if (address.startsWith("bc1p") || address.startsWith("tb1p")) {
    return BitcoinScriptType.P2TR;
  }
  // Native SegWit (bech32)
  if (address.startsWith("bc1q") || address.startsWith("tb1q")) {
    return BitcoinScriptType.P2WPKH;
  }
  // Legacy (base58check)
  return BitcoinScriptType.P2PKH;
}

/**
 * Compute total input value from parsed PSBT.
 */
export function computeTotalInputValue(psbt: ParsedPSBT): bigint {
  return psbt.inputs.reduce((sum, input) => sum + input.value, 0n);
}

/**
 * Compute total output value from parsed PSBT.
 */
export function computeTotalOutputValue(psbt: ParsedPSBT): bigint {
  return psbt.outputs.reduce((sum, output) => sum + output.value, 0n);
}

/**
 * Compute fee from parsed PSBT.
 */
export function computeFee(psbt: ParsedPSBT): bigint {
  const totalIn = computeTotalInputValue(psbt);
  const totalOut = computeTotalOutputValue(psbt);
  return totalIn - totalOut;
}

/**
 * Format satoshis as BTC string.
 */
export function satoshisToBTC(satoshis: bigint): string {
  const btc = Number(satoshis) / 100_000_000;
  return btc.toFixed(8);
}

/**
 * Parse BTC string to satoshis.
 */
export function btcToSatoshis(btc: string | number): bigint {
  const value = typeof btc === "string" ? parseFloat(btc) : btc;
  return BigInt(Math.round(value * 100_000_000));
}
