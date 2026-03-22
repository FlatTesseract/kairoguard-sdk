/**
 * Solana Intent Utilities
 *
 * Client-side helpers for Solana transaction intent hashing and validation.
 */

import { sha256 } from "@noble/hashes/sha256";
import type { Hex } from "./types.js";

/**
 * Solana cluster types.
 */
export type SolanaCluster = "mainnet-beta" | "devnet" | "testnet";

/**
 * Lamports per SOL.
 */
export const LAMPORTS_PER_SOL = 1_000_000_000n;

/**
 * Parsed Solana instruction.
 */
export interface ParsedInstruction {
  programId: string;
  accounts: string[];
  data: Uint8Array;
}

/**
 * Parsed Solana transaction.
 */
export interface ParsedSolanaTransaction {
  feePayer: string;
  recentBlockhash: string;
  instructions: ParsedInstruction[];
  programIds: string[];
}

/**
 * Solana intent for policy verification.
 */
export interface SolanaIntent {
  cluster: SolanaCluster;
  /** 32-byte intent hash (message hash) */
  intentHash: Hex;
  /** Fee payer (signer) */
  feePayer: string;
  /** Destination addresses (extracted from transfer instructions) */
  destinations: string[];
  /** Amounts in lamports */
  amounts: bigint[];
  /** Program IDs involved */
  programIds: string[];
  /** Raw transaction bytes (base58) */
  transactionBase58: string;
}

/**
 * Common Solana program IDs.
 */
export const PROGRAM_IDS = {
  SYSTEM: "11111111111111111111111111111111",
  TOKEN: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  TOKEN_2022: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
  ASSOCIATED_TOKEN: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
  MEMO: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  COMPUTE_BUDGET: "ComputeBudget111111111111111111111111111111",
} as const;

/**
 * System instruction types.
 */
export enum SystemInstructionType {
  CreateAccount = 0,
  Assign = 1,
  Transfer = 2,
  CreateAccountWithSeed = 3,
  AdvanceNonceAccount = 4,
  WithdrawNonceAccount = 5,
  InitializeNonceAccount = 6,
  AuthorizeNonceAccount = 7,
  Allocate = 8,
  AllocateWithSeed = 9,
  AssignWithSeed = 10,
  TransferWithSeed = 11,
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
 * Base58 alphabet (Bitcoin/Solana variant).
 */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Decode base58 string to bytes.
 */
export function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [];
  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`Invalid base58 character: ${char}`);
    let carry = index;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  for (const char of str) {
    if (char !== "1") break;
    bytes.push(0);
  }

  return Uint8Array.from(bytes.reverse());
}

/**
 * Encode bytes to base58.
 */
export function base58Encode(data: Uint8Array): string {
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
 * Validate a Solana address (base58 encoded Ed25519 public key).
 */
export function validateSolanaAddress(address: string): boolean {
  try {
    const decoded = base58Decode(address);
    return decoded.length === 32;
  } catch {
    return false;
  }
}

/**
 * Compute intent hash from transaction message bytes.
 */
export function computeSolanaIntentHash(messageBytes: Uint8Array): Uint8Array {
  return sha256(messageBytes);
}

/**
 * Check if a program ID is a known safe program.
 */
export function isKnownSafeProgram(programId: string): boolean {
  return (
    programId === PROGRAM_IDS.SYSTEM ||
    programId === PROGRAM_IDS.MEMO ||
    programId === PROGRAM_IDS.COMPUTE_BUDGET
  );
}

/**
 * Check if a program ID is a token program.
 */
export function isTokenProgram(programId: string): boolean {
  return (
    programId === PROGRAM_IDS.TOKEN ||
    programId === PROGRAM_IDS.TOKEN_2022 ||
    programId === PROGRAM_IDS.ASSOCIATED_TOKEN
  );
}

/**
 * Get human-readable name for a program.
 */
export function getProgramName(programId: string): string {
  switch (programId) {
    case PROGRAM_IDS.SYSTEM:
      return "System Program";
    case PROGRAM_IDS.TOKEN:
      return "Token Program";
    case PROGRAM_IDS.TOKEN_2022:
      return "Token 2022 Program";
    case PROGRAM_IDS.ASSOCIATED_TOKEN:
      return "Associated Token Program";
    case PROGRAM_IDS.MEMO:
      return "Memo Program";
    case PROGRAM_IDS.COMPUTE_BUDGET:
      return "Compute Budget Program";
    default:
      return `Unknown (${programId.slice(0, 8)}...)`;
  }
}

/**
 * Format lamports as SOL string.
 */
export function lamportsToSOL(lamports: bigint): string {
  const sol = Number(lamports) / Number(LAMPORTS_PER_SOL);
  return sol.toFixed(9);
}

/**
 * Parse SOL string to lamports.
 */
export function solToLamports(sol: string | number): bigint {
  const value = typeof sol === "string" ? parseFloat(sol) : sol;
  return BigInt(Math.round(value * Number(LAMPORTS_PER_SOL)));
}

/**
 * Extract transfer destinations and amounts from System Program instructions.
 */
export function extractSystemTransfers(
  instructions: ParsedInstruction[]
): { destinations: string[]; amounts: bigint[] } {
  const destinations: string[] = [];
  const amounts: bigint[] = [];

  for (const ix of instructions) {
    if (ix.programId !== PROGRAM_IDS.SYSTEM) continue;
    if (ix.data.length < 12) continue;

    // Check instruction type (first 4 bytes, little-endian)
    const instructionType =
      ix.data[0] | (ix.data[1] << 8) | (ix.data[2] << 16) | (ix.data[3] << 24);

    if (instructionType === SystemInstructionType.Transfer) {
      // Next 8 bytes are lamports (little-endian u64)
      let lamports = 0n;
      for (let i = 0; i < 8; i++) {
        lamports |= BigInt(ix.data[4 + i]) << BigInt(i * 8);
      }

      // Destination is the second account
      if (ix.accounts.length >= 2) {
        destinations.push(ix.accounts[1]);
        amounts.push(lamports);
      }
    }
  }

  return { destinations, amounts };
}
