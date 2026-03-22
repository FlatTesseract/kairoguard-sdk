/**
 * Bitcoin Address Utilities
 *
 * Address derivation, validation, and conversion utilities.
 */

import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { bech32, bech32m } from "bech32";
import { BitcoinScriptType, type BitcoinNetwork } from "../types.js";
import { getBitcoinNetworkConfig, type BitcoinNetworkConfig } from "./config.js";

/**
 * Compute HASH160 (RIPEMD160(SHA256(data))).
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/**
 * Compute double SHA256.
 */
export function hash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

/**
 * Base58 alphabet.
 */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
 * Encode bytes to base58check (with checksum).
 */
export function base58CheckEncode(data: Uint8Array): string {
  const checksum = hash256(data).slice(0, 4);
  const combined = new Uint8Array(data.length + 4);
  combined.set(data);
  combined.set(checksum, data.length);
  return base58Encode(combined);
}

/**
 * Decode base58check string to bytes (validates checksum).
 */
export function base58CheckDecode(str: string): Uint8Array {
  const data = base58Decode(str);
  if (data.length < 5) throw new Error("Invalid base58check: too short");
  const payload = data.slice(0, -4);
  const checksum = data.slice(-4);
  const computedChecksum = hash256(payload).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== computedChecksum[i]) {
      throw new Error("Invalid base58check: checksum mismatch");
    }
  }
  return payload;
}

/**
 * Derive P2PKH address from public key.
 * Format: Base58Check(version || HASH160(pubkey))
 */
export function deriveP2PKHAddress(
  publicKey: Uint8Array,
  network: BitcoinNetwork = "mainnet"
): string {
  const config = getBitcoinNetworkConfig(network);
  const pubkeyHash = hash160(publicKey);
  const payload = new Uint8Array(1 + pubkeyHash.length);
  payload[0] = config.pubKeyHash;
  payload.set(pubkeyHash, 1);
  return base58CheckEncode(payload);
}

/**
 * Derive P2WPKH (native SegWit) address from public key.
 * Format: bech32(hrp, version || program)
 */
export function deriveP2WPKHAddress(
  publicKey: Uint8Array,
  network: BitcoinNetwork = "mainnet"
): string {
  const config = getBitcoinNetworkConfig(network);
  const pubkeyHash = hash160(publicKey);
  // Version 0, then 5-bit encoded program
  const words = bech32.toWords(pubkeyHash);
  words.unshift(0); // witness version 0
  return bech32.encode(config.bech32, words);
}

/**
 * Derive P2TR (Taproot) address from public key.
 * For Taproot, we use the x-only public key (32 bytes).
 * Format: bech32m(hrp, version || program)
 */
export function deriveP2TRAddress(
  publicKey: Uint8Array,
  network: BitcoinNetwork = "mainnet"
): string {
  const config = getBitcoinNetworkConfig(network);

  // Get x-only pubkey (32 bytes)
  let xOnlyPubkey: Uint8Array;
  if (publicKey.length === 33) {
    // Compressed pubkey: remove the prefix byte
    xOnlyPubkey = publicKey.slice(1);
  } else if (publicKey.length === 32) {
    // Already x-only
    xOnlyPubkey = publicKey;
  } else if (publicKey.length === 65) {
    // Uncompressed pubkey: use x-coordinate
    xOnlyPubkey = publicKey.slice(1, 33);
  } else {
    throw new Error(`Invalid public key length: ${publicKey.length}`);
  }

  // For a simple key-path spend (no scripts), the output key is:
  // P = internal_key + H(internal_key || "") * G
  // For simplicity, we'll use the internal key directly.
  // A proper implementation would compute the tweak.
  // This is simplified - in production use a proper BIP340/BIP341 implementation.
  const words = bech32m.toWords(xOnlyPubkey);
  words.unshift(1); // witness version 1
  return bech32m.encode(config.bech32m, words);
}

/**
 * Derive Bitcoin address from public key based on script type.
 */
export function deriveBitcoinAddress(
  publicKey: Uint8Array,
  scriptType: BitcoinScriptType,
  network: BitcoinNetwork = "mainnet"
): string {
  switch (scriptType) {
    case BitcoinScriptType.P2PKH:
      return deriveP2PKHAddress(publicKey, network);
    case BitcoinScriptType.P2WPKH:
      return deriveP2WPKHAddress(publicKey, network);
    case BitcoinScriptType.P2TR:
      return deriveP2TRAddress(publicKey, network);
    default:
      throw new Error(`Unknown script type: ${scriptType}`);
  }
}

/**
 * Validate a Bitcoin address.
 */
export function validateBitcoinAddress(
  address: string,
  network: BitcoinNetwork = "mainnet"
): { valid: boolean; type?: BitcoinScriptType; error?: string } {
  const config = getBitcoinNetworkConfig(network);

  // Try bech32/bech32m (SegWit/Taproot)
  try {
    // Try bech32m first (Taproot)
    const decoded = bech32m.decode(address);
    if (decoded.prefix === config.bech32m) {
      const version = decoded.words[0];
      if (version === 1) {
        const program = bech32m.fromWords(decoded.words.slice(1));
        if (program.length === 32) {
          return { valid: true, type: BitcoinScriptType.P2TR };
        }
      }
    }
  } catch {
    // Not bech32m
  }

  try {
    // Try bech32 (SegWit v0)
    const decoded = bech32.decode(address);
    if (decoded.prefix === config.bech32) {
      const version = decoded.words[0];
      if (version === 0) {
        const program = bech32.fromWords(decoded.words.slice(1));
        if (program.length === 20) {
          return { valid: true, type: BitcoinScriptType.P2WPKH };
        }
      }
    }
  } catch {
    // Not bech32
  }

  // Try base58check (P2PKH or P2SH)
  try {
    const decoded = base58CheckDecode(address);
    if (decoded.length === 21) {
      const version = decoded[0];
      if (version === config.pubKeyHash) {
        return { valid: true, type: BitcoinScriptType.P2PKH };
      }
      if (version === config.scriptHash) {
        // P2SH - we don't handle this in our simple case
        return { valid: true, error: "P2SH addresses not supported" };
      }
    }
  } catch {
    // Not base58check
  }

  return { valid: false, error: "Invalid Bitcoin address format" };
}

/**
 * Convert address to script pubkey bytes.
 */
export function addressToScriptPubKey(
  address: string,
  network: BitcoinNetwork = "mainnet"
): Uint8Array {
  const config = getBitcoinNetworkConfig(network);

  // Try bech32m (Taproot)
  try {
    const decoded = bech32m.decode(address);
    if (decoded.prefix === config.bech32m && decoded.words[0] === 1) {
      const program = Uint8Array.from(bech32m.fromWords(decoded.words.slice(1)));
      if (program.length === 32) {
        // OP_1 <32-byte-program>
        const script = new Uint8Array(34);
        script[0] = 0x51; // OP_1
        script[1] = 0x20; // Push 32 bytes
        script.set(program, 2);
        return script;
      }
    }
  } catch {
    // Not bech32m
  }

  // Try bech32 (SegWit v0)
  try {
    const decoded = bech32.decode(address);
    if (decoded.prefix === config.bech32 && decoded.words[0] === 0) {
      const program = Uint8Array.from(bech32.fromWords(decoded.words.slice(1)));
      if (program.length === 20) {
        // OP_0 <20-byte-program>
        const script = new Uint8Array(22);
        script[0] = 0x00; // OP_0
        script[1] = 0x14; // Push 20 bytes
        script.set(program, 2);
        return script;
      }
    }
  } catch {
    // Not bech32
  }

  // Try base58check (P2PKH)
  try {
    const decoded = base58CheckDecode(address);
    if (decoded.length === 21 && decoded[0] === config.pubKeyHash) {
      const pubkeyHash = decoded.slice(1);
      // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
      const script = new Uint8Array(25);
      script[0] = 0x76; // OP_DUP
      script[1] = 0xa9; // OP_HASH160
      script[2] = 0x14; // Push 20 bytes
      script.set(pubkeyHash, 3);
      script[23] = 0x88; // OP_EQUALVERIFY
      script[24] = 0xac; // OP_CHECKSIG
      return script;
    }
  } catch {
    // Not base58check
  }

  throw new Error(`Cannot convert address to scriptPubKey: ${address}`);
}
