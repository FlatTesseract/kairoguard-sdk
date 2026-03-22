/**
 * Bitcoin PSBT (Partially Signed Bitcoin Transaction) Utilities
 *
 * Parsing, sighash computation, and signature injection for PSBTs.
 * Implements BIP 174 (PSBT) and BIP 370 (PSBT Version 2).
 */

import { sha256 } from "@noble/hashes/sha256";
import { BitcoinScriptType, type BitcoinUTXO } from "../types.js";
import { hash256, addressToScriptPubKey } from "./address.js";
import type { BitcoinNetwork } from "../types.js";

/**
 * PSBT key types.
 */
const PSBT_GLOBAL_UNSIGNED_TX = 0x00;
const PSBT_GLOBAL_XPUB = 0x01;
const PSBT_GLOBAL_VERSION = 0xfb;

const PSBT_IN_NON_WITNESS_UTXO = 0x00;
const PSBT_IN_WITNESS_UTXO = 0x01;
const PSBT_IN_PARTIAL_SIG = 0x02;
const PSBT_IN_SIGHASH_TYPE = 0x03;
const PSBT_IN_REDEEM_SCRIPT = 0x04;
const PSBT_IN_WITNESS_SCRIPT = 0x05;
const PSBT_IN_BIP32_DERIVATION = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
const PSBT_IN_TAP_KEY_SIG = 0x13;
const PSBT_IN_TAP_INTERNAL_KEY = 0x17;

const PSBT_OUT_REDEEM_SCRIPT = 0x00;
const PSBT_OUT_WITNESS_SCRIPT = 0x01;
const PSBT_OUT_BIP32_DERIVATION = 0x02;

/**
 * Sighash types.
 */
export const SIGHASH_ALL = 0x01;
export const SIGHASH_NONE = 0x02;
export const SIGHASH_SINGLE = 0x03;
export const SIGHASH_ANYONECANPAY = 0x80;

/**
 * PSBT magic bytes.
 */
const PSBT_MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]); // "psbt" + 0xff

/**
 * Transaction output.
 */
export interface TxOutput {
  value: bigint;
  scriptPubKey: Uint8Array;
}

/**
 * Transaction input.
 */
export interface TxInput {
  txid: Uint8Array; // 32 bytes, little-endian
  vout: number;
  scriptSig: Uint8Array;
  sequence: number;
}

/**
 * Parsed raw Bitcoin transaction.
 */
export interface ParsedRawTransaction {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  locktime: number;
  hasWitness: boolean;
}

/**
 * Taproot script-path data for MPC signing.
 */
export interface TapScriptPathData {
  /** The Tapscript being executed (e.g., <pubkey> OP_CHECKSIG) */
  leafScript: Uint8Array;
  /** Leaf version (0xc0 for Tapscript) */
  leafVersion: number;
  /** Control block for script-path witness */
  controlBlock: Uint8Array;
  /** Computed leaf hash */
  leafHash: Uint8Array;
}

/**
 * PSBT input data.
 */
export interface PSBTInput {
  nonWitnessUtxo?: Uint8Array;
  witnessUtxo?: {
    value: bigint;
    scriptPubKey: Uint8Array;
  };
  partialSigs?: Map<Uint8Array, Uint8Array>;
  sighashType?: number;
  redeemScript?: Uint8Array;
  witnessScript?: Uint8Array;
  bip32Derivation?: Map<Uint8Array, { fingerprint: Uint8Array; path: number[] }>;
  finalScriptSig?: Uint8Array;
  finalScriptWitness?: Uint8Array;
  tapKeySig?: Uint8Array;
  tapInternalKey?: Uint8Array;
  tapScriptSig?: Array<{
    pubkey: Uint8Array;
    signature: Uint8Array;
    leafHash: Uint8Array;
  }>;
  tapLeafScript?: Array<{
    controlBlock: Uint8Array;
    script: Uint8Array;
    leafVersion: number;
  }>;
}

/**
 * PSBT output data.
 */
export interface PSBTOutput {
  redeemScript?: Uint8Array;
  witnessScript?: Uint8Array;
  bip32Derivation?: Map<Uint8Array, { fingerprint: Uint8Array; path: number[] }>;
}

/**
 * Parsed PSBT.
 */
export interface ParsedPSBT {
  version: number;
  tx: ParsedRawTransaction;
  inputs: PSBTInput[];
  outputs: PSBTOutput[];
  globalXpubs?: Map<Uint8Array, { fingerprint: Uint8Array; path: number[] }>;
}

/**
 * Read a variable-length integer (CompactSize).
 */
function readVarInt(buffer: Uint8Array, offset: number): { value: number; bytesRead: number } {
  const first = buffer[offset];
  if (first < 0xfd) {
    return { value: first, bytesRead: 1 };
  } else if (first === 0xfd) {
    const value = buffer[offset + 1] | (buffer[offset + 2] << 8);
    return { value, bytesRead: 3 };
  } else if (first === 0xfe) {
    const value =
      buffer[offset + 1] |
      (buffer[offset + 2] << 8) |
      (buffer[offset + 3] << 16) |
      (buffer[offset + 4] << 24);
    return { value: value >>> 0, bytesRead: 5 };
  } else {
    // 0xff - 8 bytes, but we don't support values > 32 bits
    throw new Error("VarInt too large");
  }
}

/**
 * Write a variable-length integer.
 */
function writeVarInt(value: number): Uint8Array {
  if (value < 0xfd) {
    return new Uint8Array([value]);
  } else if (value <= 0xffff) {
    return new Uint8Array([0xfd, value & 0xff, (value >> 8) & 0xff]);
  } else if (value <= 0xffffffff) {
    return new Uint8Array([
      0xfe,
      value & 0xff,
      (value >> 8) & 0xff,
      (value >> 16) & 0xff,
      (value >> 24) & 0xff,
    ]);
  } else {
    throw new Error("Value too large for varint");
  }
}

/**
 * Read a little-endian 32-bit integer.
 */
function readUint32LE(buffer: Uint8Array, offset: number): number {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  ) >>> 0;
}

/**
 * Read a little-endian 64-bit integer as bigint.
 */
function readUint64LE(buffer: Uint8Array, offset: number): bigint {
  const low = readUint32LE(buffer, offset);
  const high = readUint32LE(buffer, offset + 4);
  return BigInt(low) | (BigInt(high) << 32n);
}

/**
 * Write a little-endian 32-bit integer.
 */
function writeUint32LE(value: number): Uint8Array {
  return new Uint8Array([value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff]);
}

/**
 * Write a little-endian 64-bit integer.
 */
function writeUint64LE(value: bigint): Uint8Array {
  const result = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    result[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return result;
}

/**
 * Parse a raw Bitcoin transaction.
 */
export function parseRawTransaction(buffer: Uint8Array): ParsedRawTransaction {
  let offset = 0;

  // Version
  const version = readUint32LE(buffer, offset);
  offset += 4;

  // Check for witness marker
  let hasWitness = false;
  if (buffer[offset] === 0x00 && buffer[offset + 1] === 0x01) {
    hasWitness = true;
    offset += 2;
  }

  // Input count
  const { value: inputCount, bytesRead: inputCountBytes } = readVarInt(buffer, offset);
  offset += inputCountBytes;

  // Inputs
  const inputs: TxInput[] = [];
  for (let i = 0; i < inputCount; i++) {
    const txid = buffer.slice(offset, offset + 32);
    offset += 32;
    const vout = readUint32LE(buffer, offset);
    offset += 4;
    const { value: scriptLen, bytesRead: scriptLenBytes } = readVarInt(buffer, offset);
    offset += scriptLenBytes;
    const scriptSig = buffer.slice(offset, offset + scriptLen);
    offset += scriptLen;
    const sequence = readUint32LE(buffer, offset);
    offset += 4;
    inputs.push({ txid, vout, scriptSig, sequence });
  }

  // Output count
  const { value: outputCount, bytesRead: outputCountBytes } = readVarInt(buffer, offset);
  offset += outputCountBytes;

  // Outputs
  const outputs: TxOutput[] = [];
  for (let i = 0; i < outputCount; i++) {
    const value = readUint64LE(buffer, offset);
    offset += 8;
    const { value: scriptLen, bytesRead: scriptLenBytes } = readVarInt(buffer, offset);
    offset += scriptLenBytes;
    const scriptPubKey = buffer.slice(offset, offset + scriptLen);
    offset += scriptLen;
    outputs.push({ value, scriptPubKey });
  }

  // Skip witness data if present
  if (hasWitness) {
    for (let i = 0; i < inputCount; i++) {
      const { value: witnessCount, bytesRead: witnessCountBytes } = readVarInt(buffer, offset);
      offset += witnessCountBytes;
      for (let j = 0; j < witnessCount; j++) {
        const { value: itemLen, bytesRead: itemLenBytes } = readVarInt(buffer, offset);
        offset += itemLenBytes + itemLen;
      }
    }
  }

  // Locktime
  const locktime = readUint32LE(buffer, offset);

  return { version, inputs, outputs, locktime, hasWitness };
}

/**
 * Serialize a transaction for signing (without witness).
 */
export function serializeTransactionForSigning(tx: ParsedRawTransaction): Uint8Array {
  const parts: Uint8Array[] = [];

  // Version
  parts.push(writeUint32LE(tx.version));

  // Inputs
  parts.push(writeVarInt(tx.inputs.length));
  for (const input of tx.inputs) {
    parts.push(input.txid);
    parts.push(writeUint32LE(input.vout));
    parts.push(writeVarInt(input.scriptSig.length));
    parts.push(input.scriptSig);
    parts.push(writeUint32LE(input.sequence));
  }

  // Outputs
  parts.push(writeVarInt(tx.outputs.length));
  for (const output of tx.outputs) {
    parts.push(writeUint64LE(output.value));
    parts.push(writeVarInt(output.scriptPubKey.length));
    parts.push(output.scriptPubKey);
  }

  // Locktime
  parts.push(writeUint32LE(tx.locktime));

  // Concatenate
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * Parse PSBT from hex string or bytes.
 */
export function parsePSBT(data: Uint8Array | string): ParsedPSBT {
  const buffer = typeof data === "string" ? hexToBytes(data) : data;

  // Check magic
  for (let i = 0; i < PSBT_MAGIC.length; i++) {
    if (buffer[i] !== PSBT_MAGIC[i]) {
      throw new Error("Invalid PSBT magic");
    }
  }

  let offset = PSBT_MAGIC.length;

  // Parse global map
  let tx: ParsedRawTransaction | undefined;
  let psbtVersion = 0;
  const globalXpubs = new Map<Uint8Array, { fingerprint: Uint8Array; path: number[] }>();

  while (buffer[offset] !== 0x00) {
    const { value: keyLen, bytesRead: keyLenBytes } = readVarInt(buffer, offset);
    offset += keyLenBytes;
    const keyType = buffer[offset];
    const keyData = buffer.slice(offset + 1, offset + keyLen);
    offset += keyLen;

    const { value: valueLen, bytesRead: valueLenBytes } = readVarInt(buffer, offset);
    offset += valueLenBytes;
    const valueData = buffer.slice(offset, offset + valueLen);
    offset += valueLen;

    if (keyType === PSBT_GLOBAL_UNSIGNED_TX) {
      tx = parseRawTransaction(valueData);
    } else if (keyType === PSBT_GLOBAL_VERSION) {
      psbtVersion = readUint32LE(valueData, 0);
    }
  }
  offset++; // Skip separator

  if (!tx) {
    throw new Error("PSBT missing unsigned transaction");
  }

  // Parse input maps
  const inputs: PSBTInput[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const input: PSBTInput = {};
    while (buffer[offset] !== 0x00) {
      const { value: keyLen, bytesRead: keyLenBytes } = readVarInt(buffer, offset);
      offset += keyLenBytes;
      const keyType = buffer[offset];
      const keyData = buffer.slice(offset + 1, offset + keyLen);
      offset += keyLen;

      const { value: valueLen, bytesRead: valueLenBytes } = readVarInt(buffer, offset);
      offset += valueLenBytes;
      const valueData = buffer.slice(offset, offset + valueLen);
      offset += valueLen;

      switch (keyType) {
        case PSBT_IN_NON_WITNESS_UTXO:
          input.nonWitnessUtxo = valueData;
          break;
        case PSBT_IN_WITNESS_UTXO:
          input.witnessUtxo = {
            value: readUint64LE(valueData, 0),
            scriptPubKey: valueData.slice(8 + 1, 8 + 1 + valueData[8]),
          };
          break;
        case PSBT_IN_SIGHASH_TYPE:
          input.sighashType = readUint32LE(valueData, 0);
          break;
        case PSBT_IN_TAP_KEY_SIG:
          input.tapKeySig = valueData;
          break;
        case PSBT_IN_TAP_INTERNAL_KEY:
          input.tapInternalKey = valueData;
          break;
      }
    }
    offset++; // Skip separator
    inputs.push(input);
  }

  // Parse output maps
  const outputs: PSBTOutput[] = [];
  for (let i = 0; i < tx.outputs.length; i++) {
    const output: PSBTOutput = {};
    while (offset < buffer.length && buffer[offset] !== 0x00) {
      const { value: keyLen, bytesRead: keyLenBytes } = readVarInt(buffer, offset);
      offset += keyLenBytes;
      const keyType = buffer[offset];
      offset += keyLen;

      const { value: valueLen, bytesRead: valueLenBytes } = readVarInt(buffer, offset);
      offset += valueLenBytes;
      offset += valueLen;
    }
    if (offset < buffer.length) offset++; // Skip separator
    outputs.push(output);
  }

  return {
    version: psbtVersion,
    tx,
    inputs,
    outputs,
    globalXpubs,
  };
}

/**
 * Detect script type from PSBT input.
 */
export function detectScriptType(psbt: ParsedPSBT, inputIndex: number): BitcoinScriptType {
  const input = psbt.inputs[inputIndex];
  if (!input) throw new Error(`Input ${inputIndex} not found`);

  // Check for Taproot
  if (input.tapInternalKey || input.tapKeySig) {
    return BitcoinScriptType.P2TR;
  }

  // Check witness UTXO for SegWit
  if (input.witnessUtxo) {
    const script = input.witnessUtxo.scriptPubKey;
    // P2WPKH: OP_0 <20-byte-hash>
    if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) {
      return BitcoinScriptType.P2WPKH;
    }
    // P2TR: OP_1 <32-byte-key>
    if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) {
      return BitcoinScriptType.P2TR;
    }
  }

  // Default to P2PKH (legacy)
  return BitcoinScriptType.P2PKH;
}

/**
 * Compute sighash for legacy P2PKH input.
 */
export function computeLegacySighash(
  psbt: ParsedPSBT,
  inputIndex: number,
  scriptPubKey: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  // Create a copy of the transaction
  const tx = { ...psbt.tx, inputs: psbt.tx.inputs.map((i) => ({ ...i })) };

  // Clear all input scripts
  for (const input of tx.inputs) {
    input.scriptSig = new Uint8Array();
  }

  // Set the script for the input being signed
  tx.inputs[inputIndex].scriptSig = scriptPubKey;

  // Serialize and append sighash type
  const txBytes = serializeTransactionForSigning(tx);
  const withSighash = new Uint8Array(txBytes.length + 4);
  withSighash.set(txBytes);
  withSighash.set(writeUint32LE(sighashType), txBytes.length);

  // Double SHA256
  return hash256(withSighash);
}

/**
 * Compute the legacy (non-SegWit) sighash preimage (tx serialization + sighashType).
 * This is useful for MPC schemes where the signer applies an additional hash step.
 */
export function computeLegacySighashPreimage(
  psbt: ParsedPSBT,
  inputIndex: number,
  scriptPubKey: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  // Create a copy of the transaction
  const tx = { ...psbt.tx, inputs: psbt.tx.inputs.map((i) => ({ ...i })) };

  // Clear all input scripts
  for (const input of tx.inputs) {
    input.scriptSig = new Uint8Array();
  }

  // Set the script for the input being signed
  tx.inputs[inputIndex].scriptSig = scriptPubKey;

  // Serialize and append sighash type (u32 LE)
  const txBytes = serializeTransactionForSigning(tx);
  const withSighash = new Uint8Array(txBytes.length + 4);
  withSighash.set(txBytes);
  withSighash.set(writeUint32LE(sighashType), txBytes.length);
  return withSighash;
}

/**
 * Compute the *single* SHA256 of the legacy sighash preimage.
 * If the MPC/network applies Hash.SHA256 to the provided message bytes before signing,
 * then providing this value yields the correct Bitcoin hash256(sighashPreimage) overall.
 */
export function computeLegacySighashPrehash(
  psbt: ParsedPSBT,
  inputIndex: number,
  scriptPubKey: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  const preimage = computeLegacySighashPreimage(psbt, inputIndex, scriptPubKey, sighashType);
  return new Uint8Array(sha256(preimage));
}

/**
 * Compute BIP143 sighash for SegWit inputs (P2WPKH).
 */
export function computeSegwitSighash(
  psbt: ParsedPSBT,
  inputIndex: number,
  value: bigint,
  scriptCode: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  const tx = psbt.tx;
  const input = tx.inputs[inputIndex];

  // hashPrevouts
  let prevoutsData = new Uint8Array(tx.inputs.length * 36);
  for (let i = 0; i < tx.inputs.length; i++) {
    prevoutsData.set(tx.inputs[i].txid, i * 36);
    prevoutsData.set(writeUint32LE(tx.inputs[i].vout), i * 36 + 32);
  }
  const hashPrevouts = hash256(prevoutsData);

  // hashSequence
  let sequenceData = new Uint8Array(tx.inputs.length * 4);
  for (let i = 0; i < tx.inputs.length; i++) {
    sequenceData.set(writeUint32LE(tx.inputs[i].sequence), i * 4);
  }
  const hashSequence = hash256(sequenceData);

  // hashOutputs
  const outputParts: Uint8Array[] = [];
  for (const output of tx.outputs) {
    outputParts.push(writeUint64LE(output.value));
    outputParts.push(writeVarInt(output.scriptPubKey.length));
    outputParts.push(output.scriptPubKey);
  }
  const outputsData = concatBytes(...outputParts);
  const hashOutputs = hash256(outputsData);

  // Build preimage
  const parts: Uint8Array[] = [
    writeUint32LE(tx.version),
    hashPrevouts,
    hashSequence,
    input.txid,
    writeUint32LE(input.vout),
    writeVarInt(scriptCode.length),
    scriptCode,
    writeUint64LE(value),
    writeUint32LE(input.sequence),
    hashOutputs,
    writeUint32LE(tx.locktime),
    writeUint32LE(sighashType),
  ];

  const preimage = concatBytes(...parts);
  return hash256(preimage);
}

/**
 * Compute the BIP143 sighash preimage for SegWit inputs.
 */
export function computeSegwitSighashPreimage(
  psbt: ParsedPSBT,
  inputIndex: number,
  value: bigint,
  scriptCode: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  const tx = psbt.tx;
  const input = tx.inputs[inputIndex];

  // hashPrevouts
  const prevoutsData = new Uint8Array(tx.inputs.length * 36);
  for (let i = 0; i < tx.inputs.length; i++) {
    prevoutsData.set(tx.inputs[i].txid, i * 36);
    prevoutsData.set(writeUint32LE(tx.inputs[i].vout), i * 36 + 32);
  }
  const hashPrevouts = hash256(prevoutsData);

  // hashSequence
  const sequenceData = new Uint8Array(tx.inputs.length * 4);
  for (let i = 0; i < tx.inputs.length; i++) {
    sequenceData.set(writeUint32LE(tx.inputs[i].sequence), i * 4);
  }
  const hashSequence = hash256(sequenceData);

  // hashOutputs
  const outputParts: Uint8Array[] = [];
  for (const output of tx.outputs) {
    outputParts.push(writeUint64LE(output.value));
    outputParts.push(writeVarInt(output.scriptPubKey.length));
    outputParts.push(output.scriptPubKey);
  }
  const outputsData = concatBytes(...outputParts);
  const hashOutputs = hash256(outputsData);

  // Build preimage
  const parts: Uint8Array[] = [
    writeUint32LE(tx.version),
    hashPrevouts,
    hashSequence,
    input.txid,
    writeUint32LE(input.vout),
    writeVarInt(scriptCode.length),
    scriptCode,
    writeUint64LE(value),
    writeUint32LE(input.sequence),
    hashOutputs,
    writeUint32LE(tx.locktime),
    writeUint32LE(sighashType),
  ];

  return concatBytes(...parts);
}

/**
 * Compute the *single* SHA256 of the BIP143 sighash preimage.
 * If the MPC/network applies Hash.SHA256 to the provided message bytes before signing,
 * then providing this value yields the correct Bitcoin hash256(sighashPreimage) overall.
 */
export function computeSegwitSighashPrehash(
  psbt: ParsedPSBT,
  inputIndex: number,
  value: bigint,
  scriptCode: Uint8Array,
  sighashType: number = SIGHASH_ALL
): Uint8Array {
  const preimage = computeSegwitSighashPreimage(psbt, inputIndex, value, scriptCode, sighashType);
  return new Uint8Array(sha256(preimage));
}

/**
 * Compute BIP341 sighash for Taproot key-path spending.
 */
export function computeTaprootKeypathSighash(
  psbt: ParsedPSBT,
  inputIndex: number,
  sighashType: number = 0x00 // Default = SIGHASH_DEFAULT
): Uint8Array {
  const tx = psbt.tx;

  // Collect all input values and scriptPubKeys
  const inputValues: bigint[] = [];
  const inputScriptPubKeys: Uint8Array[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const psbtInput = psbt.inputs[i];
    if (!psbtInput.witnessUtxo) {
      throw new Error(`Input ${i} missing witnessUtxo for Taproot sighash`);
    }
    inputValues.push(psbtInput.witnessUtxo.value);
    inputScriptPubKeys.push(psbtInput.witnessUtxo.scriptPubKey);
  }

  // sha_prevouts
  let prevoutsData = new Uint8Array(tx.inputs.length * 36);
  for (let i = 0; i < tx.inputs.length; i++) {
    prevoutsData.set(tx.inputs[i].txid, i * 36);
    prevoutsData.set(writeUint32LE(tx.inputs[i].vout), i * 36 + 32);
  }
  const shaPrevouts = sha256(prevoutsData);

  // sha_amounts
  const amountsData = new Uint8Array(tx.inputs.length * 8);
  for (let i = 0; i < tx.inputs.length; i++) {
    amountsData.set(writeUint64LE(inputValues[i]), i * 8);
  }
  const shaAmounts = sha256(amountsData);

  // sha_scriptpubkeys
  const scriptParts: Uint8Array[] = [];
  for (const spk of inputScriptPubKeys) {
    scriptParts.push(writeVarInt(spk.length));
    scriptParts.push(spk);
  }
  const shaScriptPubKeys = sha256(concatBytes(...scriptParts));

  // sha_sequences
  let sequenceData = new Uint8Array(tx.inputs.length * 4);
  for (let i = 0; i < tx.inputs.length; i++) {
    sequenceData.set(writeUint32LE(tx.inputs[i].sequence), i * 4);
  }
  const shaSequences = sha256(sequenceData);

  // sha_outputs
  const outputParts: Uint8Array[] = [];
  for (const output of tx.outputs) {
    outputParts.push(writeUint64LE(output.value));
    outputParts.push(writeVarInt(output.scriptPubKey.length));
    outputParts.push(output.scriptPubKey);
  }
  const shaOutputs = sha256(concatBytes(...outputParts));

  // Build SigMsg
  const epoch = 0x00;

  const parts: Uint8Array[] = [
    new Uint8Array([epoch]),
    new Uint8Array([sighashType]),
    writeUint32LE(tx.version),
    writeUint32LE(tx.locktime),
    shaPrevouts,
    shaAmounts,
    shaScriptPubKeys,
    shaSequences,
    shaOutputs,
    new Uint8Array([0x00]), // spend_type = 0 (no annex, key path)
    writeUint32LE(inputIndex),
  ];

  const sigMsg = concatBytes(...parts);

  // Tagged hash: SHA256(SHA256("TapSighash") || SHA256("TapSighash") || sigMsg)
  const tag = sha256(new TextEncoder().encode("TapSighash"));
  const tagged = concatBytes(tag, tag, sigMsg);
  return sha256(tagged);
}

/**
 * Calculate TapLeaf hash for script path spending.
 * TapLeaf hash = SHA256(SHA256("TapLeaf") || SHA256("TapLeaf") || version || script_len || script)
 */
export function calculateTapLeafHash(
  leafScript: Uint8Array,
  leafVersion: number = 0xc0 // Default Tapscript version
): Uint8Array {
  const tagHash = sha256(new TextEncoder().encode("TapLeaf"));
  const versionByte = new Uint8Array([leafVersion]);
  const scriptLenEncoded = writeVarInt(leafScript.length);
  
  const preimage = concatBytes(tagHash, tagHash, versionByte, scriptLenEncoded, leafScript);
  return sha256(preimage);
}

/**
 * Create a simple Tapscript for MPC signing: <pubkey> OP_CHECKSIG
 * This is used for script-path spending with MPC (since MPC doesn't support tweaked keys).
 */
export function createTapscriptForPubkey(xOnlyPubkey: Uint8Array): Uint8Array {
  if (xOnlyPubkey.length !== 32) {
    throw new Error("x-only public key must be 32 bytes");
  }
  // OP_PUSHBYTES_32 (0x20) + 32-byte pubkey + OP_CHECKSIG (0xac)
  return concatBytes(
    new Uint8Array([0x20]),
    xOnlyPubkey,
    new Uint8Array([0xac])
  );
}

/**
 * Compute BIP341/342 sighash for Taproot script-path spending.
 * This is required for MPC signing since MPC doesn't support tweaked keys.
 * 
 * @param psbt - Parsed PSBT
 * @param inputIndex - Input index to sign
 * @param leafHash - TapLeaf hash of the script being executed
 * @param sighashType - Sighash type (default: 0x00 = SIGHASH_DEFAULT)
 * @returns The preimage bytes (including TapSighash tag) ready for MPC signing
 */
export function computeTaprootScriptpathPreimage(
  psbt: ParsedPSBT,
  inputIndex: number,
  leafHash: Uint8Array,
  sighashType: number = 0x00
): Uint8Array {
  const tx = psbt.tx;
  const input = tx.inputs[inputIndex];

  // Collect all input values and scriptPubKeys
  const inputValues: bigint[] = [];
  const inputScriptPubKeys: Uint8Array[] = [];
  for (let i = 0; i < tx.inputs.length; i++) {
    const psbtInput = psbt.inputs[i];
    if (!psbtInput.witnessUtxo) {
      throw new Error(`Input ${i} missing witnessUtxo for Taproot sighash`);
    }
    inputValues.push(psbtInput.witnessUtxo.value);
    inputScriptPubKeys.push(psbtInput.witnessUtxo.scriptPubKey);
  }

  // Determine output/input types from sighash
  const outputType = sighashType === 0x00 ? SIGHASH_ALL : (sighashType & 0x03);
  const inputType = sighashType & 0x80;
  const isAnyoneCanPay = inputType === SIGHASH_ANYONECANPAY;
  const isNone = outputType === SIGHASH_NONE;
  const isSingle = outputType === SIGHASH_SINGLE;

  // sha_prevouts (if not ANYONECANPAY)
  let shaPrevouts = new Uint8Array(32);
  let shaAmounts = new Uint8Array(32);
  let shaScriptPubKeys = new Uint8Array(32);
  let shaSequences = new Uint8Array(32);

  if (!isAnyoneCanPay) {
    // sha_prevouts
    const prevoutsData = new Uint8Array(tx.inputs.length * 36);
    for (let i = 0; i < tx.inputs.length; i++) {
      prevoutsData.set(tx.inputs[i].txid, i * 36);
      prevoutsData.set(writeUint32LE(tx.inputs[i].vout), i * 36 + 32);
    }
    shaPrevouts = new Uint8Array(sha256(prevoutsData));

    // sha_amounts
    const amountsData = new Uint8Array(tx.inputs.length * 8);
    for (let i = 0; i < tx.inputs.length; i++) {
      amountsData.set(writeUint64LE(inputValues[i]), i * 8);
    }
    shaAmounts = new Uint8Array(sha256(amountsData));

    // sha_scriptpubkeys
    const scriptParts: Uint8Array[] = [];
    for (const spk of inputScriptPubKeys) {
      scriptParts.push(writeVarInt(spk.length));
      scriptParts.push(spk);
    }
    shaScriptPubKeys = new Uint8Array(sha256(concatBytes(...scriptParts)));

    // sha_sequences
    const sequenceData = new Uint8Array(tx.inputs.length * 4);
    for (let i = 0; i < tx.inputs.length; i++) {
      sequenceData.set(writeUint32LE(tx.inputs[i].sequence), i * 4);
    }
    shaSequences = new Uint8Array(sha256(sequenceData));
  }

  // sha_outputs
  let shaOutputs = new Uint8Array(32);
  if (!isNone && !isSingle) {
    const outputParts: Uint8Array[] = [];
    for (const output of tx.outputs) {
      outputParts.push(writeUint64LE(output.value));
      outputParts.push(writeVarInt(output.scriptPubKey.length));
      outputParts.push(output.scriptPubKey);
    }
    shaOutputs = new Uint8Array(sha256(concatBytes(...outputParts)));
  } else if (isSingle && inputIndex < tx.outputs.length) {
    const output = tx.outputs[inputIndex];
    const outputData = concatBytes(
      writeUint64LE(output.value),
      writeVarInt(output.scriptPubKey.length),
      output.scriptPubKey
    );
    shaOutputs = new Uint8Array(sha256(outputData));
  }

  // spend_type: bit 0 = annex present, bit 1 = script path
  const spendType = 0x02; // Script path, no annex

  // Build SigMsg parts
  const sigMsgParts: Uint8Array[] = [];

  // Hash type (1 byte)
  sigMsgParts.push(new Uint8Array([sighashType]));

  // Transaction data
  sigMsgParts.push(writeUint32LE(tx.version));
  sigMsgParts.push(writeUint32LE(tx.locktime));
  sigMsgParts.push(shaPrevouts);
  sigMsgParts.push(shaAmounts);
  sigMsgParts.push(shaScriptPubKeys);
  sigMsgParts.push(shaSequences);

  if (!isNone && !isSingle) {
    sigMsgParts.push(shaOutputs);
  }

  // Input-specific data
  sigMsgParts.push(new Uint8Array([spendType]));

  if (isAnyoneCanPay) {
    sigMsgParts.push(input.txid);
    sigMsgParts.push(writeUint32LE(input.vout));
    sigMsgParts.push(writeUint64LE(inputValues[inputIndex]));
    sigMsgParts.push(writeVarInt(inputScriptPubKeys[inputIndex].length));
    sigMsgParts.push(inputScriptPubKeys[inputIndex]);
    sigMsgParts.push(writeUint32LE(input.sequence));
  } else {
    sigMsgParts.push(writeUint32LE(inputIndex));
  }

  // Output (for SIGHASH_SINGLE)
  if (isSingle) {
    sigMsgParts.push(shaOutputs);
  }

  // BIP342 extension for script path (ext_flag = 1)
  sigMsgParts.push(leafHash); // 32 bytes
  sigMsgParts.push(new Uint8Array([0x00])); // key_version = 0
  sigMsgParts.push(writeUint32LE(0xffffffff)); // codesep_pos = 0xffffffff (no OP_CODESEPARATOR)

  const sigMsg = concatBytes(...sigMsgParts);

  // Build tagged hash preimage: tagHash || tagHash || 0x00 || sigMsg
  // The MPC will hash this with SHA256 to get the final TapSighash
  const tagHash = sha256(new TextEncoder().encode("TapSighash"));
  const preimage = concatBytes(tagHash, tagHash, new Uint8Array([0x00]), sigMsg);

  return preimage;
}

/**
 * Compute final TapSighash by hashing the preimage.
 */
export function computeTaprootScriptpathSighash(
  psbt: ParsedPSBT,
  inputIndex: number,
  leafHash: Uint8Array,
  sighashType: number = 0x00
): Uint8Array {
  const preimage = computeTaprootScriptpathPreimage(psbt, inputIndex, leafHash, sighashType);
  return sha256(preimage);
}

/**
 * Compute BIP341 sighash for Taproot inputs.
 * @deprecated Use computeTaprootKeypathSighash or computeTaprootScriptpathSighash instead.
 */
export function computeTaprootSighash(
  psbt: ParsedPSBT,
  inputIndex: number,
  sighashType: number = 0x00
): Uint8Array {
  // Default to key-path for backward compatibility
  return computeTaprootKeypathSighash(psbt, inputIndex, sighashType);
}

/**
 * Compute sighash for a PSBT input based on script type.
 */
export function computePSBTSighash(
  psbt: ParsedPSBT,
  inputIndex: number,
  sighashType?: number
): { hash: Uint8Array; scriptType: BitcoinScriptType } {
  const scriptType = detectScriptType(psbt, inputIndex);
  const input = psbt.inputs[inputIndex];

  switch (scriptType) {
    case BitcoinScriptType.P2TR: {
      const hash = computeTaprootSighash(psbt, inputIndex, sighashType ?? 0x00);
      return { hash, scriptType };
    }
    case BitcoinScriptType.P2WPKH: {
      if (!input.witnessUtxo) {
        throw new Error("Missing witnessUtxo for P2WPKH input");
      }
      // For P2WPKH, scriptCode is OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
      const pubkeyHash = input.witnessUtxo.scriptPubKey.slice(2); // Skip OP_0 and push byte
      const scriptCode = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
      const hash = computeSegwitSighash(
        psbt,
        inputIndex,
        input.witnessUtxo.value,
        scriptCode,
        sighashType ?? SIGHASH_ALL
      );
      return { hash, scriptType };
    }
    case BitcoinScriptType.P2PKH:
    default: {
      // Need the scriptPubKey from the UTXO
      let scriptPubKey: Uint8Array;
      if (input.witnessUtxo) {
        scriptPubKey = input.witnessUtxo.scriptPubKey;
      } else if (input.nonWitnessUtxo) {
        const utxoTx = parseRawTransaction(input.nonWitnessUtxo);
        const txInput = psbt.tx.inputs[inputIndex];
        scriptPubKey = utxoTx.outputs[txInput.vout].scriptPubKey;
      } else {
        throw new Error("Missing UTXO data for input");
      }
      const hash = computeLegacySighash(psbt, inputIndex, scriptPubKey, sighashType ?? SIGHASH_ALL);
      return { hash, scriptType };
    }
  }
}

/**
 * Extract UTXOs from PSBT.
 */
export function extractUTXOs(psbt: ParsedPSBT): BitcoinUTXO[] {
  const utxos: BitcoinUTXO[] = [];
  for (let i = 0; i < psbt.tx.inputs.length; i++) {
    const txInput = psbt.tx.inputs[i];
    const psbtInput = psbt.inputs[i];

    let value: bigint;
    let scriptPubKey: Uint8Array;

    if (psbtInput.witnessUtxo) {
      value = psbtInput.witnessUtxo.value;
      scriptPubKey = psbtInput.witnessUtxo.scriptPubKey;
    } else if (psbtInput.nonWitnessUtxo) {
      const utxoTx = parseRawTransaction(psbtInput.nonWitnessUtxo);
      const output = utxoTx.outputs[txInput.vout];
      value = output.value;
      scriptPubKey = output.scriptPubKey;
    } else {
      throw new Error(`Input ${i} missing UTXO data`);
    }

    utxos.push({
      txid: bytesToHex(txInput.txid.slice().reverse()), // Convert to big-endian hex
      vout: txInput.vout,
      value,
      scriptPubKey,
      witnessUtxo: psbtInput.witnessUtxo
        ? { script: psbtInput.witnessUtxo.scriptPubKey, value: psbtInput.witnessUtxo.value }
        : undefined,
    });
  }
  return utxos;
}

/**
 * Helper to convert hex to bytes.
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
 * Helper to convert bytes to hex.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Helper to concatenate byte arrays.
 */
function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}
