/**
 * Bitcoin Chain Connector
 *
 * Implements the ChainConnector interface for Bitcoin.
 * Handles PSBT parsing, sighash computation, address derivation, and broadcasting.
 */

import { bech32, bech32m } from "bech32";
import * as bitcoin from "bitcoinjs-lib";
import * as ecc from "tiny-secp256k1";
import { logger } from "../../logger.js";
import {
  type ChainConnector,
  type ParsedTransaction,
  type TxParams,
  type BroadcastResult,
  ChainNamespace,
  BitcoinScriptType,
  Curve,
  SignatureAlgorithm,
  type BitcoinNetwork,
} from "../types.js";
import {
  getBitcoinNetworkConfig,
  getBroadcastUrl,
  getFeeEstimateUrl,
  type BitcoinNetworkConfig,
} from "./config.js";
import { deriveBitcoinAddress, validateBitcoinAddress, base58CheckEncode } from "./address.js";
import {
  parsePSBT,
  computePSBTSighash,
  computeTaprootScriptpathPreimage,
  calculateTapLeafHash,
  createTapscriptForPubkey,
  computeLegacySighashPrehash,
  computeSegwitSighashPrehash,
  detectScriptType,
  parseRawTransaction,
  extractUTXOs,
  hexToBytes,
  bytesToHex,
  type ParsedPSBT,
  type TapScriptPathData,
  SIGHASH_ALL,
} from "./psbt.js";

/**
 * Bitcoin connector implementation.
 */
export class BitcoinConnector implements ChainConnector {
  readonly namespace = ChainNamespace.BITCOIN;
  readonly curve = Curve.SECP256K1;

  private config: BitcoinNetworkConfig;
  private parsedPSBTCache = new Map<string, ParsedPSBT>();
  private static bitcoinJsInitialized = false;

  constructor(
    readonly chainId: BitcoinNetwork,
    private readonly apiUrl?: string
  ) {
    this.config = getBitcoinNetworkConfig(chainId);
    if (apiUrl) {
      this.config = {
        ...this.config,
        apiEndpoints: {
          ...this.config.apiEndpoints,
          mempool: apiUrl,
        },
      };
    }
  }

  private static ensureBitcoinJsInitialized(): void {
    if (BitcoinConnector.bitcoinJsInitialized) return;
    // bitcoinjs-lib v7 requires explicit ECC library init.
    (bitcoin as any).initEccLib?.(ecc);
    BitcoinConnector.bitcoinJsInitialized = true;
  }

  /**
   * Get signature algorithm based on script type.
   */
  get signatureAlgorithm(): SignatureAlgorithm {
    // Default to ECDSA; actual algorithm determined per-input
    return SignatureAlgorithm.ECDSA;
  }

  /**
   * Get signature algorithm for a specific script type.
   */
  getSignatureAlgorithmForScriptType(scriptType: BitcoinScriptType): SignatureAlgorithm {
    if (scriptType === BitcoinScriptType.P2TR) {
      return SignatureAlgorithm.SCHNORR;
    }
    return SignatureAlgorithm.ECDSA;
  }

  /**
   * Parse a PSBT and extract policy-relevant fields.
   */
  async parseTransaction(rawTx: Uint8Array | string): Promise<ParsedTransaction> {
    const psbtHex = typeof rawTx === "string" ? rawTx : bytesToHex(rawTx);
    const psbt = parsePSBT(psbtHex);

    // Cache for later use
    this.parsedPSBTCache.set(psbtHex, psbt);

    // Extract destinations and amounts from outputs
    const destinations: string[] = [];
    const amounts: bigint[] = [];

    for (const output of psbt.tx.outputs) {
      try {
        const address = this.scriptPubKeyToAddress(output.scriptPubKey);
        destinations.push(address);
        amounts.push(output.value);
      } catch (e) {
        // Skip outputs we can't decode (e.g., OP_RETURN)
        logger.debug({ error: e }, "Could not decode output address");
      }
    }

    // Compute sighash for the first input (for policy verification)
    // In practice, you might need to handle multiple inputs with different sighashes
    const { hash: intentHash, scriptType } = computePSBTSighash(psbt, 0);

    // Extract UTXOs
    const utxos = extractUTXOs(psbt);

    return {
      namespace: this.namespace,
      chainId: this.chainId,
      destinations,
      amounts,
      intentHash,
      rawBytes: typeof rawTx === "string" ? hexToBytes(rawTx) : rawTx,
      btc: {
        utxos,
        scriptType,
        locktime: psbt.tx.locktime,
      },
    };
  }

  /**
   * Convert scriptPubKey to address.
   */
  private scriptPubKeyToAddress(scriptPubKey: Uint8Array): string {
    // P2WPKH: OP_0 <20-byte-hash>
    if (scriptPubKey.length === 22 && scriptPubKey[0] === 0x00 && scriptPubKey[1] === 0x14) {
      const words = bech32.toWords(scriptPubKey.slice(2));
      words.unshift(0);
      return bech32.encode(this.config.bech32, words);
    }

    // P2TR: OP_1 <32-byte-key>
    if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
      const words = bech32m.toWords(scriptPubKey.slice(2));
      words.unshift(1);
      return bech32m.encode(this.config.bech32m, words);
    }

    // P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    if (
      scriptPubKey.length === 25 &&
      scriptPubKey[0] === 0x76 &&
      scriptPubKey[1] === 0xa9 &&
      scriptPubKey[2] === 0x14 &&
      scriptPubKey[23] === 0x88 &&
      scriptPubKey[24] === 0xac
    ) {
      const payload = new Uint8Array(21);
      payload[0] = this.config.pubKeyHash;
      payload.set(scriptPubKey.slice(3, 23), 1);
      return base58CheckEncode(payload);
    }

    throw new Error("Unknown scriptPubKey format");
  }

  /**
   * Compute intent hash for a parsed transaction.
   */
  computeIntentHash(parsedTx: ParsedTransaction): Uint8Array {
    // Intent hash is already computed during parsing
    return parsedTx.intentHash;
  }

  /**
   * Derive Bitcoin address from public key.
   */
  deriveAddress(publicKey: Uint8Array, options?: Record<string, unknown>): string {
    const scriptType = (options?.scriptType as BitcoinScriptType) ?? BitcoinScriptType.P2WPKH;
    return deriveBitcoinAddress(publicKey, scriptType, this.chainId);
  }

  /**
   * Format raw signature for Bitcoin.
   * For ECDSA: Convert to DER encoding with sighash type appended.
   * For Schnorr: Use 64-byte signature directly.
   */
  formatSignature(rawSig: Uint8Array, parsedTx: ParsedTransaction): Uint8Array {
    const scriptType = parsedTx.btc?.scriptType ?? BitcoinScriptType.P2WPKH;

    if (scriptType === BitcoinScriptType.P2TR) {
      // Schnorr: 64-byte signature, optionally with sighash type if not DEFAULT
      return rawSig;
    }

    // ECDSA: Convert r,s to DER format
    const r = rawSig.slice(0, 32);
    const s = rawSig.slice(32, 64);

    const derSig = this.toDER(r, s);

    // Append sighash type
    const result = new Uint8Array(derSig.length + 1);
    result.set(derSig);
    result[derSig.length] = SIGHASH_ALL;

    return result;
  }

  /**
   * Convert r,s to DER format.
   */
  private toDER(r: Uint8Array, s: Uint8Array): Uint8Array {
    // Remove leading zeros and ensure positive
    let rTrimmed = this.trimLeadingZeros(r);
    let sTrimmed = this.trimLeadingZeros(s);

    // Add leading zero if high bit is set (to ensure positive integer)
    if (rTrimmed[0] & 0x80) {
      const newR = new Uint8Array(rTrimmed.length + 1);
      newR.set(rTrimmed, 1);
      rTrimmed = newR;
    }
    if (sTrimmed[0] & 0x80) {
      const newS = new Uint8Array(sTrimmed.length + 1);
      newS.set(sTrimmed, 1);
      sTrimmed = newS;
    }

    // DER structure: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
    const totalLength = 2 + rTrimmed.length + 2 + sTrimmed.length;
    const der = new Uint8Array(2 + totalLength);
    let offset = 0;

    der[offset++] = 0x30; // SEQUENCE
    der[offset++] = totalLength;
    der[offset++] = 0x02; // INTEGER
    der[offset++] = rTrimmed.length;
    der.set(rTrimmed, offset);
    offset += rTrimmed.length;
    der[offset++] = 0x02; // INTEGER
    der[offset++] = sTrimmed.length;
    der.set(sTrimmed, offset);

    return der;
  }

  /**
   * Trim leading zeros from a byte array.
   */
  private trimLeadingZeros(bytes: Uint8Array): Uint8Array {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) {
      start++;
    }
    return bytes.slice(start);
  }

  /**
   * Inject signature into PSBT for a specific input.
   * Returns updated PSBT bytes (not finalized).
   * 
   * Note: For full PSBT finalization and extraction, use injectAndFinalizePSBT.
   */
  injectSignature(parsedTx: ParsedTransaction, signature: Uint8Array): Uint8Array {
    logger.warn(
      "injectSignature returns raw bytes; use injectSignatureIntoPSBT for proper PSBT handling"
    );
    return parsedTx.rawBytes;
  }

  /**
   * Inject signature(s) into PSBT and optionally finalize.
   * This is the main method for completing Bitcoin transactions after MPC signing.
   */
  injectSignatureIntoPSBT(
    psbtHex: string,
    inputIndex: number,
    signature: Uint8Array,
    publicKey: Uint8Array,
    scriptType: BitcoinScriptType,
    options?: {
      finalize?: boolean;
      sighashType?: number;
      leafHash?: Uint8Array;
      leafScript?: Uint8Array;
      controlBlock?: Uint8Array;
    }
  ): {
    psbtHex: string;
    txHex?: string;
  } {
    const psbt = parsePSBT(psbtHex);
    const input = psbt.inputs[inputIndex];
    
    if (!input) {
      throw new Error(`Input ${inputIndex} not found in PSBT`);
    }

    // Format signature based on script type
    const formattedSig = this.formatSignatureForType(signature, scriptType, options?.sighashType);

    // Build the signed PSBT data
    // Since we're working with raw bytes, we need to serialize back to PSBT format
    // For now, we'll return the formatted components that can be used by bitcoinjs-lib
    
    const signatureData = {
      inputIndex,
      signature: formattedSig,
      publicKey,
      scriptType,
      leafHash: options?.leafHash,
      leafScript: options?.leafScript,
      controlBlock: options?.controlBlock,
    };

    logger.info(
      {
        inputIndex,
        scriptType,
        signatureLength: formattedSig.length,
        publicKeyLength: publicKey.length,
      },
      "Prepared signature for PSBT injection"
    );

    // For full PSBT manipulation, the caller should use bitcoinjs-lib
    // We return the hex unchanged with metadata about what needs to be injected
    return {
      psbtHex,
      txHex: undefined, // Would be set if finalize=true and we had full PSBT support
    };
  }

  /**
   * Format signature for a specific script type.
   */
  formatSignatureForType(
    rawSig: Uint8Array,
    scriptType: BitcoinScriptType,
    sighashType?: number
  ): Uint8Array {
    if (scriptType === BitcoinScriptType.P2TR) {
      // Schnorr: 64-byte signature
      // Append sighash type only if not SIGHASH_DEFAULT (0x00)
      if (sighashType && sighashType !== 0x00) {
        const result = new Uint8Array(rawSig.length + 1);
        result.set(rawSig);
        result[rawSig.length] = sighashType;
        return result;
      }
      return rawSig;
    }

    // ECDSA: Convert r,s to DER format and append sighash type
    const r = rawSig.slice(0, 32);
    const s = rawSig.slice(32, 64);
    const derSig = this.toDER(r, s);

    const result = new Uint8Array(derSig.length + 1);
    result.set(derSig);
    result[derSig.length] = sighashType ?? SIGHASH_ALL;

    return result;
  }

  /**
   * Build witness data for different script types.
   * Returns the witness stack as an array of byte arrays.
   */
  buildWitness(
    signature: Uint8Array,
    publicKey: Uint8Array,
    scriptType: BitcoinScriptType,
    options?: {
      leafScript?: Uint8Array;
      controlBlock?: Uint8Array;
    }
  ): Uint8Array[] {
    switch (scriptType) {
      case BitcoinScriptType.P2TR:
        if (options?.leafScript && options?.controlBlock) {
          // Script-path spending: [signature, script, controlBlock]
          return [signature, options.leafScript, options.controlBlock];
        }
        // Key-path spending: [signature]
        return [signature];

      case BitcoinScriptType.P2WPKH:
        // Native SegWit: [signature, pubkey]
        return [signature, publicKey];

      case BitcoinScriptType.P2PKH:
      default:
        // P2PKH doesn't use witness
        return [];
    }
  }

  /**
   * Build scriptSig for legacy P2PKH.
   */
  buildScriptSig(signature: Uint8Array, publicKey: Uint8Array): Uint8Array {
    // scriptSig format: <sig-len> <signature> <pubkey-len> <pubkey>
    const sigLen = signature.length;
    const pubLen = publicKey.length;
    
    const result = new Uint8Array(1 + sigLen + 1 + pubLen);
    let offset = 0;
    
    result[offset++] = sigLen;
    result.set(signature, offset);
    offset += sigLen;
    
    result[offset++] = pubLen;
    result.set(publicKey, offset);
    
    return result;
  }

  /**
   * Compute the message bytes to provide to Ika MPC signing for ECDSA inputs.
   *
   * IMPORTANT: Ika signing flows apply Hash.SHA256 to the provided message bytes before signing.
   * Bitcoin ECDSA signatures require a double-SHA256 (hash256) of the sighash preimage.
   *
   * To achieve hash256(preimage), we provide SHA256(preimage) and let Ika apply SHA256 again.
   */
  getEcdsaMessageForIkaSigning(
    psbtHex: string,
    inputIndex: number,
    sighashType: number = SIGHASH_ALL
  ): Uint8Array {
    const psbt = parsePSBT(psbtHex);
    const scriptType = detectScriptType(psbt, inputIndex);
    const input = psbt.inputs[inputIndex];
    if (!input) throw new Error(`Input ${inputIndex} not found`);

    if (scriptType === BitcoinScriptType.P2WPKH) {
      if (!input.witnessUtxo) throw new Error("Missing witnessUtxo for P2WPKH");
      const pubkeyHash = input.witnessUtxo.scriptPubKey.slice(2);
      const scriptCode = new Uint8Array([0x76, 0xa9, 0x14, ...pubkeyHash, 0x88, 0xac]);
      return computeSegwitSighashPrehash(
        psbt,
        inputIndex,
        input.witnessUtxo.value,
        scriptCode,
        sighashType
      );
    }

    // Legacy P2PKH
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
    return computeLegacySighashPrehash(psbt, inputIndex, scriptPubKey, sighashType);
  }

  /**
   * Finalize a PSBT by injecting the signature for one input and extracting the raw tx hex.
   *
   * This uses bitcoinjs-lib and supports:
   * - P2PKH (legacy): scriptSig
   * - P2WPKH: witness stack
   * - P2TR: script-path witness (signature + tapscript + control block)
   */
  finalizeSignedPsbt(params: {
    psbtHex: string;
    inputIndex: number;
    scriptType: BitcoinScriptType;
    signature: Uint8Array; // raw (64 bytes from MPC)
    publicKey: Uint8Array; // 33B compressed for ECDSA; 32/33 for Taproot
    sighashType?: number;
  }): { psbtHex: string; txHex: string } {
    BitcoinConnector.ensureBitcoinJsInitialized();

    const psbtBuf = Buffer.from(params.psbtHex, "hex");
    const psbt = bitcoin.Psbt.fromBuffer(psbtBuf, { network: this.chainId === "mainnet" ? bitcoin.networks.bitcoin : bitcoin.networks.testnet });

    const inputIndex = params.inputIndex;
    const sighashType = params.sighashType ?? (params.scriptType === BitcoinScriptType.P2TR ? 0x00 : SIGHASH_ALL);

    if (params.scriptType === BitcoinScriptType.P2TR) {
      const tap = this.prepareTaprootScriptPath(params.publicKey);
      const sig = this.formatSignatureForType(params.signature, BitcoinScriptType.P2TR, sighashType);
      const xOnly = Buffer.from(this.toXOnlyPubkey(params.publicKey));

      psbt.updateInput(inputIndex, {
        tapInternalKey: Buffer.from(tap.controlBlock.slice(1, 33)), // internal key is bytes 1..32 of control block
        tapLeafScript: [
          {
            leafVersion: tap.leafVersion,
            script: Buffer.from(tap.leafScript),
            controlBlock: Buffer.from(tap.controlBlock),
          },
        ],
        tapScriptSig: [
          {
            pubkey: xOnly,
            signature: Buffer.from(sig),
            leafHash: Buffer.from(tap.leafHash),
          },
        ],
      });
    } else if (params.scriptType === BitcoinScriptType.P2WPKH) {
      const sig = this.formatSignatureForType(params.signature, BitcoinScriptType.P2WPKH, sighashType);
      psbt.updateInput(inputIndex, {
        partialSig: [
          {
            pubkey: Buffer.from(params.publicKey),
            signature: Buffer.from(sig),
          },
        ],
      });
    } else {
      // P2PKH
      const sig = this.formatSignatureForType(params.signature, BitcoinScriptType.P2PKH, sighashType);
      psbt.updateInput(inputIndex, {
        partialSig: [
          {
            pubkey: Buffer.from(params.publicKey),
            signature: Buffer.from(sig),
          },
        ],
      });
    }

    psbt.finalizeAllInputs();
    const tx = psbt.extractTransaction();

    return {
      psbtHex: Buffer.from(psbt.toBuffer()).toString("hex"),
      txHex: tx.toHex(),
    };
  }

  /**
   * Get the x-only public key (32 bytes) from a compressed public key (33 bytes).
   */
  toXOnlyPubkey(compressedPubkey: Uint8Array): Uint8Array {
    if (compressedPubkey.length === 32) {
      return compressedPubkey;
    }
    if (compressedPubkey.length === 33) {
      return compressedPubkey.slice(1);
    }
    throw new Error(`Invalid public key length: ${compressedPubkey.length}`);
  }

  /**
   * Prepare Taproot script-path data for MPC signing.
   * Creates a simple <pubkey> OP_CHECKSIG tapscript.
   * 
   * @param publicKey - The compressed or x-only public key
   * @returns TapScriptPathData with script, leaf hash, and control block info
   */
  prepareTaprootScriptPath(publicKey: Uint8Array): TapScriptPathData {
    const xOnlyPubkey = this.toXOnlyPubkey(publicKey);
    const leafScript = createTapscriptForPubkey(xOnlyPubkey);
    const leafVersion = 0xc0; // Tapscript version
    const leafHash = calculateTapLeafHash(leafScript, leafVersion);

    // NUMS point (Nothing Up My Sleeve) - SHA256("H") - used as internal pubkey
    // This is provably unspendable since nobody knows the discrete log
    const numsPoint = hexToBytes("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

    // Control block: [leaf_version | parity_bit] || internal_pubkey || merkle_path
    // For a single-leaf tree, merkle_path is empty
    // Parity bit is 0 for even Y coordinate (we use NUMS which has even Y)
    const controlBlock = new Uint8Array(33);
    controlBlock[0] = leafVersion; // c0 already encodes even parity
    controlBlock.set(numsPoint, 1);

    return {
      leafScript,
      leafVersion,
      controlBlock,
      leafHash,
    };
  }

  /**
   * Get the Taproot preimage for script-path signing.
   * This is what MPC should sign (will be hashed with SHA256).
   */
  getTaprootScriptpathPreimage(
    psbtHex: string,
    inputIndex: number,
    publicKey: Uint8Array,
    sighashType: number = 0x00
  ): {
    preimage: Uint8Array;
    leafHash: Uint8Array;
    tapScriptData: TapScriptPathData;
  } {
    const psbt = parsePSBT(psbtHex);
    const tapScriptData = this.prepareTaprootScriptPath(publicKey);
    const preimage = computeTaprootScriptpathPreimage(
      psbt,
      inputIndex,
      tapScriptData.leafHash,
      sighashType
    );

    return {
      preimage,
      leafHash: tapScriptData.leafHash,
      tapScriptData,
    };
  }

  /**
   * Get all sighashes for a PSBT (for multi-input signing).
   */
  getAllSighashes(psbtHex: string, publicKey?: Uint8Array): Array<{
    inputIndex: number;
    sighash: Uint8Array;
    scriptType: BitcoinScriptType;
    preimage?: Uint8Array;
    tapScriptData?: TapScriptPathData;
  }> {
    const psbt = parsePSBT(psbtHex);
    const results: Array<{
      inputIndex: number;
      sighash: Uint8Array;
      scriptType: BitcoinScriptType;
      preimage?: Uint8Array;
      tapScriptData?: TapScriptPathData;
    }> = [];

    for (let i = 0; i < psbt.inputs.length; i++) {
      const { hash, scriptType } = computePSBTSighash(psbt, i);

      if (scriptType === BitcoinScriptType.P2TR && publicKey) {
        // For Taproot, also compute the preimage for MPC
        const { preimage, tapScriptData } = this.getTaprootScriptpathPreimage(
          psbtHex,
          i,
          publicKey
        );
        results.push({
          inputIndex: i,
          sighash: hash,
          scriptType,
          preimage,
          tapScriptData,
        });
      } else {
        results.push({
          inputIndex: i,
          sighash: hash,
          scriptType,
        });
      }
    }

    return results;
  }

  /**
   * Broadcast signed transaction to the Bitcoin network.
   */
  async broadcast(signedTx: Uint8Array): Promise<BroadcastResult> {
    const txHex = bytesToHex(signedTx);
    const url = getBroadcastUrl(this.config);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: txHex,
      });

      if (!response.ok) {
        const error = await response.text();
        logger.error({ error, url }, "Failed to broadcast Bitcoin transaction");
        return { success: false, txHash: "", error };
      }

      const txid = await response.text();
      logger.info({ txid, network: this.chainId }, "Bitcoin transaction broadcast successful");

      return { success: true, txHash: txid };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error({ error, url }, "Failed to broadcast Bitcoin transaction");
      return { success: false, txHash: "", error: message };
    }
  }

  /**
   * Get current fee estimates.
   */
  async getTxParams(address: string): Promise<TxParams> {
    const url = getFeeEstimateUrl(this.config);

    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`Failed to fetch fee estimates: ${response.status}`);
      }

      const data = await response.json();

      // Mempool.space format
      if (data.fastestFee && data.halfHourFee && data.hourFee) {
        return {
          fee: {
            suggested: String(data.halfHourFee), // sat/vB
            minimum: String(data.hourFee),
            maximum: String(data.fastestFee),
          },
        };
      }

      // Blockstream format (returns object with block targets)
      if (typeof data === "object" && data["1"]) {
        return {
          fee: {
            suggested: String(Math.ceil(data["6"] || 10)),
            minimum: String(Math.ceil(data["25"] || 1)),
            maximum: String(Math.ceil(data["1"] || 50)),
          },
        };
      }

      // Default fallback
      return {
        fee: {
          suggested: "10",
          minimum: "1",
          maximum: "50",
        },
      };
    } catch (error) {
      logger.warn({ error }, "Failed to fetch Bitcoin fee estimates, using defaults");
      return {
        fee: {
          suggested: "10",
          minimum: "1",
          maximum: "50",
        },
      };
    }
  }

  /**
   * Validate a Bitcoin address.
   */
  validateAddress(address: string): boolean {
    const result = validateBitcoinAddress(address, this.chainId);
    return result.valid;
  }
}

/**
 * Create a Bitcoin connector for the specified network.
 */
export function createBitcoinConnector(
  network: BitcoinNetwork,
  apiUrl?: string
): BitcoinConnector {
  return new BitcoinConnector(network, apiUrl);
}
