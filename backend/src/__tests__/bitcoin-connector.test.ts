/**
 * Bitcoin Connector Tests
 *
 * Unit tests for Bitcoin PSBT parsing, address derivation, and sighash computation.
 */

import { describe, test, expect } from "bun:test";
import {
  BitcoinConnector,
  createBitcoinConnector,
  deriveBitcoinAddress,
  validateBitcoinAddress,
} from "../chains/bitcoin/index.js";
import { BitcoinScriptType, ChainNamespace, Curve, SignatureAlgorithm } from "../chains/types.js";

describe("BitcoinConnector", () => {
  describe("initialization", () => {
    test("creates connector for mainnet", () => {
      const connector = createBitcoinConnector("mainnet");
      expect(connector.namespace).toBe(ChainNamespace.BITCOIN);
      expect(connector.chainId).toBe("mainnet");
      expect(connector.curve).toBe(Curve.SECP256K1);
    });

    test("creates connector for testnet", () => {
      const connector = createBitcoinConnector("testnet");
      expect(connector.chainId).toBe("testnet");
    });

    test("creates connector for signet", () => {
      const connector = createBitcoinConnector("signet");
      expect(connector.chainId).toBe("signet");
    });
  });

  describe("address derivation", () => {
    // Sample compressed public key (33 bytes)
    const compressedPubkey = new Uint8Array([
      0x02, // prefix for even y-coordinate
      0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
      0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
      0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
      0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    ]);

    test("derives P2PKH address for mainnet", () => {
      const address = deriveBitcoinAddress(compressedPubkey, BitcoinScriptType.P2PKH, "mainnet");
      expect(address).toMatch(/^1[a-zA-Z0-9]{25,34}$/);
    });

    test("derives P2WPKH address for mainnet", () => {
      const address = deriveBitcoinAddress(compressedPubkey, BitcoinScriptType.P2WPKH, "mainnet");
      expect(address).toMatch(/^bc1q[a-z0-9]{38,}$/);
    });

    test("derives P2WPKH address for testnet", () => {
      const address = deriveBitcoinAddress(compressedPubkey, BitcoinScriptType.P2WPKH, "testnet");
      expect(address).toMatch(/^tb1q[a-z0-9]{38,}$/);
    });

    test("derives P2TR address for mainnet", () => {
      const address = deriveBitcoinAddress(compressedPubkey, BitcoinScriptType.P2TR, "mainnet");
      expect(address).toMatch(/^bc1p[a-z0-9]{58,}$/);
    });
  });

  describe("address validation", () => {
    const connector = createBitcoinConnector("mainnet");
    const testnetConnector = createBitcoinConnector("testnet");

    test("validates mainnet P2PKH address", () => {
      const result = validateBitcoinAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "mainnet");
      expect(result.valid).toBe(true);
      expect(result.type).toBe(BitcoinScriptType.P2PKH);
    });

    test("validates mainnet P2WPKH address", () => {
      const result = validateBitcoinAddress("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet");
      expect(result.valid).toBe(true);
      expect(result.type).toBe(BitcoinScriptType.P2WPKH);
    });

    test("validates mainnet P2TR address", () => {
      // Using a sample P2TR address
      const result = validateBitcoinAddress("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "mainnet");
      expect(result.valid).toBe(true);
      expect(result.type).toBe(BitcoinScriptType.P2TR);
    });

    test("validates testnet P2WPKH address", () => {
      const result = validateBitcoinAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet");
      expect(result.valid).toBe(true);
      expect(result.type).toBe(BitcoinScriptType.P2WPKH);
    });

    test("rejects invalid address", () => {
      const result = validateBitcoinAddress("invalid-address", "mainnet");
      expect(result.valid).toBe(false);
    });

    test("connector validateAddress method", () => {
      expect(connector.validateAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")).toBe(true);
      expect(connector.validateAddress("invalid")).toBe(false);
    });
  });

  describe("signature algorithm selection", () => {
    const connector = createBitcoinConnector("mainnet");

    test("returns ECDSA for P2PKH", () => {
      const algo = connector.getSignatureAlgorithmForScriptType(BitcoinScriptType.P2PKH);
      expect(algo).toBe(SignatureAlgorithm.ECDSA);
    });

    test("returns ECDSA for P2WPKH", () => {
      const algo = connector.getSignatureAlgorithmForScriptType(BitcoinScriptType.P2WPKH);
      expect(algo).toBe(SignatureAlgorithm.ECDSA);
    });

    test("returns SCHNORR for P2TR", () => {
      const algo = connector.getSignatureAlgorithmForScriptType(BitcoinScriptType.P2TR);
      expect(algo).toBe(SignatureAlgorithm.SCHNORR);
    });
  });
});
