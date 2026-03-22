/**
 * Chain Types Tests
 *
 * Unit tests for chain connector types and registry.
 */

import { describe, test, expect } from "bun:test";
import {
  ChainNamespace,
  BitcoinScriptType,
  Curve,
  SignatureAlgorithm,
  namespaceToString,
  parseNamespace,
  getCurveForNamespace,
  getSignatureAlgorithmForNamespace,
} from "../chains/types.js";
import {
  chainConnectorRegistry,
  getConnectorOrThrow,
  hasConnector,
} from "../chains/registry.js";
import { createBitcoinConnector } from "../chains/bitcoin/index.js";
import { createSolanaConnector } from "../chains/solana/index.js";

describe("ChainNamespace", () => {
  test("has correct values", () => {
    expect(ChainNamespace.EVM).toBe(1);
    expect(ChainNamespace.BITCOIN).toBe(2);
    expect(ChainNamespace.SOLANA).toBe(3);
  });

  test("namespaceToString converts correctly", () => {
    expect(namespaceToString(ChainNamespace.EVM)).toBe("evm");
    expect(namespaceToString(ChainNamespace.BITCOIN)).toBe("bitcoin");
    expect(namespaceToString(ChainNamespace.SOLANA)).toBe("solana");
    expect(namespaceToString(99 as ChainNamespace)).toBe("unknown-99");
  });

  test("parseNamespace parses correctly", () => {
    expect(parseNamespace("evm")).toBe(ChainNamespace.EVM);
    expect(parseNamespace("EVM")).toBe(ChainNamespace.EVM);
    expect(parseNamespace("ethereum")).toBe(ChainNamespace.EVM);
    expect(parseNamespace("bitcoin")).toBe(ChainNamespace.BITCOIN);
    expect(parseNamespace("btc")).toBe(ChainNamespace.BITCOIN);
    expect(parseNamespace("solana")).toBe(ChainNamespace.SOLANA);
    expect(parseNamespace("sol")).toBe(ChainNamespace.SOLANA);
    expect(parseNamespace("unknown")).toBeNull();
  });
});

describe("Curves and Algorithms", () => {
  test("getCurveForNamespace returns correct curves", () => {
    expect(getCurveForNamespace(ChainNamespace.EVM)).toBe(Curve.SECP256K1);
    expect(getCurveForNamespace(ChainNamespace.BITCOIN)).toBe(Curve.SECP256K1);
    expect(getCurveForNamespace(ChainNamespace.SOLANA)).toBe(Curve.ED25519);
  });

  test("getCurveForNamespace throws for unknown namespace", () => {
    expect(() => getCurveForNamespace(99 as ChainNamespace)).toThrow("Unknown namespace");
  });

  test("getSignatureAlgorithmForNamespace returns correct algorithms", () => {
    expect(getSignatureAlgorithmForNamespace(ChainNamespace.EVM)).toBe(SignatureAlgorithm.ECDSA);
    expect(getSignatureAlgorithmForNamespace(ChainNamespace.BITCOIN)).toBe(SignatureAlgorithm.ECDSA);
    expect(getSignatureAlgorithmForNamespace(ChainNamespace.SOLANA)).toBe(SignatureAlgorithm.ED25519);
  });

  test("Bitcoin Taproot uses Schnorr", () => {
    const algo = getSignatureAlgorithmForNamespace(ChainNamespace.BITCOIN, {
      btcScriptType: BitcoinScriptType.P2TR,
    });
    expect(algo).toBe(SignatureAlgorithm.SCHNORR);
  });
});

describe("ChainConnectorRegistry", () => {
  test("registers and retrieves Bitcoin connector", () => {
    const connector = createBitcoinConnector("testnet");
    chainConnectorRegistry.registerConnector(connector);
    
    const retrieved = chainConnectorRegistry.getConnector(ChainNamespace.BITCOIN, "testnet");
    expect(retrieved).toBe(connector);
  });

  test("registers and retrieves Solana connector", () => {
    const connector = createSolanaConnector("devnet");
    chainConnectorRegistry.registerConnector(connector);
    
    const retrieved = chainConnectorRegistry.getConnector(ChainNamespace.SOLANA, "devnet");
    expect(retrieved).toBe(connector);
  });

  test("hasConnector returns false for unregistered connector", () => {
    expect(hasConnector(ChainNamespace.EVM, 999999)).toBe(false);
  });

  test("getConnectorOrThrow throws for missing connector", () => {
    expect(() => getConnectorOrThrow(ChainNamespace.EVM, 999999)).toThrow("No connector registered");
  });

  test("listConnectors returns all registered connectors", () => {
    const connectors = chainConnectorRegistry.listConnectors();
    expect(Array.isArray(connectors)).toBe(true);
  });
});

describe("BitcoinScriptType", () => {
  test("has correct values", () => {
    expect(BitcoinScriptType.P2PKH).toBe(0);
    expect(BitcoinScriptType.P2WPKH).toBe(1);
    expect(BitcoinScriptType.P2TR).toBe(2);
  });
});
