/**
 * Solana Connector Tests
 *
 * Unit tests for Solana transaction parsing, address derivation, and validation.
 */

import { describe, test, expect } from "bun:test";
import { sha256 } from "@noble/hashes/sha256";
import {
  SolanaConnector,
  createSolanaConnector,
  PROGRAM_IDS,
  getProgramName,
  isTokenProgram,
  isSafeProgram,
} from "../chains/solana/index.js";
import { ChainNamespace, Curve, SignatureAlgorithm } from "../chains/types.js";

describe("SolanaConnector", () => {
  describe("initialization", () => {
    test("creates connector for mainnet-beta", () => {
      const connector = createSolanaConnector("mainnet-beta");
      expect(connector.namespace).toBe(ChainNamespace.SOLANA);
      expect(connector.chainId).toBe("mainnet-beta");
      expect(connector.curve).toBe(Curve.ED25519);
      expect(connector.signatureAlgorithm).toBe(SignatureAlgorithm.ED25519);
    });

    test("creates connector for devnet", () => {
      const connector = createSolanaConnector("devnet");
      expect(connector.chainId).toBe("devnet");
    });

    test("creates connector for testnet", () => {
      const connector = createSolanaConnector("testnet");
      expect(connector.chainId).toBe("testnet");
    });
  });

  describe("message bytes + intent hash", () => {
    test("getMessageBytes matches parsed intent hash (synthetic tx)", async () => {
      const connector = createSolanaConnector("devnet");

      // Construct a minimal Solana tx:
      // - signatureCount = 0
      // - message:
      //   header: [numRequiredSignatures=1, numReadonlySigned=0, numReadonlyUnsigned=0]
      //   accountKeys: 1 key
      //   recentBlockhash: 32 bytes
      //   instructions: 0
      const header = new Uint8Array([1, 0, 0]);
      const numAccountKeys = new Uint8Array([1]); // shortvec
      const pubkey = new Uint8Array(32).fill(1);
      const blockhash = new Uint8Array(32).fill(2);
      const numInstructions = new Uint8Array([0]); // shortvec
      const message = new Uint8Array([
        ...header,
        ...numAccountKeys,
        ...pubkey,
        ...blockhash,
        ...numInstructions,
      ]);

      const signatureCount = new Uint8Array([0]); // shortvec
      const txBytes = new Uint8Array([...signatureCount, ...message]);

      const parsed = await connector.parseTransaction(txBytes);
      const msgBytes = connector.getMessageBytes(txBytes);

      expect(Buffer.from(msgBytes).toString("hex")).toBe(Buffer.from(message).toString("hex"));
      expect(Buffer.from(sha256(msgBytes)).toString("hex")).toBe(
        Buffer.from(parsed.intentHash).toString("hex")
      );
    });
  });

  describe("address derivation", () => {
    // Sample Ed25519 public key (32 bytes)
    const pubkey = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ]);

    test("derives address from Ed25519 public key", () => {
      const connector = createSolanaConnector("mainnet-beta");
      const address = connector.deriveAddress(pubkey);
      // Base58 encoded 32 bytes
      expect(address.length).toBeGreaterThanOrEqual(32);
      expect(address.length).toBeLessThanOrEqual(44);
    });

    test("throws for invalid public key length", () => {
      const connector = createSolanaConnector("mainnet-beta");
      const invalidPubkey = new Uint8Array(31); // 31 bytes instead of 32
      expect(() => connector.deriveAddress(invalidPubkey)).toThrow("Invalid Ed25519 public key length");
    });
  });

  describe("address validation", () => {
    const connector = createSolanaConnector("mainnet-beta");

    test("validates valid Solana address", () => {
      // System program address (known valid)
      expect(connector.validateAddress("11111111111111111111111111111111")).toBe(true);
    });

    test("validates Token program address", () => {
      expect(connector.validateAddress("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")).toBe(true);
    });

    test("rejects invalid address (too short)", () => {
      expect(connector.validateAddress("short")).toBe(false);
    });

    test("rejects invalid address (invalid characters)", () => {
      expect(connector.validateAddress("0OIl111111111111111111111111111")).toBe(false);
    });

    test("rejects invalid address (invalid base58)", () => {
      expect(connector.validateAddress("not-a-valid-base58-address!!")).toBe(false);
    });
  });

  describe("signature formatting", () => {
    const connector = createSolanaConnector("mainnet-beta");

    test("accepts 64-byte signature", () => {
      const sig = new Uint8Array(64);
      const parsed = { intentHash: new Uint8Array(32) } as any;
      const formatted = connector.formatSignature(sig, parsed);
      expect(formatted.length).toBe(64);
    });

    test("throws for invalid signature length", () => {
      const sig = new Uint8Array(63);
      const parsed = { intentHash: new Uint8Array(32) } as any;
      expect(() => connector.formatSignature(sig, parsed)).toThrow("Invalid Ed25519 signature length");
    });
  });
});

describe("Program IDs", () => {
  test("SYSTEM program ID is correct", () => {
    expect(PROGRAM_IDS.SYSTEM).toBe("11111111111111111111111111111111");
  });

  test("TOKEN program ID is correct", () => {
    expect(PROGRAM_IDS.TOKEN).toBe("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
  });

  test("isTokenProgram correctly identifies token programs", () => {
    expect(isTokenProgram(PROGRAM_IDS.TOKEN)).toBe(true);
    expect(isTokenProgram(PROGRAM_IDS.TOKEN_2022)).toBe(true);
    expect(isTokenProgram(PROGRAM_IDS.ASSOCIATED_TOKEN)).toBe(true);
    expect(isTokenProgram(PROGRAM_IDS.SYSTEM)).toBe(false);
  });

  test("isSafeProgram correctly identifies safe programs", () => {
    expect(isSafeProgram(PROGRAM_IDS.SYSTEM)).toBe(true);
    expect(isSafeProgram(PROGRAM_IDS.MEMO)).toBe(true);
    expect(isSafeProgram(PROGRAM_IDS.COMPUTE_BUDGET)).toBe(true);
    expect(isSafeProgram(PROGRAM_IDS.TOKEN)).toBe(false);
  });

  test("getProgramName returns correct names", () => {
    expect(getProgramName(PROGRAM_IDS.SYSTEM)).toBe("System Program");
    expect(getProgramName(PROGRAM_IDS.TOKEN)).toBe("Token Program");
    expect(getProgramName(PROGRAM_IDS.MEMO)).toBe("Memo Program");
    expect(getProgramName("SomeRandomProgramId12345678901234")).toContain("Unknown");
  });
});
