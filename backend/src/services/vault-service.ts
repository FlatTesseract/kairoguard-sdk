/**
 * PolicyVault Service - Hard-gated dWallet signing with on-chain policy enforcement
 *
 * This service implements Option A from the Kairo policy integration plan:
 * - All signing goes through the vault's policy_gated_authorize_sign_v4
 * - Receipts are consumed (one-time authorization)
 * - Idempotency by IntentDigestV1
 * - Single audit event per signing attempt
 */

import { Transaction } from "@mysten/sui/transactions";
import { bcs } from "@mysten/sui/bcs";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { SuiClientBase } from "./sui-client-base.js";

// Chain namespace constants (must match Move module)
export const NAMESPACE_EVM = 1;
export const NAMESPACE_BITCOIN = 2;
export const NAMESPACE_SOLANA = 3;

/**
 * Parameters for vault-gated signing authorization
 */
export interface VaultAuthorizeParams {
  // Vault and dWallet identifiers
  vaultObjectId: string;
  dwalletIdBytes: Uint8Array; // 32 bytes (object ID as bytes)
  
  // Policy objects
  receiptObjectId: string;
  bindingObjectId: string;
  
  // Intent details
  intentDigest: Uint8Array; // 32 bytes (IntentDigestV1)
  namespace: number; // 1=EVM, 2=Bitcoin, 3=Solana
  chainId: Uint8Array; // Chain-specific identifier
  destination: Uint8Array; // Destination address bytes
  
  // Optional receipt TTL (0 = no expiry check)
  receiptTtlMs?: number;
}

/**
 * Result from vault authorization
 */
export interface VaultAuthorizeResult {
  // The ticket output for use with complete_signing
  signingTicket: any; // Transaction result object
  digest: string; // Sui transaction digest
}

/**
 * Parameters for completing vault signing
 */
export interface VaultCompleteParams {
  vaultObjectId: string;
  signingTicket: any; // From authorize step
  signRequestId: string; // From Ika coordinator
}

/**
 * Canonical IntentDigestV1 format
 * 
 * Computes a 32-byte digest over: namespace (1 byte) + chain_id_len (2 bytes) + chain_id + payload
 */
export function computeIntentDigestV1(
  namespace: number,
  chainIdBytes: Uint8Array,
  payloadBytes: Uint8Array
): Uint8Array {
  // Build canonical payload: [namespace(1)] + [chain_id_len(2 BE)] + [chain_id] + [payload]
  const chainIdLen = chainIdBytes.length;
  const totalLen = 1 + 2 + chainIdLen + payloadBytes.length;
  const canonical = new Uint8Array(totalLen);
  
  canonical[0] = namespace;
  canonical[1] = (chainIdLen >> 8) & 0xff;
  canonical[2] = chainIdLen & 0xff;
  canonical.set(chainIdBytes, 3);
  canonical.set(payloadBytes, 3 + chainIdLen);
  
  // Compute keccak256 hash
  // Using SubtleCrypto for SHA-256 as fallback (keccak not available in browser)
  // In production, use the same hash function as the Move module
  return sha256Sync(canonical);
}

/**
 * Simple SHA-256 sync implementation using Node.js crypto
 */
function sha256Sync(data: Uint8Array): Uint8Array {
  const crypto = require("crypto");
  return new Uint8Array(crypto.createHash("sha256").update(data).digest());
}

/**
 * PolicyVault Service for hard-gated signing
 * 
 * This is the mandatory signing gateway - all signing MUST go through the vault.
 * There is no legacy/ungated signing path.
 */
export class VaultService {
  constructor(private readonly base: SuiClientBase) {}

  /**
   * Get the configured vault object ID.
   * Throws if not configured (should fail fast at startup).
   */
  getVaultObjectId(): string {
    const vaultId = config.kairo.policyVaultObjectId;
    if (!vaultId || !vaultId.startsWith("0x")) {
      throw new Error(
        "KAIRO_POLICY_VAULT_OBJECT_ID is required but not configured. " +
        "All signing must go through the PolicyVault."
      );
    }
    return vaultId;
  }

  /**
   * Authorize a signing request through the vault.
   * 
   * This calls the vault's policy_gated_authorize_sign_v4 function which:
   * 1. Verifies the receipt is allowed
   * 2. Checks receipt/binding match
   * 3. Consumes the receipt (one-time authorization)
   * 4. Returns a SigningTicket (hot potato)
   * 
   * The caller must then:
   * 1. Use the dWallet cap with Ika's coordinator
   * 2. Call completeVaultSigning with the ticket and sign request ID
   */
  async authorizeVaultSigning(
    tx: Transaction,
    params: VaultAuthorizeParams
  ): Promise<any> {
    await this.base.initPromise;

    const packageId = config.kairo.policyMintPackageId;
    if (!packageId) {
      throw new Error("Policy package ID not configured for vault operations");
    }

    // Convert dwallet ID bytes to Move vector<u8>
    const dwalletIdArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(params.dwalletIdBytes)));
    const intentDigestArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(params.intentDigest)));
    const chainIdArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(params.chainId)));
    const destinationArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(params.destination)));

    // Call policy_gated_authorize_sign_v4
    const [signingTicket] = tx.moveCall({
      target: `${packageId}::dwallet_policy_vault::policy_gated_authorize_sign_v4`,
      arguments: [
        tx.object(params.vaultObjectId), // &mut PolicyVault
        tx.object(params.receiptObjectId), // PolicyReceiptV4 (consumed)
        tx.object(params.bindingObjectId), // &PolicyBinding
        tx.object("0x6"), // Clock
        dwalletIdArg, // dwallet_id: vector<u8>
        intentDigestArg, // intent_digest: vector<u8>
        tx.pure.u8(params.namespace), // namespace: u8
        chainIdArg, // chain_id: vector<u8>
        destinationArg, // destination: vector<u8>
        tx.pure.u64(params.receiptTtlMs ?? 0), // receipt_ttl_ms: u64
      ],
    });

    logger.info(
      {
        vaultObjectId: params.vaultObjectId,
        receiptObjectId: params.receiptObjectId,
        bindingObjectId: params.bindingObjectId,
        namespace: params.namespace,
        intentDigestHex: Buffer.from(params.intentDigest).toString("hex").slice(0, 16) + "...",
      },
      "Added vault authorization to transaction"
    );

    return signingTicket;
  }

  /**
   * Complete a vault signing request by recording the sign request ID.
   * 
   * This must be called after the Ika coordinator returns a sign request ID.
   * It consumes the SigningTicket (hot potato) and records the intent for idempotency.
   */
  addCompleteVaultSigning(
    tx: Transaction,
    vaultObjectId: string,
    signingTicket: any,
    signRequestIdHex: string
  ): void {
    const packageId = config.kairo.policyMintPackageId;
    if (!packageId) {
      throw new Error("Policy package ID not configured for vault operations");
    }

    // Convert sign request ID to object::ID format (32 bytes from hex)
    const signRequestIdBytes = Buffer.from(signRequestIdHex.replace(/^0x/, ""), "hex");
    const signRequestIdArg = tx.pure(bcs.Address.serialize(signRequestIdHex));

    tx.moveCall({
      target: `${packageId}::dwallet_policy_vault::complete_signing`,
      arguments: [
        tx.object(vaultObjectId), // &mut PolicyVault
        signingTicket, // SigningTicket (hot potato)
        signRequestIdArg, // sign_request_id: ID
        tx.object("0x6"), // Clock
      ],
    });

    logger.info(
      {
        vaultObjectId,
        signRequestIdHex: signRequestIdHex.slice(0, 16) + "...",
      },
      "Added vault signing completion to transaction"
    );
  }

  /**
   * Check if an intent has already been processed (idempotency check).
   * 
   * @returns The existing sign request ID if found, null otherwise
   */
  async getExistingSignRequest(
    vaultObjectId: string,
    intentDigest: Uint8Array
  ): Promise<string | null> {
    await this.base.initPromise;

    const packageId = config.kairo.policyMintPackageId;
    if (!packageId) {
      throw new Error("Policy package ID not configured for vault operations");
    }

    // Build a devInspect transaction to check idempotency
    const tx = new Transaction();
    const intentDigestArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(intentDigest)));

    tx.moveCall({
      target: `${packageId}::dwallet_policy_vault::get_existing_sign_request`,
      arguments: [
        tx.object(vaultObjectId),
        intentDigestArg,
      ],
    });

    try {
      const result = await this.base.client.devInspectTransactionBlock({
        transactionBlock: tx,
        sender: this.base.adminKeypair.toSuiAddress(),
      });

      // Parse the result (bool, ID)
      if (result.results && result.results[0]?.returnValues) {
        const returnValues = result.results[0].returnValues;
        if (returnValues.length >= 2) {
          // First return value is bool (exists)
          const existsBytes = new Uint8Array(returnValues[0][0] as number[]);
          const exists = existsBytes[0] === 1;
          
          if (exists) {
            // Second return value is the sign request ID
            const idBytes = new Uint8Array(returnValues[1][0] as number[]);
            return "0x" + Buffer.from(idBytes).toString("hex");
          }
        }
      }
    } catch (err) {
      logger.warn({ err, vaultObjectId }, "Failed to check vault idempotency");
    }

    return null;
  }

  /**
   * Register a new dWallet into the vault.
   * Called when creating a new dWallet through Kairo.
   */
  addRegisterDWalletIntoVault(
    tx: Transaction,
    params: {
      vaultObjectId: string;
      dwalletIdBytes: Uint8Array;
      bindingObjectId: string;
      stableIdBytes: Uint8Array;
      isImportedKey: boolean;
    }
  ): void {
    const packageId = config.kairo.policyMintPackageId;
    if (!packageId) {
      throw new Error("Policy package ID not configured for vault operations");
    }

    const dwalletIdArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(params.dwalletIdBytes)));
    const stableIdArg = tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(params.stableIdBytes)));

    tx.moveCall({
      target: `${packageId}::dwallet_policy_vault::register_dwallet_into_vault`,
      arguments: [
        tx.object(params.vaultObjectId), // &mut PolicyVault
        tx.object("0x6"), // Clock
        dwalletIdArg, // dwallet_id: vector<u8>
        tx.object(params.bindingObjectId), // binding_id: ID
        stableIdArg, // stable_id: vector<u8>
        tx.pure.bool(params.isImportedKey), // is_imported_key: bool
      ],
    });

    logger.info(
      {
        vaultObjectId: params.vaultObjectId,
        bindingObjectId: params.bindingObjectId,
        isImportedKey: params.isImportedKey,
      },
      "Added dWallet vault registration to transaction"
    );
  }
}

/**
 * Helper to convert an object ID string to bytes
 */
export function objectIdToBytes(objectId: string): Uint8Array {
  const hex = objectId.replace(/^0x/, "");
  if (hex.length !== 64) {
    throw new Error(`Invalid object ID length: ${hex.length} (expected 64 hex chars)`);
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/**
 * Helper to convert a chain ID to canonical bytes for vault authorization.
 * MUST match the encoding used when minting PolicyReceiptV4!
 */
export function chainIdToBytes(namespace: number, chainId: string | number | bigint): Uint8Array {
  switch (namespace) {
    case NAMESPACE_EVM:
      // EVM: BCS u64 serialization (little-endian 8 bytes)
      // This MUST match mintPolicyReceiptV3 which uses bcs.u64().serialize()
      return new Uint8Array(bcs.u64().serialize(BigInt(chainId)).toBytes());
    
    case NAMESPACE_BITCOIN:
      // Bitcoin: network name as UTF-8 bytes ("mainnet", "testnet", "signet")
      return new TextEncoder().encode(String(chainId));
    
    case NAMESPACE_SOLANA:
      // Solana: cluster name as UTF-8 bytes ("mainnet-beta", "devnet", "testnet")
      return new TextEncoder().encode(String(chainId));
    
    default:
      throw new Error(`Unsupported namespace: ${namespace}`);
  }
}
