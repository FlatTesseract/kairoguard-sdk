/**
 * Sign Service - Handles MPC signing operations
 *
 * Responsible for:
 * - Executing MPC sign requests on the Ika network
 * - Managing signature algorithm selection
 * - Returning raw signatures for further processing
 * - (Optional) Vault-gated signing with on-chain policy enforcement
 */

import { Transaction } from "@mysten/sui/transactions";
import {
  coordinatorTransactions,
  SessionsManagerModule,
  CoordinatorInnerModule,
  Curve,
  SignatureAlgorithm,
  IkaTransaction,
  Hash,
} from "@ika.xyz/sdk";
import { keccak256 } from "viem";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { SuiClientBase } from "./sui-client-base.js";
import { withTimeout, TIMEOUTS } from "./utils.js";
import { DKGService } from "./dkg-service.js";
import { VaultService, objectIdToBytes, chainIdToBytes, NAMESPACE_EVM, NAMESPACE_BITCOIN, NAMESPACE_SOLANA } from "./vault-service.js";
import type { ISignService } from "../coordinator/operation-coordinator.js";
import type { SignatureResult } from "../types/operation-lifecycle.js";

/**
 * Vault-gated signing parameters (REQUIRED for all signing)
 */
export interface VaultSigningParams {
  receiptObjectId: string;
  bindingObjectId: string;
  namespace: number; // 1=EVM, 2=Bitcoin, 3=Solana
  chainId: string | number | bigint;
  destination: Uint8Array;
  receiptTtlMs?: number;
}

/**
 * Input parameters for sign operation
 */
export interface SignInput {
  dWalletId: string;
  dWalletCapId: string;
  presignId: string;
  messageHex: string;
  userSignMessage: number[];
  encryptedUserSecretKeyShareId?: string;
  userOutputSignature?: number[];
  // Vault-gated signing parameters (REQUIRED - no legacy path)
  vaultParams: VaultSigningParams;
}

/**
 * Raw sign result from MPC network
 */
export interface SignResult {
  signatureHex: string;
  signatureBytes: Uint8Array;
  signId: string;
  digest: string;
}

/**
 * Sign Service handles MPC signing operations.
 * This is a focused service for signing only - policy, custody, and broadcast
 * are handled by other services/orchestrator.
 * 
 * ALL signing goes through the PolicyVault's policy_gated_authorize_sign_v4.
 * There is no legacy/ungated signing path - the vault is mandatory.
 */
export class SignService implements ISignService {
  private dkgService: DKGService;
  private vaultService: VaultService;

  constructor(private readonly base: SuiClientBase) {
    this.dkgService = new DKGService(base);
    this.vaultService = new VaultService(base);
  }

  /**
   * Execute MPC sign operation.
   * Implements ISignService interface.
   * 
   * ALL signing requires vaultParams - vault-gated signing is mandatory.
   *
   * @param params - Sign parameters (vaultParams is REQUIRED)
   * @returns Signature result
   */
  async sign(params: {
    dWalletId: string;
    dWalletCapId: string;
    presignId: string;
    messageHex: string;
    userSignMessage: number[];
    encryptedUserSecretKeyShareId?: string;
    userOutputSignature?: number[];
    vaultParams: VaultSigningParams; // REQUIRED - no legacy path
  }): Promise<SignatureResult> {
    // Validate vault params are provided (mandatory)
    if (!params.vaultParams) {
      throw new Error(
        "vaultParams is required - all signing must go through the PolicyVault. " +
        "There is no legacy/ungated signing path."
      );
    }

    const result = await this.executeSignTransaction({
      dWalletId: params.dWalletId,
      dWalletCapId: params.dWalletCapId,
      presignId: params.presignId,
      messageHex: params.messageHex,
      userSignMessage: params.userSignMessage,
      encryptedUserSecretKeyShareId: params.encryptedUserSecretKeyShareId,
      userOutputSignature: params.userOutputSignature,
      vaultParams: params.vaultParams,
    });

    return {
      success: true,
      signatureHex: result.signatureHex,
      signatureBytes: result.signatureBytes,
      signId: result.signId,
      digest: result.digest,
    };
  }

  /**
   * Execute sign transaction (core MPC signing).
   * 
   * When vault-gated signing is enabled:
   * 1. Authorize through PolicyVault (consumes receipt)
   * 2. Call Ika coordinator for MPC signing
   * 3. Complete vault signing (record sign request ID)
   * 
   * NOTE: Currently, vault authorization and Ika signing are in SEPARATE transactions
   * because the vault returns a SigningTicket that needs the sign_request_id from Ika,
   * but we don't get that until after execution. A future optimization could use
   * PTB inspection or a callback pattern to do this in a single tx.
   *
   * @param data - Sign input parameters
   * @returns Sign result with signature
   */
  async executeSignTransaction(data: SignInput): Promise<SignResult> {
    await this.base.initPromise;

    // ====== VAULT PARAMS VALIDATION ======
    // Vault-gated signing is MANDATORY - validate params
    if (!data.vaultParams) {
      throw new Error(
        "vaultParams is required - all signing must go through the PolicyVault."
      );
    }
    
    const { namespace, chainId, destination } = data.vaultParams;
    const chainIdBytes = chainIdToBytes(namespace, chainId);
    const messageBytes = new Uint8Array(
      Buffer.from(data.messageHex.replace(/^0x/, ""), "hex")
    );
    // CRITICAL: Intent digest must be keccak256(messageBytes) to match what's stored in PolicyReceiptV4
    // DO NOT use computeIntentDigestV1 here - that wraps with namespace/chainId which doesn't match the receipt
    const intentHashHex = keccak256(messageBytes);
    const intentDigest = new Uint8Array(Buffer.from(intentHashHex.replace(/^0x/, ""), "hex"));
    
    // ====== VAULT IDEMPOTENCY CHECK ======
    const existingSignId = await this.vaultService.getExistingSignRequest(
      this.vaultService.getVaultObjectId(),
      intentDigest
    );
    
    if (existingSignId) {
      logger.info(
        { existingSignId, intentDigestHex: Buffer.from(intentDigest).toString("hex").slice(0, 16) + "..." },
        "Idempotent hit: returning existing sign request"
      );
      
      // Wait for the existing signature
      const signResult = await withTimeout(
        this.base.ikaClient.getSignInParticularState(
          existingSignId,
          Curve.SECP256K1,
          SignatureAlgorithm.ECDSASecp256k1,
          "Completed"
        ),
        TIMEOUTS.SIGN_WAIT,
        "Signature from Ika network (idempotent)"
      );
      
      const signatureBytes = new Uint8Array(signResult.state.Completed.signature);
      const signatureHex = Buffer.from(signatureBytes).toString("hex");
      
      return {
        signatureHex,
        signatureBytes,
        signId: existingSignId,
        digest: "", // No new transaction
      };
    }

    // Verify presign exists
    const presign = await withTimeout(
      this.base.ikaClient.getPresignInParticularState(data.presignId, "Completed"),
      TIMEOUTS.PRESIGN_WAIT,
      "Presign state check"
    );

    if (!presign) {
      throw new Error(`Presign ${data.presignId} not found or not completed`);
    }

    logger.info(
      {
        messageHex: data.messageHex.slice(0, 20) + "...",
        userSignMessageLength: data.userSignMessage.length,
        userOutputSignatureLength: data.userOutputSignature?.length ?? 0,
        encryptedUserSecretKeyShareId: data.encryptedUserSecretKeyShareId,
        presignId: data.presignId,
        dWalletId: data.dWalletId,
        dWalletCapId: data.dWalletCapId,
        vaultObjectId: this.vaultService.getVaultObjectId(),
      },
      "Processing vault-gated sign request"
    );

    const tx = new Transaction();
    const ikaTx = new IkaTransaction({
      ikaClient: this.base.ikaClient,
      transaction: tx,
    });
    tx.setSender(this.base.adminKeypair.toSuiAddress());
    await this.base.setAdminGas(
      tx,
      this.base.adminKeypair.toSuiAddress(),
      BigInt(config.sui.gasBudgetsMist.sign)
    );

    // ====== VAULT AUTHORIZATION (MANDATORY) ======
    const { receiptObjectId, bindingObjectId, receiptTtlMs } = data.vaultParams;
    
    // Add vault authorization to the transaction
    const _signingAuth = await this.vaultService.authorizeVaultSigning(tx, {
      vaultObjectId: this.vaultService.getVaultObjectId(),
      dwalletIdBytes: objectIdToBytes(data.dWalletId),
      receiptObjectId,
      bindingObjectId,
      intentDigest,
      namespace,
      chainId: chainIdBytes,
      destination,
      receiptTtlMs,
    });
    
    logger.info(
      {
        vaultObjectId: this.vaultService.getVaultObjectId(),
        receiptObjectId,
        intentDigestHex: Buffer.from(intentDigest).toString("hex").slice(0, 16) + "...",
      },
      "Added vault authorization to sign transaction"
    );

    // Check if dWallet needs activation
    const dWallet = await this.base.ikaClient.getDWallet(data.dWalletId);
    const stateKind = this.dkgService.getDWalletStateKind(dWallet);
    if (stateKind === "AwaitingKeyHolderSignature") {
      if (
        !data.encryptedUserSecretKeyShareId ||
        !data.userOutputSignature?.length
      ) {
        throw new Error(
          "dWallet requires activation (AwaitingKeyHolderSignature) but activation inputs are missing (encryptedUserSecretKeyShareId/userOutputSignature)."
        );
      }
      coordinatorTransactions.acceptEncryptedUserShare(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        data.dWalletId,
        data.encryptedUserSecretKeyShareId,
        new Uint8Array(data.userOutputSignature),
        tx
      );
    }

    const verifiedPresignCap = ikaTx.verifyPresignCap({
      presign,
    });

    const isImported = Boolean((dWallet as any)?.is_imported_key_dwallet);
    const messageBytes = new Uint8Array(
      Buffer.from(data.messageHex.replace(/^0x/, ""), "hex")
    );

    // Create message approval based on dWallet type
    const verifiedMessageApproval = isImported
      ? ikaTx.approveImportedKeyMessage({
          curve: Curve.SECP256K1,
          hashScheme: Hash.KECCAK256,
          signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
          dWalletCap: data.dWalletCapId,
          message: messageBytes,
        })
      : ikaTx.approveMessage({
          curve: Curve.SECP256K1,
          hashScheme: Hash.KECCAK256,
          signatureAlgorithm: SignatureAlgorithm.ECDSASecp256k1,
          dWalletCap: data.dWalletCapId,
          message: messageBytes,
        });

    const ikaPaymentCoinId = await this.base.selectIkaPaymentCoinOrThrow({
      owner: this.base.adminKeypair.toSuiAddress(),
      context: "sign request",
    });

    // Build sign transaction
    if (isImported) {
      coordinatorTransactions.requestImportedKeySign(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        verifiedPresignCap,
        verifiedMessageApproval,
        new Uint8Array(data.userSignMessage),
        ikaTx.createSessionIdentifier(),
        tx.object(ikaPaymentCoinId),
        tx.gas,
        tx
      );
    } else {
      coordinatorTransactions.requestSign(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        verifiedPresignCap,
        verifiedMessageApproval,
        new Uint8Array(data.userSignMessage),
        ikaTx.createSessionIdentifier(),
        tx.object(ikaPaymentCoinId),
        tx.gas,
        tx
      );
    }

    const result = await this.base.executeSuiTransaction(tx);

    // Wait for sign transaction confirmation
    const txResult = await withTimeout(
      this.base.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Sign transaction confirmation"
    );

    let signId: string | null = null;
    for (const event of txResult.events || []) {
      if (event.type.includes("SignRequestEvent")) {
        try {
          const parsedData = SessionsManagerModule.DWalletSessionEvent(
            CoordinatorInnerModule.SignRequestEvent
          ).fromBase64(event.bcs);
          signId = parsedData.event_data.sign_id;
        } catch (err) {
          logger.warn({ event: event.type, err }, "Failed to parse sign event");
        }
      }
    }

    if (!signId) {
      throw new Error("Failed to get sign ID from transaction");
    }

    // Wait for network to complete the signature
    const signResult = await withTimeout(
      this.base.ikaClient.getSignInParticularState(
        signId,
        Curve.SECP256K1,
        SignatureAlgorithm.ECDSASecp256k1,
        "Completed"
      ),
      TIMEOUTS.SIGN_WAIT,
      "Signature from Ika network"
    );

    const signatureBytes = new Uint8Array(signResult.state.Completed.signature);
    const signatureHex = Buffer.from(signatureBytes).toString("hex");

    logger.info(
      { signId, signatureLength: signatureBytes.length },
      "Got signature from Ika network"
    );

    return {
      signatureHex,
      signatureBytes,
      signId,
      digest: result.digest,
    };
  }
}
