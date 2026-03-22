/**
 * DKG Service - Handles dWallet creation and key management
 *
 * Responsible for:
 * - Creating new dWallets via MPC DKG protocol
 * - Importing existing keys as dWallets
 * - Activating dWallets after key holder signature
 * - Monitoring dWallet state
 */

import { Transaction } from "@mysten/sui/transactions";
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
import {
  coordinatorTransactions,
  SessionsManagerModule,
  CoordinatorInnerModule,
  Curve,
  publicKeyFromCentralizedDKGOutput,
} from "@ika.xyz/sdk";
import { config } from "../config.js";
import { logger } from "../logger.js";
import type { DKGSubmitInput, ImportedKeyVerifySubmitInput } from "../types.js";
import { SuiClientBase } from "./sui-client-base.js";
import {
  withTimeout,
  TIMEOUTS,
  CURVE_SECP256K1,
  CURVE_ED25519,
  deriveEthereumAddress,
  deriveSolanaAddress,
} from "./utils.js";

/**
 * Result from DKG or imported key operations
 */
export interface DKGResult {
  dWalletCapObjectId: string;
  dWalletObjectId: string;
  ethereumAddress?: string;
  solanaAddress?: string;
  bitcoinAddress?: string;
  curve: number;
  digest: string;
  encryptedUserSecretKeyShareId: string | null;
}

/**
 * DKG Service handles dWallet creation and management operations.
 */
export class DKGService {
  constructor(private readonly base: SuiClientBase) {}

  /**
   * Execute DKG transaction to create a new dWallet.
   *
   * @param data - DKG input parameters from client
   * @returns DKG result with dWallet IDs and Ethereum address
   */
  async executeDKGTransaction(data: DKGSubmitInput): Promise<DKGResult> {
    await this.base.initPromise;
    let tx = new Transaction();
    const adminAddress = this.base.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.base.setAdminGas(
      tx,
      adminAddress,
      BigInt(config.sui.gasBudgetsMist.dkg)
    );

    // Use SECP256K1 for Ethereum by default
    const curve = data.curve ?? CURVE_SECP256K1;

    // Basic validation so we fail with a clear error before hitting opaque Move aborts
    if (!data.sessionIdentifier || data.sessionIdentifier.length !== 32) {
      throw new Error(
        `Invalid sessionIdentifier: expected 32 bytes, got ${data.sessionIdentifier?.length ?? 0}`
      );
    }

    // Derive the Sui address that will own the encryption key entry on-chain
    const derivedEncryptionKeyAddress = new Ed25519PublicKey(
      new Uint8Array(data.signerPublicKey)
    ).toSuiAddress();
    if (
      data.encryptionKeyAddress &&
      data.encryptionKeyAddress.toLowerCase() !==
        derivedEncryptionKeyAddress.toLowerCase()
    ) {
      logger.warn(
        {
          provided: data.encryptionKeyAddress,
          derived: derivedEncryptionKeyAddress,
        },
        "encryptionKeyAddress mismatch; using derived address from signerPublicKey"
      );
    }

    // Get the latest network encryption key
    const encryptionKey =
      await this.base.ikaClient.getLatestNetworkEncryptionKey();

    logger.debug(
      { encryptionKeyId: encryptionKey.id, curve },
      "Got network encryption key"
    );

    // Step 1: Ensure the encryption key is registered
    const hasActiveEncryptionKey = await this.checkEncryptionKeyRegistered(
      derivedEncryptionKeyAddress
    );

    if (!hasActiveEncryptionKey) {
      coordinatorTransactions.registerEncryptionKeyTx(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        curve,
        new Uint8Array(data.encryptionKey),
        new Uint8Array(data.encryptionKeySignature),
        new Uint8Array(data.signerPublicKey),
        tx
      );
    }

    const latestNetworkEncryptionKeyId = encryptionKey.id;

    // Step 2: Request DKG - create the dWallet
    const ikaPaymentCoinId = await this.base.selectIkaPaymentCoinOrThrow({
      owner: adminAddress,
      context: "DKG",
    });
    const dkgResult = coordinatorTransactions.requestDWalletDKG(
      this.base.ikaConfig,
      tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      latestNetworkEncryptionKeyId,
      curve,
      new Uint8Array(data.userDkgMessage),
      new Uint8Array(data.encryptedUserShareAndProof),
      data.encryptionKeyAddress,
      new Uint8Array(data.userPublicOutput),
      new Uint8Array(data.signerPublicKey),
      coordinatorTransactions.registerSessionIdentifier(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        new Uint8Array(data.sessionIdentifier),
        tx
      ),
      null,
      tx.object(ikaPaymentCoinId),
      tx.gas,
      tx
    );

    const dWalletCap = (dkgResult as any)[0];

    // Step 3: Transfer the returned dWallet capability to the admin address
    tx.transferObjects([dWalletCap], adminAddress);

    logger.debug("Executing DKG transaction...");

    // Execute transaction
    const result = await this.base.executeSuiTransaction(tx);

    logger.debug({ digest: result.digest }, "Transaction executed");

    // Wait for transaction and parse events (with timeout)
    const txResult = await withTimeout(
      this.base.client.waitForTransaction({
        digest: result.digest,
        options: {
          showEvents: true,
          showObjectChanges: true,
          showEffects: true,
        },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "DKG transaction confirmation"
    );

    // Fail fast with the on-chain error
    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      throw new Error(`DKG transaction failed on-chain: ${err}`);
    }

    // Find the created DWalletCap and dWallet objects from events
    let dWalletCapObjectId: string | null = null;
    let dWalletObjectId: string | null = null;
    let encryptedUserSecretKeyShareId: string | null = null;

    for (const event of txResult.events || []) {
      if (event.type.includes("DWalletSessionEvent")) {
        try {
          const parsedData = SessionsManagerModule.DWalletSessionEvent(
            CoordinatorInnerModule.DWalletDKGRequestEvent
          ).fromBase64(event.bcs);

          dWalletCapObjectId = parsedData.event_data.dwallet_cap_id;
          dWalletObjectId = parsedData.event_data.dwallet_id;
          encryptedUserSecretKeyShareId =
            parsedData.event_data.user_secret_key_share.Encrypted
              ?.encrypted_user_secret_key_share_id || null;
        } catch (parseError) {
          logger.warn(
            { event: event.type, parseError },
            "Failed to parse DWalletSessionEvent"
          );
        }
      }
    }

    // Fallback: extract from object changes (more reliable across SDK/event format changes)
    if (
      (!dWalletCapObjectId || !dWalletObjectId) &&
      (txResult as any)?.objectChanges
    ) {
      const changes = (txResult as any).objectChanges as Array<any>;
      const created = changes.filter((c) => c && c.type === "created");

      const findCreatedBySuffix = (suffix: string): string | null => {
        for (const c of created) {
          const t = String(c.objectType ?? "");
          const id = String(c.objectId ?? "");
          if (id && t.endsWith(suffix)) return id;
        }
        return null;
      };

      dWalletCapObjectId =
        dWalletCapObjectId ??
        findCreatedBySuffix("::coordinator_inner::DWalletCap") ??
        findCreatedBySuffix("::coordinator_inner::ImportedKeyDWalletCap");

      dWalletObjectId =
        dWalletObjectId ?? findCreatedBySuffix("::coordinator_inner::DWallet");

      encryptedUserSecretKeyShareId =
        encryptedUserSecretKeyShareId ??
        findCreatedBySuffix("::coordinator_inner::EncryptedUserSecretKeyShare");
    }

    if (!dWalletCapObjectId || !dWalletObjectId) {
      logger.warn(
        {
          events: txResult.events?.map((e) => e.type),
          objectChanges: (txResult as any)?.objectChanges?.map((c: any) => ({
            type: c?.type,
            objectType: c?.objectType,
          })),
          digest: result.digest,
        },
        "Could not find dWallet objects in transaction result"
      );
      throw new Error("Failed to parse dWallet objects from transaction");
    }

    // Derive chain-specific address from the dWallet's combined public output
    let ethereumAddress: string | undefined;
    let solanaAddress: string | undefined;

    if (curve === CURVE_SECP256K1) {
      // Ethereum (and Bitcoin with ECDSA)
      const publicKey = await publicKeyFromCentralizedDKGOutput(
        Curve.SECP256K1,
        new Uint8Array(data.userPublicOutput)
      );
      ethereumAddress = deriveEthereumAddress(publicKey);
    } else if (curve === CURVE_ED25519) {
      // Solana
      try {
        const publicKey = await publicKeyFromCentralizedDKGOutput(
          Curve.ED25519,
          new Uint8Array(data.userPublicOutput)
        );
        solanaAddress = deriveSolanaAddress(publicKey);
      } catch (err) {
        logger.warn({ err }, "Failed to derive Solana address from Ed25519 public key");
      }
    }

    return {
      dWalletCapObjectId,
      dWalletObjectId,
      ethereumAddress,
      solanaAddress,
      curve,
      digest: result.digest,
      encryptedUserSecretKeyShareId,
    };
  }

  /**
   * Execute imported-key verification transaction on Sui/Ika network.
   * This creates an ImportedKey dWallet without the backend ever seeing the private key.
   *
   * @param data - Import input parameters prepared offline by client
   * @returns DKG result with dWallet IDs and Ethereum address
   */
  async executeImportedKeyVerificationTransaction(
    data: ImportedKeyVerifySubmitInput
  ): Promise<DKGResult> {
    await this.base.initPromise;
    const tx = new Transaction();
    const adminAddress = this.base.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.base.setAdminGas(
      tx,
      adminAddress,
      BigInt(config.sui.gasBudgetsMist.dkg)
    );

    // Basic validation
    if (!data.sessionIdentifier || data.sessionIdentifier.length !== 32) {
      throw new Error(
        `Invalid sessionIdentifier: expected 32 bytes, got ${data.sessionIdentifier?.length ?? 0}`
      );
    }

    // Derive the Sui address that will own the encryption key entry on-chain
    const derivedEncryptionKeyAddress = new Ed25519PublicKey(
      new Uint8Array(data.signerPublicKey)
    ).toSuiAddress();
    if (
      data.encryptionKeyAddress &&
      data.encryptionKeyAddress.toLowerCase() !==
        derivedEncryptionKeyAddress.toLowerCase()
    ) {
      logger.warn(
        {
          provided: data.encryptionKeyAddress,
          derived: derivedEncryptionKeyAddress,
        },
        "encryptionKeyAddress mismatch; using derived address from signerPublicKey"
      );
    }

    // Ensure encryption key is registered
    const encryptionKey =
      await this.base.ikaClient.getLatestNetworkEncryptionKey();
    const hasActiveEncryptionKey = await this.checkEncryptionKeyRegistered(
      derivedEncryptionKeyAddress
    );

    if (!hasActiveEncryptionKey) {
      coordinatorTransactions.registerEncryptionKeyTx(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        CURVE_SECP256K1,
        new Uint8Array(data.encryptionKey),
        new Uint8Array(data.encryptionKeySignature),
        new Uint8Array(data.signerPublicKey),
        tx
      );
    }

    // Payment coin for protocol fees
    const ikaPaymentCoinId = await this.base.selectIkaPaymentCoinOrThrow({
      owner: adminAddress,
      context: "ImportedKey verification",
    });

    const importDWalletVerificationRequestInput = {
      userPublicOutput: new Uint8Array(data.importInput.userPublicOutput),
      userMessage: new Uint8Array(data.importInput.userMessage),
      encryptedUserShareAndProof: new Uint8Array(
        data.importInput.encryptedUserShareAndProof
      ),
    };

    // Call the lower-level tx builder directly
    const coordinatorObjectRef = (tx as any).sharedObjectRef({
      objectId: this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID,
      initialSharedVersion:
        this.base.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
      mutable: true,
    });
    const sessionIdentifierObj = (
      coordinatorTransactions as any
    ).registerSessionIdentifier(
      this.base.ikaConfig as any,
      coordinatorObjectRef,
      new Uint8Array(data.sessionIdentifier),
      tx as any
    );
    const importedCap = (
      coordinatorTransactions as any
    ).requestImportedKeyDwalletVerification(
      this.base.ikaConfig as any,
      coordinatorObjectRef,
      encryptionKey.id,
      CURVE_SECP256K1,
      importDWalletVerificationRequestInput.userMessage,
      importDWalletVerificationRequestInput.encryptedUserShareAndProof,
      derivedEncryptionKeyAddress,
      importDWalletVerificationRequestInput.userPublicOutput,
      new Uint8Array(data.signerPublicKey),
      sessionIdentifierObj,
      (tx as any).object(ikaPaymentCoinId),
      (tx as any).gas,
      tx as any
    );

    // Transfer returned cap to admin
    tx.transferObjects([importedCap], adminAddress);

    const result = await this.base.executeSuiTransaction(tx);
    const txResult = await withTimeout(
      this.base.client.waitForTransaction({
        digest: result.digest,
        options: {
          showEvents: true,
          showObjectChanges: true,
          showEffects: true,
        },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Imported-key verification confirmation"
    );

    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      throw new Error(`Imported-key verification failed on-chain: ${err}`);
    }

    // Extract created objects
    let dWalletCapObjectId: string | null = null;
    let dWalletObjectId: string | null = null;
    let encryptedUserSecretKeyShareId: string | null = null;

    if ((txResult as any)?.objectChanges) {
      const changes = (txResult as any).objectChanges as Array<any>;
      const created = changes.filter((c) => c && c.type === "created");
      const findCreatedBySuffix = (suffix: string): string | null => {
        for (const c of created) {
          const t = String(c.objectType ?? "");
          const id = String(c.objectId ?? "");
          if (id && t.endsWith(suffix)) return id;
        }
        return null;
      };

      dWalletCapObjectId =
        findCreatedBySuffix("::coordinator_inner::ImportedKeyDWalletCap") ??
        findCreatedBySuffix("::coordinator_inner::DWalletCap");
      dWalletObjectId = findCreatedBySuffix("::coordinator_inner::DWallet");
      encryptedUserSecretKeyShareId =
        findCreatedBySuffix(
          "::coordinator_inner::EncryptedUserSecretKeyShare"
        ) ?? null;
    }

    if (!dWalletCapObjectId || !dWalletObjectId) {
      logger.warn(
        {
          objectChanges: (txResult as any)?.objectChanges?.map((c: any) => ({
            type: c?.type,
            objectType: c?.objectType,
          })),
          digest: result.digest,
        },
        "Could not find imported dWallet objects in transaction result"
      );
      throw new Error(
        "Failed to parse imported dWallet objects from transaction"
      );
    }

    // Best-effort derive chain-specific address
    const curve = data.curve ?? CURVE_SECP256K1;
    let ethereumAddress: string | undefined;
    let solanaAddress: string | undefined;

    try {
      if (curve === CURVE_SECP256K1) {
        const publicKey = await publicKeyFromCentralizedDKGOutput(
          Curve.SECP256K1,
          new Uint8Array(data.importInput.userPublicOutput)
        );
        ethereumAddress = deriveEthereumAddress(publicKey);
      } else if (curve === CURVE_ED25519) {
        const publicKey = await publicKeyFromCentralizedDKGOutput(
          Curve.ED25519,
          new Uint8Array(data.importInput.userPublicOutput)
        );
        solanaAddress = deriveSolanaAddress(publicKey);
      }
    } catch {
      // ignore; UI can still proceed with dWallet id
    }

    return {
      dWalletCapObjectId,
      dWalletObjectId,
      ethereumAddress,
      solanaAddress,
      curve,
      digest: result.digest,
      encryptedUserSecretKeyShareId,
    };
  }

  /**
   * Activate a dWallet after key holder provides their signature.
   *
   * @param params.dWalletId - The dWallet object ID
   * @param params.encryptedUserSecretKeyShareId - The encrypted key share ID
   * @param params.userOutputSignature - The user's output signature
   * @returns Transaction digest
   */
  async activateDWallet(params: {
    dWalletId: string;
    encryptedUserSecretKeyShareId: string;
    userOutputSignature: number[];
  }): Promise<{ digest: string }> {
    await this.base.initPromise;

    const tx = new Transaction();
    tx.setSender(this.base.adminKeypair.toSuiAddress());
    await this.base.setAdminGas(
      tx,
      this.base.adminKeypair.toSuiAddress(),
      BigInt(config.sui.gasBudgetsMist.sign)
    );

    coordinatorTransactions.acceptEncryptedUserShare(
      this.base.ikaConfig,
      tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      params.dWalletId,
      params.encryptedUserSecretKeyShareId,
      new Uint8Array(params.userOutputSignature),
      tx
    );

    const result = await this.base.executeSuiTransaction(tx);
    return { digest: result.digest };
  }

  /**
   * Wait for a dWallet to be ready for presign operations.
   *
   * @param dWalletId - The dWallet object ID
   * @returns The dWallet state kind
   */
  async waitForDWalletReadyForPresign(dWalletId: string): Promise<{
    kind: "Active" | "AwaitingKeyHolderSignature" | "Unknown" | string;
  }> {
    const start = Date.now();
    while (Date.now() - start < TIMEOUTS.PRESIGN_WAIT) {
      const dWallet = await this.base.ikaClient.getDWallet(dWalletId);
      const kind = this.getDWalletStateKind(dWallet);
      if (kind === "Active" || kind === "AwaitingKeyHolderSignature")
        return { kind };
      await new Promise((r) => setTimeout(r, 1000));
    }
    return { kind: "Unknown" };
  }

  /**
   * Get the state kind of a dWallet.
   *
   * @param dWallet - The dWallet object from IkaClient
   * @returns The state kind string
   */
  getDWalletStateKind(dWallet: unknown): string {
    const state = (dWallet as any)?.state;
    if (!state) return "Unknown";
    if (state.$kind) return String(state.$kind);
    if (state.Active) return "Active";
    if (state.AwaitingKeyHolderSignature) return "AwaitingKeyHolderSignature";
    // fall back to first key present
    const keys = Object.keys(state);
    return keys.length ? keys[0] : "Unknown";
  }

  /**
   * Check if an encryption key is registered for an address.
   * Uses direct dynamic-field existence check to avoid devInspect issues.
   */
  private async checkEncryptionKeyRegistered(
    derivedEncryptionKeyAddress: string
  ): Promise<boolean> {
    const { coordinatorInner } = (await (
      this.base.ikaClient as any
    ).ensureInitialized()) as {
      coordinatorInner: any;
    };
    const encryptionKeysParentId = String(
      coordinatorInner?.encryption_keys?.id?.id ?? ""
    );
    if (!encryptionKeysParentId) {
      throw new Error(
        "Failed to resolve coordinatorInner.encryption_keys table id"
      );
    }

    const df = await this.base.client.getDynamicFieldObject({
      parentId: encryptionKeysParentId,
      name: { type: "address", value: derivedEncryptionKeyAddress },
    });
    return !!(df as any)?.data;
  }
}
