/**
 * PolicyVault Routes - Hard-gated dWallet registration and management
 * 
 * All Kairo dWallets MUST be registered in the vault. This is mandatory.
 */

import { Elysia, t } from "elysia";
import { Transaction } from "@mysten/sui/transactions";
import { bcs } from "@mysten/sui/bcs";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { DKGExecutorService } from "../dkg-executor.js";
import { bindBinding, bindWallet } from "../key-registry.js";

// Shared executor instance (initialized lazily)
let executorInstance: DKGExecutorService | null = null;

function getExecutor(): DKGExecutorService {
  if (!executorInstance) {
    executorInstance = new DKGExecutorService();
  }
  return executorInstance;
}

function mapProvisionErrorMessage(message: string): string {
  const lower = message.toLowerCase();
  const hasMoveAbort = lower.includes("moveabort") || lower.includes("move abort");
  const hasCode102 =
    /\b102\b/.test(message) || lower.includes("0x66") || lower.includes("e_policy_not_registered");
  if (hasMoveAbort && hasCode102) {
    return "Policy version is not registered. Run `kairo policy-register --policy-id <id>` first.";
  }
  return message;
}

export const vaultRoutes = new Elysia({ prefix: "/api/vault" })

  /**
   * POST /api/wallet/provision
   * 
   * ATOMIC wallet provisioning: Creates PolicyBinding + registers into PolicyVault
   * in a SINGLE transaction. This is the preferred way to secure a wallet.
   * 
   * Guarantees:
   * - Either both binding AND vault registration succeed, or neither does
   * - No partial/intermediate states
   * - Wallet is immediately ready for signing after success
   */
  .post(
    "/provision",
    async ({ body, set, request }) => {
      const { dwalletObjectId, policyObjectId, stableId, isImportedKey } = body;

      // Validate inputs
      if (!dwalletObjectId?.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "dwalletObjectId is required (0x...)" };
      }
      if (!policyObjectId?.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "policyObjectId is required (0x...)" };
      }
      if (!stableId) {
        set.status = 400;
        return { success: false, error: "stableId is required" };
      }

      const vaultObjectId = config.kairo.policyVaultObjectId;
      if (!vaultObjectId?.startsWith("0x")) {
        set.status = 500;
        return { success: false, error: "PolicyVault not configured (KAIRO_POLICY_VAULT_OBJECT_ID)" };
      }

      const packageId = config.kairo.policyMintPackageId;
      if (!packageId?.startsWith("0x")) {
        set.status = 500;
        return { success: false, error: "Policy package not configured (KAIRO_POLICY_MINT_PACKAGE_ID)" };
      }

      const registryId = (config.kairo as any).policyRegistryId;
      if (!registryId?.startsWith("0x")) {
        set.status = 500;
        return { success: false, error: "PolicyRegistry not configured (KAIRO_POLICY_REGISTRY_ID)" };
      }

      try {
        const executor = getExecutor();
        await (executor as any).initPromise;

        const tx = new Transaction();
        const adminAddress = (executor as any).adminKeypair.toSuiAddress();
        tx.setSender(adminAddress);

        // Encode the dWallet object ID string as UTF-8 (matches policy discovery expectations)
        const dwalletIdBytes = new TextEncoder().encode(dwalletObjectId);
        
        // Convert stable ID to bytes
        const stableIdBytes = new TextEncoder().encode(stableId);
        
        const VecU8 = bcs.vector(bcs.u8());

        // ========== STEP 1: Create PolicyBinding ==========
        // Returns the binding ID which we pass to step 2
        const [bindingId] = tx.moveCall({
          target: `${packageId}::policy_registry::create_and_share_policy_binding`,
          arguments: [
            tx.object(registryId), // &PolicyRegistry
            tx.object("0x6"), // Clock
            tx.pure(VecU8.serialize(Array.from(dwalletIdBytes)).toBytes()), // dwallet_id: vector<u8>
            tx.pure(VecU8.serialize(Array.from(stableIdBytes)).toBytes()), // stable_id: vector<u8>
          ],
        });

        // ========== STEP 2: Register dWallet into Vault ==========
        // Uses the binding ID from step 1 (atomic!)
        tx.moveCall({
          target: `${packageId}::dwallet_policy_vault::register_dwallet_into_vault`,
          arguments: [
            tx.object(vaultObjectId), // &mut PolicyVault
            tx.object("0x6"), // Clock
            tx.pure(VecU8.serialize(Array.from(dwalletIdBytes)).toBytes()), // dwallet_id: vector<u8>
            bindingId, // binding_id: ID (from step 1!)
            tx.pure(VecU8.serialize(Array.from(stableIdBytes)).toBytes()), // stable_id: vector<u8>
            tx.pure.bool(Boolean(isImportedKey ?? true)), // is_imported_key: bool
          ],
        });

        // Set gas budget
        await (executor as any).setAdminGas(
          tx,
          adminAddress,
          BigInt(config.sui.gasBudgetsMist.sign)
        );

        // Execute the atomic transaction
        const result = await (executor as any).executeSuiTransaction(tx);
        
        // Wait for confirmation and get created objects
        const client = (executor as any).client;
        await client.waitForTransaction({
          digest: result.digest,
          options: { showEffects: true },
        });
        const txResult = await client.getTransactionBlock({
          digest: result.digest,
          options: { showObjectChanges: true, showEffects: true },
        });

        // Check transaction status
        const status = (txResult as any)?.effects?.status;
        if (status?.status && status.status !== "success") {
          const errMsg = String(status.error ?? "unknown execution error");
          throw new Error(`Atomic provision failed on-chain (digest=${result.digest}): ${errMsg}`);
        }

        // Extract binding object ID from created objects
        let bindingObjectId: string | null = null;
        const changes = (txResult as any)?.objectChanges ?? [];
        for (const change of changes) {
          if (change.type === "created" && String(change.objectType ?? "").includes("PolicyBinding")) {
            bindingObjectId = change.objectId;
            break;
          }
        }
        if (!bindingObjectId) {
          const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
          for (const c of created) {
            const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
            if (!id.startsWith("0x")) continue;
            try {
              const obj = await client.getObject({ id, options: { showType: true } });
              const t = String((obj as any)?.data?.type ?? "");
              if (t.includes("PolicyBinding")) {
                bindingObjectId = id;
                break;
              }
            } catch {
              // ignore
            }
          }
        }

        logger.info(
          {
            dwalletObjectId,
            bindingObjectId,
            vaultObjectId,
            digest: result.digest,
          },
          "Wallet provisioned atomically (binding + vault)"
        );

        // Auto-bind wallet to the calling API key
        const callerKey = request.headers.get("x-kairo-api-key");
        if (callerKey) {
          await bindWallet(callerKey, dwalletObjectId);
          if (bindingObjectId) {
            await bindBinding(callerKey, bindingObjectId);
          }
        }

        return {
          success: true,
          digest: result.digest,
          bindingObjectId,
          vaultObjectId,
          dwalletObjectId,
          walletState: "BOUND_AND_READY",
        };
      } catch (err) {
        const rawMsg = err instanceof Error ? err.message : String(err);
        const msg = mapProvisionErrorMessage(rawMsg);
        logger.error({ err, dwalletObjectId, policyObjectId, stableId }, "Atomic wallet provision failed");
        set.status = msg === rawMsg ? 500 : 400;
        return { success: false, error: msg };
      }
    },
    {
      body: t.Object({
        dwalletObjectId: t.String(),
        policyObjectId: t.String(),
        stableId: t.String(),
        isImportedKey: t.Optional(t.Boolean()),
      }),
    }
  )

  /**
   * POST /api/vault/register
   * 
   * Register a dWallet into the PolicyVault. This is MANDATORY for all Kairo dWallets.
   * Must be called after dWallet creation and PolicyBinding creation.
   * 
   * @deprecated Use POST /api/vault/provision instead for atomic provisioning
   */
  .post(
    "/register",
    async ({ body, set, request }) => {
      const { dwalletObjectId, bindingObjectId, stableId, isImportedKey } = body;

      // Validate inputs
      if (!dwalletObjectId?.startsWith("0x")) {
        set.status = 400;
        return { error: "dwalletObjectId is required (0x...)" };
      }
      if (!bindingObjectId?.startsWith("0x")) {
        set.status = 400;
        return { error: "bindingObjectId is required (0x...)" };
      }
      if (!stableId) {
        set.status = 400;
        return { error: "stableId is required" };
      }

      const vaultObjectId = config.kairo.policyVaultObjectId;
      if (!vaultObjectId?.startsWith("0x")) {
        set.status = 500;
        return { error: "PolicyVault not configured (KAIRO_POLICY_VAULT_OBJECT_ID)" };
      }

      const packageId = config.kairo.policyMintPackageId;
      if (!packageId?.startsWith("0x")) {
        set.status = 500;
        return { error: "Policy package not configured (KAIRO_POLICY_MINT_PACKAGE_ID)" };
      }

      try {
        const executor = getExecutor();
        await (executor as any).initPromise;

        const tx = new Transaction();
        const adminAddress = (executor as any).adminKeypair.toSuiAddress();
        tx.setSender(adminAddress);

        // Encode the dWallet object ID string as UTF-8 (matches policy discovery expectations)
        const dwalletIdBytes = new TextEncoder().encode(dwalletObjectId);
        
        // Convert stable ID to bytes
        const stableIdBytes = new TextEncoder().encode(stableId);

        // Build the register_dwallet_into_vault call
        tx.moveCall({
          target: `${packageId}::dwallet_policy_vault::register_dwallet_into_vault`,
          arguments: [
            tx.object(vaultObjectId), // &mut PolicyVault
            tx.object("0x6"), // Clock
            tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(dwalletIdBytes))), // dwallet_id: vector<u8>
            tx.object(bindingObjectId), // binding_id: ID (passed as object ref, Move converts to ID)
            tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(stableIdBytes))), // stable_id: vector<u8>
            tx.pure.bool(Boolean(isImportedKey)), // is_imported_key: bool
          ],
        });

        // Set gas budget
        await (executor as any).setAdminGas(
          tx,
          adminAddress,
          BigInt(config.sui.gasBudgetsMist.sign) // Reuse sign budget
        );

        // Execute the transaction
        const result = await (executor as any).executeSuiTransaction(tx);

        logger.info(
          {
            dwalletObjectId,
            bindingObjectId,
            vaultObjectId,
            digest: result.digest,
          },
          "dWallet registered into PolicyVault"
        );

        // Auto-bind wallet to the calling API key
        const callerKey = request.headers.get("x-kairo-api-key");
        if (callerKey) {
          await bindWallet(callerKey, dwalletObjectId);
        }

        return {
          success: true,
          digest: result.digest,
          vaultObjectId,
          dwalletObjectId,
          bindingObjectId,
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error({ err, dwalletObjectId, bindingObjectId }, "Vault registration failed");
        set.status = 500;
        return { error: msg };
      }
    },
    {
      body: t.Object({
        dwalletObjectId: t.String(),
        bindingObjectId: t.String(),
        stableId: t.String(),
        isImportedKey: t.Optional(t.Boolean()),
      }),
    }
  )

  /**
   * GET /api/vault/status/:dwalletObjectId
   * 
   * Check if a dWallet is registered in the vault.
   */
  .get(
    "/status/:dwalletObjectId",
    async ({ params, set }) => {
      const { dwalletObjectId } = params;

      if (!dwalletObjectId?.startsWith("0x")) {
        set.status = 400;
        return { error: "Invalid dwalletObjectId" };
      }

      const vaultObjectId = config.kairo.policyVaultObjectId;
      if (!vaultObjectId?.startsWith("0x")) {
        set.status = 500;
        return { error: "PolicyVault not configured (KAIRO_POLICY_VAULT_OBJECT_ID)" };
      }

      const packageId = config.kairo.policyMintPackageId;
      if (!packageId?.startsWith("0x")) {
        set.status = 500;
        return { error: "Policy package not configured (KAIRO_POLICY_MINT_PACKAGE_ID)" };
      }

      try {
        const executor = getExecutor();
        await (executor as any).initPromise;

        const tx = new Transaction();
        const adminAddress = (executor as any).adminKeypair.toSuiAddress();
        
        // Convert dWallet object ID to bytes
        const dwalletIdHex = dwalletObjectId.replace(/^0x/, "");
        const dwalletIdBytes = new Uint8Array(Buffer.from(dwalletIdHex, "hex"));

        // Call has_dwallet to check registration status
        tx.moveCall({
          target: `${packageId}::dwallet_policy_vault::has_dwallet`,
          arguments: [
            tx.object(vaultObjectId),
            tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(dwalletIdBytes))),
          ],
        });

        // Use devInspect to read the result
        const client = (executor as any).client;
        const result = await client.devInspectTransactionBlock({
          transactionBlock: tx,
          sender: adminAddress,
        });

        // Parse the boolean result
        let isRegistered = false;
        if (result.results && result.results[0]?.returnValues) {
          const returnVal = result.results[0].returnValues[0];
          if (returnVal && returnVal[0]) {
            const bytes = new Uint8Array(returnVal[0] as number[]);
            isRegistered = bytes[0] === 1;
          }
        }

        return {
          dwalletObjectId,
          vaultObjectId,
          isRegistered,
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.error({ err, dwalletObjectId }, "Vault status check failed");
        set.status = 500;
        return { error: msg };
      }
    },
    {
      params: t.Object({
        dwalletObjectId: t.String(),
      }),
    }
  )

  /**
   * GET /api/vault/info
   * 
   * Get PolicyVault configuration and stats.
   */
  .get("/info", async () => {
    const vaultObjectId = config.kairo.policyVaultObjectId;
    
    return {
      configured: Boolean(vaultObjectId?.startsWith("0x")),
      vaultObjectId: vaultObjectId || null,
      packageId: config.kairo.policyMintPackageId || null,
    };
  });
