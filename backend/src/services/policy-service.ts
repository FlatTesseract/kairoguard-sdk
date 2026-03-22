/**
 * Policy Service - Handles policy management and receipt operations
 *
 * Responsible for:
 * - Verifying PolicyReceipts against expected parameters
 * - Minting new PolicyReceipts
 * - Creating and managing policies, versions, and bindings
 * - Enforcing continuous compliance through registry/binding checks
 */

import { Transaction } from "@mysten/sui/transactions";
import { bcs } from "@mysten/sui/bcs";
import type { Hex } from "viem";
import { toBytes as viemToBytes } from "viem";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { CustodyMode, type CustodyStatus, resolveEffectiveCustodyMode } from "../custody-mode.js";
import { SuiClientBase } from "./sui-client-base.js";
import { withTimeout, TIMEOUTS, bytesFieldToHex, bytesFieldToUtf8, bytesFieldToU8 } from "./utils.js";
import { PolicyDeniedError } from "../types/errors.js";
import type { IPolicyService } from "../coordinator/operation-coordinator.js";
import type { PolicyResult } from "../types/operation-lifecycle.js";

/**
 * Parameters for minting a PolicyReceipt
 */
export interface MintReceiptParams {
  policyId: string;
  policyVersion: string;
  evmChainId: number;
  toEvm: string;
  intentHashHex: Hex;
  evmSelectorHex?: Hex | null;
  erc20AmountHex?: Hex | null;
  policyBindingObjectId?: string;
  custodyChainObjectId?: string;
  custodyPackageId?: string;
  custodyMode?: CustodyMode;
}

/**
 * Result from minting a PolicyReceipt
 */
export interface MintReceiptResult {
  receiptObjectId: string;
  digest: string;
  receiptType?: string;
  custodyChainObjectId?: string;
  custodyAppendDigest?: string;
  custodyEventObjectId?: string;
  custodyAppendError?: string;
  custodyStatus: CustodyStatus;
  custodyCompliant: boolean;
}

/**
 * Parameters for verifying a PolicyReceipt
 */
export interface VerifyReceiptParams {
  receiptId: string;
  expectedPolicyId: string;
  expectedPolicyVersion: string;
  policyBindingObjectId?: string;
  evmChainId: number;
  toEvm: string;
  intentHashHex: Hex;
}

/**
 * Policy Service handles all policy-related operations.
 */
export class PolicyService implements IPolicyService {
  constructor(
    private readonly base: SuiClientBase,
    private readonly custodyAppendFn?: (params: {
      custodyPackageId: string;
      custodyChainObjectId: string;
      receiptObjectId: string;
      policyObjectId: string;
      intentHashHex: string;
      toEvm: string;
      mintDigest: string;
    }) => Promise<{ digest: string; custodyEventObjectId?: string }>,
    private readonly createCustodyChainFn?: (params: {
      custodyPackageId: string;
      policyObjectId: string;
    }) => Promise<{ custodyChainObjectId: string; digest: string }>
  ) {}

  /**
   * Verify a PolicyReceipt matches expected parameters.
   * Implements IPolicyService interface.
   */
  async verifyReceipt(params: {
    receiptId: string;
    expectedPolicyId: string;
    expectedPolicyVersion: string;
    policyBindingObjectId?: string;
    evmChainId: number;
    toEvm: string;
    intentHashHex: Hex;
  }): Promise<PolicyResult> {
    try {
      await this.verifyPolicyReceiptOrThrow(params);
      return {
        success: true,
        allowed: true,
        receiptId: params.receiptId,
        policyId: params.expectedPolicyId,
        policyVersion: params.expectedPolicyVersion,
      };
    } catch (err) {
      return {
        success: false,
        allowed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Mint a new PolicyReceipt.
   * Implements IPolicyService interface.
   */
  async mintReceipt(params: MintReceiptParams): Promise<PolicyResult> {
    try {
      const result = await this.mintPolicyReceipt(params);
      return {
        success: true,
        allowed: true,
        receiptId: result.receiptObjectId,
        policyId: params.policyId,
        policyVersion: params.policyVersion,
        digest: result.digest,
      };
    } catch (err) {
      return {
        success: false,
        allowed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Verify a PolicyReceipt matches expected parameters.
   * Throws an error if verification fails.
   * 
   * Supports PolicyReceiptV4, PolicyReceiptV3, PolicyReceiptV2, and legacy receipts.
   */
  async verifyPolicyReceiptOrThrow(params: VerifyReceiptParams): Promise<void> {
    const obj = await this.base.client.getObject({
      id: params.receiptId,
      options: { showContent: true, showType: true },
    });

    if (!obj.data?.content || obj.data.content.dataType !== "moveObject") {
      throw new Error("Invalid policyReceiptId: receipt not found or not a Move object");
    }

    const receiptType = String((obj as any)?.data?.type ?? "");
    const fields = (obj.data.content.fields ?? {}) as Record<string, unknown>;

    // PolicyReceiptV4 or PolicyReceiptV3 — both use multi-chain verification
    if (
      receiptType.endsWith("::policy_registry::PolicyReceiptV4") ||
      receiptType.endsWith("::policy_registry::PolicyReceiptV3")
    ) {
      const NAMESPACE_EVM = 1;
      await this.verifyPolicyReceiptV3(params, fields, NAMESPACE_EVM);
      return;
    }

    if (receiptType.endsWith("::policy_registry::PolicyReceiptV2")) {
      await this.verifyPolicyReceiptV2(params, fields);
      return;
    }

    // Legacy PolicyReceipt (MVP)
    await this.verifyLegacyPolicyReceipt(params, fields);
  }

  /**
   * Verify a PolicyReceiptV2
   */
  private async verifyPolicyReceiptV2(
    params: VerifyReceiptParams,
    fields: Record<string, unknown>
  ): Promise<void> {
    const allowed = Boolean(fields["allowed"]);
    if (!allowed) {
      const denialReason = Number(fields["denial_reason"] ?? 0);
      throw new PolicyDeniedError(denialReason);
    }

    const policyObjectId = String(fields["policy_object_id"] ?? "");
    if (policyObjectId.toLowerCase() !== params.expectedPolicyId.toLowerCase()) {
      throw new Error("PolicyReceipt policy_object_id mismatch");
    }

    const policyVersionBytes = fields["policy_version"];
    const policyVersion = bytesFieldToUtf8(policyVersionBytes);
    if (policyVersion !== params.expectedPolicyVersion) {
      throw new Error("PolicyReceipt policy_version mismatch");
    }

    const policyRootHex = bytesFieldToHex(fields["policy_root"]);
    if (!policyRootHex || viemToBytes(policyRootHex as `0x${string}`).length !== 32) {
      throw new Error("PolicyReceipt policy_root missing/invalid (expected 32 bytes)");
    }
    const versionId = String(fields["policy_version_id"] ?? "").trim();
    if (!versionId.startsWith("0x")) {
      throw new Error("PolicyReceipt policy_version_id missing/invalid");
    }

    // Continuous compliance checks
    const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();
    const stableId = bytesFieldToUtf8(fields["policy_stable_id"]);
    if (params.policyBindingObjectId && params.policyBindingObjectId.startsWith("0x")) {
      const b = await this.getPolicyBindingInfo(params.policyBindingObjectId);
      if (!b.activeVersionId) throw new Error("PolicyBinding missing active_version_id");
      if (stableId && b.stableId && stableId !== b.stableId) {
        throw new Error("PolicyBinding stable_id mismatch (wrong binding for this policy)");
      }
      if (b.activeVersionId.toLowerCase() !== versionId.toLowerCase()) {
        throw new Error(
          "Policy updated and requires confirmation (reaffirm PolicyBinding to continue)."
        );
      }
    } else if (registryId.startsWith("0x") && stableId) {
      const latest = await this.getLatestPolicyVersionIdFromRegistry({
        registryObjectId: registryId,
        stableId,
      });
      if (latest && latest.toLowerCase() !== versionId.toLowerCase()) {
        throw new Error(
          "PolicyReceipt does not reference latest policy version (policy update pending)."
        );
      }
    }

    // Additional field validations
    const selectorHex = bytesFieldToHex(fields["evm_selector"]);
    if (selectorHex) {
      const n = bytesFieldToU8(fields["evm_selector"])?.length ?? 0;
      if (n !== 4) {
        throw new Error(
          `PolicyReceipt evm_selector invalid (expected 4 bytes or empty, got ${n})`
        );
      }
    }
    const amtHex = bytesFieldToHex(fields["erc20_amount"]);
    if (amtHex) {
      const n = bytesFieldToU8(fields["erc20_amount"])?.length ?? 0;
      if (n !== 32) {
        throw new Error(
          `PolicyReceipt erc20_amount invalid (expected 32 bytes or empty, got ${n})`
        );
      }
    }

    const evmChainId = Number(String(fields["evm_chain_id"] ?? ""));
    if (!Number.isFinite(evmChainId) || evmChainId !== params.evmChainId) {
      throw new Error("PolicyReceipt evm_chain_id mismatch");
    }

    const receiptTo = bytesFieldToHex(fields["to_evm"]);
    if (receiptTo && receiptTo.toLowerCase() !== params.toEvm.toLowerCase()) {
      throw new Error("PolicyReceipt to_evm mismatch");
    }

    const receiptIntentHash = bytesFieldToHex(fields["intent_hash"]);
    if (
      !receiptIntentHash ||
      receiptIntentHash.toLowerCase() !== params.intentHashHex.toLowerCase()
    ) {
      throw new Error(
        `PolicyReceipt intent_hash mismatch (expected=${params.intentHashHex}, receipt=${receiptIntentHash ?? "(unreadable)"})`
      );
    }
  }

  /**
   * Verify a PolicyReceiptV3 (multi-chain receipt)
   */
  private async verifyPolicyReceiptV3(
    params: VerifyReceiptParams,
    fields: Record<string, unknown>,
    namespace: number
  ): Promise<void> {
    const allowed = Boolean(fields["allowed"]);
    if (!allowed) {
      const denialReason = Number(fields["denial_reason"] ?? 0);
      throw new PolicyDeniedError(denialReason);
    }

    const policyObjectId = String(fields["policy_object_id"] ?? "");
    if (policyObjectId.toLowerCase() !== params.expectedPolicyId.toLowerCase()) {
      throw new Error("PolicyReceipt policy_object_id mismatch");
    }

    const policyVersionBytes = fields["policy_version"];
    const policyVersion = bytesFieldToUtf8(policyVersionBytes);
    if (policyVersion !== params.expectedPolicyVersion) {
      throw new Error("PolicyReceipt policy_version mismatch");
    }

    const policyRootHex = bytesFieldToHex(fields["policy_root"]);
    if (!policyRootHex || viemToBytes(policyRootHex as `0x${string}`).length !== 32) {
      throw new Error("PolicyReceipt policy_root missing/invalid (expected 32 bytes)");
    }

    const versionId = String(fields["policy_version_id"] ?? "").trim();
    if (!versionId.startsWith("0x")) {
      throw new Error("PolicyReceipt policy_version_id missing/invalid");
    }

    // Continuous compliance: enforce PolicyBinding (if provided) or latest registry version.
    const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();
    const stableId = bytesFieldToUtf8(fields["policy_stable_id"]);
    if (params.policyBindingObjectId && params.policyBindingObjectId.startsWith("0x")) {
      const b = await this.getPolicyBindingInfo(params.policyBindingObjectId);
      if (!b.activeVersionId) throw new Error("PolicyBinding missing active_version_id");
      if (stableId && b.stableId && stableId !== b.stableId) {
        throw new Error("PolicyBinding stable_id mismatch (wrong binding for this policy)");
      }
      if (b.activeVersionId.toLowerCase() !== versionId.toLowerCase()) {
        throw new Error(
          "Policy updated and requires confirmation (reaffirm PolicyBinding to continue)."
        );
      }
    } else if (registryId.startsWith("0x") && stableId) {
      const latest = await this.getLatestPolicyVersionIdFromRegistry({
        registryObjectId: registryId,
        stableId,
      });
      if (latest && latest.toLowerCase() !== versionId.toLowerCase()) {
        throw new Error(
          "PolicyReceipt does not reference latest policy version (policy update pending)."
        );
      }
    }

    // Namespace check
    const receiptNamespace = Number(String(fields["namespace"] ?? ""));
    if (!Number.isFinite(receiptNamespace) || receiptNamespace !== namespace) {
      throw new Error("PolicyReceipt namespace mismatch");
    }

    // Chain ID check (for EVM, chain_id is stored as u64 in BCS)
    const chainBytes = bytesFieldToU8(fields["chain_id"]) ?? [];
    if (receiptNamespace === 1) {
      // EVM: chain_id is BCS u64 (little-endian 8 bytes)
      const evmChainIdFromReceipt = chainBytes.length === 8
        ? Number(
            chainBytes[0] |
            (chainBytes[1] << 8) |
            (chainBytes[2] << 16) |
            (chainBytes[3] << 24)
          ) // Simple u32 portion for small chain IDs
        : 0;
      if (evmChainIdFromReceipt !== params.evmChainId) {
        throw new Error("PolicyReceipt chain_id mismatch");
      }
    }

    // Destination check (for EVM, destination is 20 bytes address)
    const destBytes = bytesFieldToU8(fields["destination"]) ?? [];
    if (receiptNamespace === 1 && destBytes.length === 20) {
      const receiptDest = bytesFieldToHex(fields["destination"]);
      if (receiptDest && receiptDest.toLowerCase() !== params.toEvm.toLowerCase()) {
        throw new Error("PolicyReceipt destination mismatch");
      }
    }

    // Intent hash check
    const receiptIntentHash = bytesFieldToHex(fields["intent_hash"]);
    if (
      !receiptIntentHash ||
      receiptIntentHash.toLowerCase() !== params.intentHashHex.toLowerCase()
    ) {
      throw new Error(
        `PolicyReceipt intent_hash mismatch (expected=${params.intentHashHex}, receipt=${receiptIntentHash ?? "(unreadable)"})`
      );
    }
  }

  /**
   * Verify a legacy PolicyReceipt
   */
  private async verifyLegacyPolicyReceipt(
    params: VerifyReceiptParams,
    fields: Record<string, unknown>
  ): Promise<void> {
    const allowed = Boolean(fields["allowed"]);
    if (!allowed) {
      const denialReason = Number(fields["denial_reason"] ?? 0);
      throw new PolicyDeniedError(denialReason);
    }

    const policyId = String(fields["policy_id"] ?? "");
    if (policyId.toLowerCase() !== params.expectedPolicyId.toLowerCase()) {
      throw new Error("PolicyReceipt policy_id mismatch");
    }

    const policyVersionBytes = fields["policy_version"];
    const policyVersion = bytesFieldToUtf8(policyVersionBytes);
    if (policyVersion !== params.expectedPolicyVersion) {
      throw new Error("PolicyReceipt policy_version mismatch");
    }

    const evmChainId = Number(String(fields["evm_chain_id"] ?? ""));
    if (!Number.isFinite(evmChainId) || evmChainId !== params.evmChainId) {
      throw new Error("PolicyReceipt evm_chain_id mismatch");
    }

    const receiptTo = bytesFieldToHex(fields["to_evm"]);
    if (receiptTo && receiptTo.toLowerCase() !== params.toEvm.toLowerCase()) {
      throw new Error("PolicyReceipt to_evm mismatch");
    }

    const receiptIntentHash = bytesFieldToHex(fields["intent_hash"]);
    if (
      !receiptIntentHash ||
      receiptIntentHash.toLowerCase() !== params.intentHashHex.toLowerCase()
    ) {
      throw new Error(
        `PolicyReceipt intent_hash mismatch (expected=${params.intentHashHex}, receipt=${receiptIntentHash ?? "(unreadable)"})`
      );
    }
  }

  /**
   * Mint a PolicyReceipt.
   * This is a complex operation that handles multiple mint function signatures.
   */
  async mintPolicyReceipt(params: MintReceiptParams): Promise<MintReceiptResult> {
    await this.base.initPromise;

    logger.info(
      {
        policyId: params.policyId,
        policyVersion: params.policyVersion,
        evmChainId: params.evmChainId,
        toEvm: params.toEvm,
        intentHashHex: String(params.intentHashHex).slice(0, 18) + "...",
      },
      "Minting PolicyReceipt"
    );

    const toBytes = (hex: string, expectedLen: number): Uint8Array => {
      const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
      if (!/^[0-9a-fA-F]+$/.test(raw) || raw.length !== expectedLen * 2) {
        throw new Error(`Invalid hex length (expected ${expectedLen} bytes)`);
      }
      const out = new Uint8Array(expectedLen);
      for (let i = 0; i < expectedLen; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
      return out;
    };

    const tx = new Transaction();
    const adminAddress = this.base.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.base.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    // Resolve policy package id from policy object type
    const policyObj = await this.base.client.getObject({
      id: params.policyId,
      options: { showType: true, showOwner: true, showContent: true },
    });
    const policyType = String((policyObj as any)?.data?.type ?? "");
    const policyPkgFromType = policyType.split("::")[0];
    if (!policyPkgFromType || !policyPkgFromType.startsWith("0x")) {
      throw new Error("Failed to resolve policy package id from policy object type");
    }
    const policyPkg =
      config.kairo.policyMintPackageId &&
      String(config.kairo.policyMintPackageId).startsWith("0x")
        ? String(config.kairo.policyMintPackageId)
        : policyPkgFromType;
    const sharedVersionRaw = (policyObj as any)?.data?.owner?.Shared?.initial_shared_version;
    const initialSharedVersion = Number(sharedVersionRaw ?? 0);
    if (!Number.isFinite(initialSharedVersion) || initialSharedVersion <= 0) {
      throw new Error("Failed to resolve policy shared initial version");
    }

    logger.info(
      {
        policyId: params.policyId,
        policyType,
        policyPkgFromType,
        policyMintPkg: policyPkg,
        initialSharedVersion,
      },
      "Resolved policy package for receipt mint"
    );

    const isPolicyV3 = policyType.endsWith("::policy_registry::PolicyV3");
    const isPolicyV2 = policyType.endsWith("::policy_registry::PolicyV2");
    const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();

    // PolicyV3/V4 requires the V4 mint flow
    if (isPolicyV3) {
      throw new Error(
        "PolicyV3/V4 detected - use the /api/policy/receipt/mint endpoint for multi-chain receipts. " +
        "The V4 mint flow supports EVM, Bitcoin, and Solana namespaces with vault-gated signing."
      );
    }

    // For V2 policies with registry, use the v2 mint function
    if (isPolicyV2 && registryId.startsWith("0x")) {
      return await this.mintPolicyReceiptV2(
        tx,
        params,
        policyPkg,
        registryId,
        initialSharedVersion,
        policyPkgFromType
      );
    }

    // Fallback to legacy mint
    return await this.mintPolicyReceiptLegacy(
      tx,
      params,
      policyPkg,
      policyPkgFromType,
      initialSharedVersion,
      policyObj
    );
  }

  /**
   * Mint a PolicyReceiptV2 using the registry
   */
  private async mintPolicyReceiptV2(
    tx: Transaction,
    params: MintReceiptParams,
    policyPkg: string,
    registryId: string,
    initialSharedVersion: number,
    policyPkgFromType: string
  ): Promise<MintReceiptResult> {
    const toBytes = (hex: string, expectedLen: number): Uint8Array => {
      const raw = hex.startsWith("0x") ? hex.slice(2) : hex;
      const out = new Uint8Array(expectedLen);
      for (let i = 0; i < expectedLen; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
      return out;
    };

    // Check if module exposes v2 mint function
    const exposed = await this.getModuleExposedFunctions(policyPkg, "policy_registry");
    if (!exposed.includes("mint_receipt_evm_v2_to_sender")) {
      throw new Error("Policy package does not expose mint_receipt_evm_v2_to_sender");
    }

    const policyRefImm = tx.sharedObjectRef({
      objectId: params.policyId,
      initialSharedVersion,
      mutable: false,
    });

    const toEvmBytes = toBytes(params.toEvm, 20);
    const intentBytes = toBytes(params.intentHashHex, 32);
    const selectorBytes = (() => {
      const h = String(params.evmSelectorHex ?? "").trim();
      if (!h) return new Uint8Array();
      return toBytes(h, 4);
    })();
    const erc20AmountBytes = (() => {
      const h = String(params.erc20AmountHex ?? "").trim();
      if (!h) return new Uint8Array();
      return toBytes(h, 32);
    })();

    tx.moveCall({
      target: `${policyPkg}::policy_registry::mint_receipt_evm_v2_to_sender`,
      arguments: [
        tx.object(registryId),
        policyRefImm,
        tx.object("0x6"), // Clock
        tx.pure.u64(BigInt(params.evmChainId)),
        tx.pure.vector("u8", [...intentBytes]),
        tx.pure.vector("u8", [...toEvmBytes]),
        tx.pure.vector("u8", [...selectorBytes]),
        tx.pure.vector("u8", [...erc20AmountBytes]),
      ],
    });

    const result = await this.base.executeSuiTransaction(tx);
    const txResult = await withTimeout(
      this.base.client.waitForTransaction({
        digest: result.digest,
        options: { showObjectChanges: true, showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "PolicyReceipt mint confirmation"
    );

    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      throw new Error(`PolicyReceipt mint failed on-chain: ${err}`);
    }

    let receiptObjectId: string | null = null;
    let receiptType: string | undefined;
    const changes = ((txResult as any)?.objectChanges ?? []) as Array<any>;
    for (const c of changes) {
      if (c?.type !== "created") continue;
      const t = String(c.objectType ?? "");
      const id = String(c.objectId ?? "");
      if (id && t.endsWith("::policy_registry::PolicyReceiptV2")) {
        receiptObjectId = id;
        receiptType = t;
        break;
      }
    }
    if (!receiptObjectId) {
      throw new Error("Failed to find created PolicyReceiptV2 object in transaction result");
    }

    // Handle custody append
    const custodyResult = await this.handleCustodyAppend(
      params,
      receiptObjectId,
      result.digest,
      policyPkgFromType
    );

    logger.info(
      {
        receiptObjectId,
        digest: result.digest,
        policyPkg,
        module: "policy_registry",
        mintFn: "mint_receipt_evm_v2_to_sender",
        ...custodyResult,
      },
      "Minted PolicyReceiptV2"
    );

    return {
      receiptObjectId,
      digest: result.digest,
      receiptType,
      ...custodyResult,
    };
  }

  /**
   * Mint a legacy PolicyReceipt
   */
  private async mintPolicyReceiptLegacy(
    tx: Transaction,
    params: MintReceiptParams,
    policyPkg: string,
    policyPkgFromType: string,
    initialSharedVersion: number,
    policyObj: any
  ): Promise<MintReceiptResult> {
    // This is a simplified version - the full implementation handles
    // multiple function signatures. For brevity, we throw if v2 isn't available.
    throw new Error(
      "Legacy policy receipt minting not implemented in extracted service. " +
        "Please use PolicyV2 with a registry."
    );
  }

  /**
   * Handle custody append after minting a receipt
   */
  private async handleCustodyAppend(
    params: MintReceiptParams,
    receiptObjectId: string,
    mintDigest: string,
    policyPkgFromType: string
  ): Promise<{
    custodyChainObjectId?: string;
    custodyAppendDigest?: string;
    custodyEventObjectId?: string;
    custodyAppendError?: string;
    custodyStatus: CustodyStatus;
    custodyCompliant: boolean;
  }> {
    const effectiveCustodyMode = resolveEffectiveCustodyMode(
      params.custodyMode,
      config.kairo.custodyMode
    );
    let custodyAppendDigest: string | undefined;
    let custodyEventObjectId: string | undefined;
    let custodyAppendError: string | undefined;
    let custodyChainObjectId: string | undefined;
    let custodyStatus: CustodyStatus = "skipped";

    if (effectiveCustodyMode === CustodyMode.DISABLED) {
      custodyStatus = "disabled";
      logger.debug({ receiptObjectId }, "Custody append disabled for this operation");
    } else if (this.custodyAppendFn && this.createCustodyChainFn) {
      try {
        const custodyPkgCandidate = String(
          params.custodyPackageId ?? config.kairo.custodyPackageId ?? ""
        ).trim();
        const custodyPkg = custodyPkgCandidate.startsWith("0x")
          ? custodyPkgCandidate
          : policyPkgFromType;

        let chainId = String(
          params.custodyChainObjectId ?? config.kairo.custodyChainObjectId ?? ""
        ).trim();
        if (!chainId.startsWith("0x")) {
          const created = await this.createCustodyChainFn({
            custodyPackageId: custodyPkg,
            policyObjectId: params.policyId,
          });
          chainId = created.custodyChainObjectId;
        }

        if (chainId.startsWith("0x")) {
          custodyChainObjectId = chainId;
          const r = await this.custodyAppendFn({
            custodyPackageId: custodyPkg,
            custodyChainObjectId: custodyChainObjectId,
            receiptObjectId,
            policyObjectId: params.policyId,
            intentHashHex: params.intentHashHex,
            toEvm: params.toEvm,
            mintDigest,
          });
          custodyAppendDigest = r.digest;
          custodyEventObjectId = r.custodyEventObjectId;
          custodyStatus = "appended";
        }
      } catch (err) {
        custodyAppendError = err instanceof Error ? err.message : String(err);

        if (effectiveCustodyMode === CustodyMode.REQUIRED) {
          logger.error(
            { err, receiptObjectId, custodyMode: effectiveCustodyMode },
            "Custody append failed (REQUIRED mode) - operation cannot complete"
          );
          throw new Error(`Custody append required but failed: ${custodyAppendError}`);
        }

        logger.warn(
          { err, receiptObjectId, custodyMode: effectiveCustodyMode },
          "Custody append failed (BEST_EFFORT mode) - continuing without custody event"
        );
        custodyStatus = "failed";
      }
    }

    const custodyCompliant =
      custodyStatus === "appended" || effectiveCustodyMode === CustodyMode.DISABLED;

    return {
      custodyChainObjectId,
      custodyAppendDigest,
      custodyEventObjectId,
      custodyAppendError,
      custodyStatus,
      custodyCompliant,
    };
  }

  /**
   * Get exposed functions from a module
   */
  private async getModuleExposedFunctions(
    packageId: string,
    moduleName: string
  ): Promise<string[]> {
    try {
      const mod = await this.base.client.getNormalizedMoveModule({
        package: packageId,
        module: moduleName,
      });
      return Object.keys(
        (mod as any)?.exposedFunctions ?? (mod as any)?.functions ?? {}
      ).filter(Boolean);
    } catch {
      return [];
    }
  }

  /**
   * Get policy binding info
   */
  async getPolicyBindingInfo(bindingObjectId: string): Promise<{
    stableId?: string;
    activeVersionId?: string;
  }> {
    const id = String(bindingObjectId ?? "").trim();
    if (!id.startsWith("0x")) return {};

    const obj = await this.base.client.getObject({
      id,
      options: { showType: true, showContent: true },
    });
    const t = String((obj as any)?.data?.type ?? "");
    if (!t.endsWith("::policy_registry::PolicyBinding")) {
      throw new Error(`policyBindingObjectId is not a PolicyBinding (type=${t})`);
    }
    const fields: any = (obj as any)?.data?.content?.fields ?? {};
    const stableId = bytesFieldToUtf8(fields["stable_id"]);
    const activeVersionId = String(fields["active_version_id"] ?? "").trim();
    return {
      stableId: stableId || undefined,
      activeVersionId: activeVersionId.startsWith("0x") ? activeVersionId : undefined,
    };
  }

  /**
   * Get latest policy version ID from registry
   */
  async getLatestPolicyVersionIdFromRegistry(params: {
    registryObjectId: string;
    stableId: string;
  }): Promise<string | null> {
    const registryObjectId = String(params.registryObjectId ?? "").trim();
    const stableId = String(params.stableId ?? "").trim();
    if (!registryObjectId.startsWith("0x") || !stableId) return null;

    const obj = await this.base.client.getObject({
      id: registryObjectId,
      options: { showType: true, showContent: true },
    });
    const t = String((obj as any)?.data?.type ?? "");
    if (!t.endsWith("::policy_registry::PolicyRegistry")) {
      throw new Error(`KAIRO_POLICY_REGISTRY_ID is not a PolicyRegistry (type=${t})`);
    }
    const fields: any = (obj as any)?.data?.content?.fields ?? {};
    const series: any[] = Array.isArray(fields["series"]) ? (fields["series"] as any[]) : [];
    for (const s0 of series) {
      const s = s0 && typeof s0 === "object" && (s0 as any).fields ? (s0 as any).fields : s0;
      const sid = bytesFieldToUtf8((s as any)?.stable_id);
      if (!sid || sid !== stableId) continue;
      const versions: any = (s as any)?.versions;
      if (!Array.isArray(versions) || versions.length === 0) return null;
      const last = String(versions[versions.length - 1] ?? "").trim();
      return last.startsWith("0x") ? last : null;
    }
    return null;
  }

  /**
   * Resolve policy stable ID string from policy object
   */
  async resolvePolicyStableIdString(policyObjectId: string): Promise<string | null> {
    await this.base.initPromise;
    if (!String(policyObjectId ?? "").startsWith("0x")) return null;
    try {
      const obj = await this.base.client.getObject({
        id: policyObjectId,
        options: { showContent: true },
      });
      const fields: any = (obj as any)?.data?.content?.fields ?? {};
      const v = fields["policy_id"];
      return v ? bytesFieldToUtf8(v) : null;
    } catch {
      return null;
    }
  }
}
