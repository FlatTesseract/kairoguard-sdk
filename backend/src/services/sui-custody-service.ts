/**
 * Sui Custody Service - Sui-specific custody operations
 *
 * Extends the abstract CustodyAppendDelegate interface with actual Sui transactions.
 * Responsible for:
 * - Appending custody events to the chain
 * - Creating new custody chains
 * - Implements ICustodyService from the coordinator interface
 */

import { Transaction } from "@mysten/sui/transactions";
import { keccak256, toBytes, type Hex } from "viem";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { SuiClientBase } from "./sui-client-base.js";
import { withTimeout, TIMEOUTS, bytesFieldToU8 } from "./utils.js";
import type { CustodyAppendDelegate } from "./custody-service.js";
import type { ICustodyService } from "../coordinator/operation-coordinator.js";
import type { CustodyResult } from "../types/operation-lifecycle.js";
import type { CustodyMode } from "../custody-mode.js";

/**
 * Sui Custody Service provides the actual Sui transaction implementations
 * for custody operations.
 */
export class SuiCustodyService implements CustodyAppendDelegate, ICustodyService {
  constructor(private readonly base: SuiClientBase) {}

  /**
   * Append custody event with receipt.
   * Implements ICustodyService interface.
   */
  async appendEvent(params: {
    receiptObjectId: string;
    policyObjectId: string;
    intentHashHex: string;
    toEvm: string;
    custodyMode: CustodyMode;
    custodyChainObjectId?: string;
    custodyPackageId?: string;
    mintDigest: string;
  }): Promise<CustodyResult> {
    try {
      // Resolve custody chain
      let chainId = params.custodyChainObjectId;
      if (!chainId || !chainId.startsWith("0x")) {
        const resolved = await this.resolveCustodyChainId(params.policyObjectId);
        if (!resolved) {
          return {
            status: "skipped",
            compliant: false,
            mode: params.custodyMode,
            error: "No custody chain available for policy",
          };
        }
        chainId = resolved;
      }

      const result = await this.appendCustodyEventWithReceipt({
        custodyPackageId:
          params.custodyPackageId ??
          config.kairo.custodyPackageId ??
          config.kairo.policyMintPackageId ??
          "",
        custodyChainObjectId: chainId,
        receiptObjectId: params.receiptObjectId,
        policyObjectId: params.policyObjectId,
        intentHashHex: params.intentHashHex as Hex,
        toEvm: params.toEvm,
        mintDigest: params.mintDigest,
      });

      return {
        status: "appended",
        compliant: true,
        mode: params.custodyMode,
        custodyChainObjectId: chainId,
        custodyEventObjectId: result.custodyEventObjectId,
        custodyAppendDigest: result.digest,
      };
    } catch (err) {
      return {
        status: "failed",
        compliant: false,
        mode: params.custodyMode,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Create a new custody chain for a policy.
   * Implements ICustodyService interface.
   */
  async createChain(params: {
    policyObjectId: string;
    custodyPackageId: string;
  }): Promise<{ custodyChainObjectId: string; digest: string }> {
    return this.createAndShareCustodyChainForPolicy(params);
  }

  /**
   * Append custody event with receipt - actual Sui transaction implementation.
   * Implements CustodyAppendDelegate interface.
   */
  async appendCustodyEventWithReceipt(args: {
    custodyPackageId: string;
    custodyChainObjectId: string;
    receiptObjectId: string;
    policyObjectId: string;
    intentHashHex: Hex;
    toEvm: string;
    mintDigest: string;
    kind?: number;
    srcNamespace?: number;
    srcChainId?: bigint;
    srcTxHashHex?: Hex | null;
    payloadExtra?: Record<string, unknown>;
  }): Promise<{ digest: string; custodyEventObjectId?: string }> {
    await this.base.initPromise;

    const pkg = args.custodyPackageId;
    if (!pkg.startsWith("0x")) throw new Error("Invalid custodyPackageId");

    // Fetch custody chain head hash
    const chainObj = await this.base.client.getObject({
      id: args.custodyChainObjectId,
      options: { showContent: true, showType: true, showOwner: true },
    });
    const chainType = String((chainObj as any)?.data?.type ?? "");
    if (!chainType.includes("::custody_ledger::CustodyChain")) {
      throw new Error(`custodyChainObjectId is not a CustodyChain (type=${chainType})`);
    }
    const sharedVersionRaw = (chainObj as any)?.data?.owner?.Shared?.initial_shared_version;
    const initialSharedVersion = Number(sharedVersionRaw ?? 0);
    if (!Number.isFinite(initialSharedVersion) || initialSharedVersion <= 0) {
      throw new Error("Failed to resolve custody chain shared initial version");
    }
    const headHashAny = (chainObj as any)?.data?.content?.fields?.head_hash;
    const prevHashBytes = bytesFieldToU8(headHashAny);
    if (!prevHashBytes || prevHashBytes.length !== 32) {
      throw new Error("Failed to read custody chain head_hash (expected 32 bytes)");
    }

    // intent_hash is required
    const intentBytes = toBytes(args.intentHashHex);
    if (intentBytes.length !== 32) throw new Error("intentHashHex must be 32 bytes");

    // src_tx_hash (optional)
    const srcTxHashBytes = (() => {
      const h = String(args.srcTxHashHex ?? "").trim();
      if (!h) return null;
      if (!/^0x[0-9a-fA-F]{64}$/.test(h)) throw new Error("srcTxHashHex must be 32 bytes hex");
      return toBytes(h as Hex);
    })();

    // Determine receipt type
    const receiptObj = await this.base.client.getObject({
      id: args.receiptObjectId,
      options: { showType: true, showContent: true },
    });
    const receiptType = String((receiptObj as any)?.data?.type ?? "");
    const isReceiptV4 = receiptType.endsWith("::policy_registry::PolicyReceiptV4");
    const isReceiptV3 = receiptType.endsWith("::policy_registry::PolicyReceiptV3");
    const isReceiptV2 = receiptType.endsWith("::policy_registry::PolicyReceiptV2");

    // For V4/V3 receipts, use the destination from the receipt for multi-chain support
    let toAddrBytes: Uint8Array | null = null;
    if (isReceiptV4 || isReceiptV3) {
      const receiptFields = (receiptObj as any)?.data?.content?.fields ?? {};
      const destBytes = bytesFieldToU8(receiptFields?.destination);
      if (destBytes && destBytes.length > 0) {
        toAddrBytes = destBytes;
      }
    } else {
      const toEvmBytes = toBytes(args.toEvm as Hex);
      toAddrBytes = toEvmBytes.length === 20 ? toEvmBytes : null;
    }

    const payloadObj: Record<string, unknown> = {
      policyObjectId: args.policyObjectId,
      receiptObjectId: args.receiptObjectId,
      toEvm: args.toEvm,
      ...(args.payloadExtra ?? {}),
    };
    const payload = new TextEncoder().encode(JSON.stringify(payloadObj));

    const tx = new Transaction();
    const adminAddress = this.base.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.base.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const chainRef = tx.sharedObjectRef({
      objectId: args.custodyChainObjectId,
      initialSharedVersion,
      mutable: true,
    });

    // Get available custody ledger functions
    const custodyFns = await this.getCustodyLedgerFunctions(pkg);

    const kind = tx.pure.u8(Number.isFinite(args.kind as any) ? Number(args.kind) : 1);
    const srcNamespace = tx.pure.u8(
      Number.isFinite(args.srcNamespace as any) ? Number(args.srcNamespace) : 1
    );
    const srcChainId = tx.pure.u64(args.srcChainId != null ? args.srcChainId : 0n);
    const srcTxHashArg = tx.pure.vector("u8", srcTxHashBytes ? Array.from(srcTxHashBytes) : []);
    const toAddrArg = tx.pure.vector("u8", toAddrBytes ? [...toAddrBytes] : []);
    const intentArg = tx.pure.vector("u8", [...intentBytes]);
    const prevHashArg = tx.pure.vector("u8", [...prevHashBytes]);
    const payloadArg = tx.pure.vector("u8", [...payload]);

    if (isReceiptV4 && custodyFns.has("append_event_with_receipt_v4")) {
      tx.moveCall({
        target: `${pkg}::custody_ledger::append_event_with_receipt_v4`,
        arguments: [
          chainRef,
          tx.object(args.receiptObjectId),
          tx.object("0x6"),
          kind,
          srcNamespace,
          srcChainId,
          srcTxHashArg,
          toAddrArg,
          intentArg,
          prevHashArg,
          payloadArg,
        ],
      });
    } else if (isReceiptV3 && custodyFns.has("append_event_with_receipt_v3")) {
      tx.moveCall({
        target: `${pkg}::custody_ledger::append_event_with_receipt_v3`,
        arguments: [
          chainRef,
          tx.object(args.receiptObjectId),
          tx.object("0x6"),
          kind,
          srcNamespace,
          srcChainId,
          srcTxHashArg,
          toAddrArg,
          intentArg,
          prevHashArg,
          payloadArg,
        ],
      });
    } else if (isReceiptV2 && custodyFns.has("append_event_with_receipt_any_v3")) {
      tx.moveCall({
        target: `${pkg}::custody_ledger::append_event_with_receipt_any_v3`,
        arguments: [
          chainRef,
          tx.object(args.receiptObjectId),
          tx.object("0x6"),
          kind,
          srcNamespace,
          srcChainId,
          srcTxHashArg,
          toAddrArg,
          intentArg,
          prevHashArg,
          payloadArg,
        ],
      });
    } else if (!isReceiptV2 && !isReceiptV3 && custodyFns.has("append_event_with_receipt_any_v2")) {
      tx.moveCall({
        target: `${pkg}::custody_ledger::append_event_with_receipt_any_v2`,
        arguments: [
          chainRef,
          tx.object(args.receiptObjectId),
          tx.object("0x6"),
          kind,
          srcNamespace,
          srcChainId,
          srcTxHashArg,
          toAddrArg,
          intentArg,
          prevHashArg,
          payloadArg,
        ],
      });
    } else {
      // Fallback (legacy): caller-provided event_hash
      const receiptIdBytes = new TextEncoder().encode(args.receiptObjectId);
      const digestBytes = new TextEncoder().encode(args.mintDigest);
      const srcHashBytes = srcTxHashBytes ?? new Uint8Array(0);
      const eventHashHex = keccak256(
        new Uint8Array([
          ...prevHashBytes,
          ...intentBytes,
          ...receiptIdBytes,
          ...digestBytes,
          ...srcHashBytes,
        ])
      );
      const eventHashBytes = toBytes(eventHashHex);
      if (eventHashBytes.length !== 32) throw new Error("eventHash is not 32 bytes");

      tx.moveCall({
        target: `${pkg}::custody_ledger::append_event_with_receipt`,
        arguments: [
          chainRef,
          tx.object(args.receiptObjectId),
          tx.object("0x6"),
          kind,
          srcNamespace,
          srcChainId,
          srcTxHashArg,
          toAddrArg,
          intentArg,
          prevHashArg,
          tx.pure.vector("u8", [...eventHashBytes]),
          payloadArg,
        ],
      });
    }

    const r = await this.base.executeSuiTransaction(tx);

    // Parse created CustodyEvent id
    let custodyEventObjectId: string | undefined;
    try {
      const txResult = await withTimeout(
        this.base.client.waitForTransaction({
          digest: r.digest,
          options: { showObjectChanges: true, showEffects: true },
        }),
        TIMEOUTS.TRANSACTION_WAIT,
        "Custody append confirmation"
      );

      const status = (txResult as any)?.effects?.status;
      if (status?.status && status.status !== "success") {
        const err = String(status.error ?? "unknown execution error");
        throw new Error(`Custody append failed on-chain: ${err}`);
      }

      const changes = ((txResult as any)?.objectChanges ?? []) as Array<any>;
      for (const c of changes) {
        if (c?.type !== "created") continue;
        const t = String(c.objectType ?? "");
        const id = String(c.objectId ?? "");
        if (id && t.endsWith("::custody_ledger::CustodyEvent")) {
          custodyEventObjectId = id;
          break;
        }
      }
    } catch (err) {
      logger.warn({ err, digest: r.digest }, "Failed to parse custody append result");
    }

    logger.info(
      { digest: r.digest, custodyChainObjectId: args.custodyChainObjectId, custodyEventObjectId },
      "Appended custody event"
    );

    return { digest: r.digest, custodyEventObjectId };
  }

  /**
   * Resolve custody chain ID for a policy.
   * Implements CustodyAppendDelegate interface.
   */
  async resolveCustodyChainId(policyObjectId: string): Promise<string | null> {
    const chainId = String(config.kairo.custodyChainObjectId ?? "").trim();
    return chainId.startsWith("0x") ? chainId : null;
  }

  /**
   * Create and share a custody chain for a policy.
   */
  async createAndShareCustodyChainForPolicy(args: {
    custodyPackageId: string;
    policyObjectId: string;
  }): Promise<{ custodyChainObjectId: string; digest: string }> {
    await this.base.initPromise;

    const pkg = String(args.custodyPackageId ?? "").trim();
    if (!pkg.startsWith("0x")) throw new Error("Invalid custodyPackageId");
    const policyId = String(args.policyObjectId ?? "").trim();
    if (!policyId.startsWith("0x")) throw new Error("Invalid policyObjectId");

    // Use policy object id bytes as AssetId.id
    const raw = policyId.slice(2);
    if (raw.length % 2 !== 0) throw new Error("Invalid policyObjectId hex");
    const idBytes = new Uint8Array(raw.length / 2);
    for (let i = 0; i < idBytes.length; i++) {
      idBytes[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
    }

    const tx = new Transaction();
    const adminAddress = this.base.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.base.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${pkg}::custody_ledger::create_and_share_chain_from_parts`,
      arguments: [
        tx.pure.u8(1), // namespace (kairo)
        tx.pure.u64(0n), // chain_id (generic)
        tx.pure.u8(1), // kind (policy)
        tx.pure.vector("u8", Array.from(idBytes)),
      ],
    });

    const r = await this.base.executeSuiTransaction(tx);
    const txResult = await withTimeout(
      this.base.client.waitForTransaction({
        digest: r.digest,
        options: { showObjectChanges: true, showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Custody chain creation confirmation"
    );

    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      throw new Error(`Custody chain creation failed on-chain: ${err}`);
    }

    let custodyChainObjectId: string | null = null;
    const changes = ((txResult as any)?.objectChanges ?? []) as Array<any>;
    for (const c of changes) {
      if (c?.type !== "created") continue;
      const t = String(c.objectType ?? "");
      const id = String(c.objectId ?? "");
      if (id && t.endsWith("::custody_ledger::CustodyChain")) {
        custodyChainObjectId = id;
        break;
      }
    }

    if (!custodyChainObjectId) {
      throw new Error("Failed to find created CustodyChain in transaction result");
    }

    logger.info(
      { custodyChainObjectId, digest: r.digest },
      "Created custody chain for policy"
    );

    return { custodyChainObjectId, digest: r.digest };
  }

  /**
   * Get available custody ledger functions from the package
   */
  private async getCustodyLedgerFunctions(pkg: string): Promise<Set<string>> {
    try {
      const mod = await this.base.client.getNormalizedMoveModule({
        package: pkg,
        module: "custody_ledger",
      });
      const fns = Object.keys(
        (mod as any)?.exposedFunctions ?? (mod as any)?.functions ?? {}
      ).filter(Boolean);
      return new Set(fns);
    } catch {
      return new Set();
    }
  }
}
