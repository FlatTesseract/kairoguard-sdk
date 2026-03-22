/**
 * Presign Service - Handles presign operations for dWallets
 *
 * Responsible for:
 * - Creating presign requests (global and dWallet-specific)
 * - Waiting for presign completion
 * - Managing pricing and coin selection for presign fees
 */

import { Transaction } from "@mysten/sui/transactions";
import {
  coordinatorTransactions,
  SessionsManagerModule,
  CoordinatorInnerModule,
} from "@ika.xyz/sdk";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { SuiClientBase } from "./sui-client-base.js";
import { withTimeout, TIMEOUTS, PricingInfoBcs } from "./utils.js";
import { DKGService } from "./dkg-service.js";

/**
 * Presign pricing information
 */
export interface PresignPricing {
  feeIka: bigint;
  gasFeeReimbursementSui: bigint;
  gasFeeReimbursementSuiForSystemCalls: bigint;
}

/**
 * Presign Service handles presign operations for dWallets.
 * Presigns are required before any signing operation.
 */
export class PresignService {
  private dkgService: DKGService;

  constructor(private readonly base: SuiClientBase) {
    this.dkgService = new DKGService(base);
  }

  /**
   * Execute presign transaction.
   * Presigns are needed before signing messages.
   *
   * @param params.dWalletId - The dWallet object ID
   * @param params.encryptedUserSecretKeyShareId - Optional encrypted key share ID (for activation)
   * @param params.userOutputSignature - Optional user signature (for activation)
   * @returns Presign ID
   */
  async executePresignTransaction(params: {
    dWalletId: string;
    encryptedUserSecretKeyShareId: string;
    userOutputSignature: number[];
  }): Promise<{ presignId: string }> {
    await this.base.initPromise;
    const tx = new Transaction();
    const adminAddress = this.base.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);

    // Get SUI coins for payment
    const suiCoins = await this.base.client.getCoins({
      owner: adminAddress,
      coinType: "0x2::sui::SUI",
    });
    const sortedSuiCoins = [...(suiCoins.data ?? [])].sort(
      (a, b) => Number(BigInt(b.balance) - BigInt(a.balance))
    );

    // Fetch on-chain pricing for presign
    const presignPricing = await this.getPresignPricing();
    const requiredIka = presignPricing?.feeIka ?? 0n;
    const requiredSui = presignPricing
      ? presignPricing.gasFeeReimbursementSui +
        presignPricing.gasFeeReimbursementSuiForSystemCalls
      : 0n;

    // Keep gas budget modest
    const gasBudget = 50_000_000n;
    tx.setGasBudget(gasBudget);

    // Choose an IKA coin object with enough balance
    const ikaPaymentCoinId = await this.base.selectIkaPaymentCoinOrThrow({
      owner: adminAddress,
      requiredIka,
      context: "presign",
    });
    const ikaPaymentCoinArg = tx.object(ikaPaymentCoinId);

    // Choose SUI payment coin
    const gasCoin = sortedSuiCoins[0];
    const secondCoin = sortedSuiCoins[1];

    const pickSecondIfSufficient =
      requiredSui > 0n &&
      secondCoin &&
      BigInt(secondCoin.balance) >= requiredSui
        ? secondCoin
        : null;

    const paymentSuiCoinArg = pickSecondIfSufficient
      ? tx.object(pickSecondIfSufficient.coinObjectId)
      : tx.gas;

    if (gasCoin && pickSecondIfSufficient) {
      tx.setGasPayment([
        {
          objectId: gasCoin.coinObjectId,
          version: gasCoin.version,
          digest: gasCoin.digest,
        },
      ]);
    }

    // Preflight the math if using single coin
    if (!pickSecondIfSufficient && requiredSui > 0n) {
      const totalSui = gasCoin ? BigInt(gasCoin.balance) : 0n;
      if (totalSui < requiredSui + gasBudget) {
        throw new Error(
          `Insufficient SUI for presign with a single SUI coin object: need >= (required_reimbursement=${requiredSui} + gas_budget=${gasBudget}) raw, ` +
            `have ${totalSui}. Top up SUI or consolidate into 2 SUI coin objects.`
        );
      }
    }

    const random32Bytes = new Uint8Array(32);
    crypto.getRandomValues(random32Bytes);

    // Wait for dWallet to be ready
    const dWalletState = await this.dkgService.waitForDWalletReadyForPresign(
      params.dWalletId
    );
    if (dWalletState.kind === "AwaitingKeyHolderSignature") {
      if (
        !params.encryptedUserSecretKeyShareId ||
        params.userOutputSignature.length === 0
      ) {
        throw new Error(
          "DWallet is not Active yet; presign requires activation inputs (encryptedUserSecretKeyShareId + userOutputSignature)."
        );
      }
      coordinatorTransactions.acceptEncryptedUserShare(
        this.base.ikaConfig,
        tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        params.dWalletId,
        params.encryptedUserSecretKeyShareId,
        new Uint8Array(params.userOutputSignature),
        tx
      );
    } else if (dWalletState.kind !== "Active") {
      throw new Error(
        `DWallet is not ready for presign yet (state=${dWalletState.kind}). Please wait and try again.`
      );
    }

    // Determine presign type (global vs dWallet-specific)
    const dWallet = await this.base.ikaClient.getDWallet(params.dWalletId);
    const isImported = Boolean((dWallet as any)?.is_imported_key_dwallet);
    const publicOutputBytes: number[] | undefined =
      (dWallet as any)?.state?.Active?.public_output ??
      (dWallet as any)?.state?.AwaitingKeyHolderSignature?.public_output;
    const dWalletVersion =
      publicOutputBytes && publicOutputBytes.length > 0
        ? Number(publicOutputBytes[0] ?? 0) + 1
        : null;

    const signatureAlgorithmNumber = 0; // ECDSA secp256k1
    const useGlobalPresign =
      (!isImported && dWalletVersion !== 1) || dWalletVersion == null;

    // Build the Move calls
    const sessionIdentifier = coordinatorTransactions.registerSessionIdentifier(
      this.base.ikaConfig,
      tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      random32Bytes,
      tx
    );
    const presign = useGlobalPresign
      ? coordinatorTransactions.requestGlobalPresign(
          this.base.ikaConfig,
          tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
          String((dWallet as any)?.dwallet_network_encryption_key_id),
          Number((dWallet as any)?.curve),
          signatureAlgorithmNumber,
          sessionIdentifier,
          ikaPaymentCoinArg,
          paymentSuiCoinArg,
          tx
        )
      : coordinatorTransactions.requestPresign(
          this.base.ikaConfig,
          tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
          params.dWalletId,
          signatureAlgorithmNumber,
          sessionIdentifier,
          ikaPaymentCoinArg,
          paymentSuiCoinArg,
          tx
        );

    // Transfer presign to admin
    tx.transferObjects([presign], adminAddress);

    const result = await this.base.executeSuiTransaction(tx);

    // Parse presign ID from events
    const txResult = await withTimeout(
      this.base.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true, showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Presign transaction confirmation"
    );

    const status = txResult.effects?.status?.status;
    if (status && status !== "success") {
      const err = String(
        (txResult.effects?.status as any)?.error ?? "unknown error"
      );

      // Provide actionable error for common MoveAbort cases
      let balancesSummary = "";
      try {
        const balances = await this.base.client.getAllBalances({
          owner: adminAddress,
        });
        const byType = new Map(balances.map((b) => [b.coinType, b.totalBalance]));
        const suiBal = byType.get("0x2::sui::SUI");
        const ikaTypePrefix = "::ika::IKA";
        const ikaEntry = balances.find((b) =>
          b.coinType.endsWith(ikaTypePrefix)
        );
        const ikaBal = ikaEntry?.totalBalance;
        balancesSummary =
          ` Admin balances (raw):` +
          (suiBal ? ` SUI=${suiBal}` : ` SUI=(unknown)`) +
          (ikaBal ? ` IKA=${ikaBal}` : ` IKA=(unknown)`);
      } catch {
        // ignore
      }

      const abortMatch = err.match(/MoveAbort\([\s\S]*?,\s*(\d+)\)\s*in command/i);
      const abortCode = abortMatch ? Number(abortMatch[1]) : null;

      if (
        abortCode === 31 &&
        err.includes('name: Identifier("coordinator_inner")') &&
        (err.includes('function_name: Some("request_presign")') ||
          err.includes('function_name: Some("request_global_presign")'))
      ) {
        throw new Error(
          "Presign transaction failed on-chain with abort code 31 (EOnlyGlobalPresignAllowed). " +
            "This means the network requires **global presign** for this dWallet/curve/algorithm. " +
            "Fix: upgrade the backend to request `request_global_presign` instead of `request_presign` for this case." +
            balancesSummary +
            ` Tx digest: ${result.digest}. Underlying error: ${err}`
        );
      }

      throw new Error(
        `Presign transaction failed: ${err}` +
          (balancesSummary ? ` ${balancesSummary}` : "") +
          ` Tx digest: ${result.digest}`
      );
    }

    let presignId: string | null = null;
    const eventTypes = (txResult.events || []).map((e) => e.type);
    for (const event of txResult.events || []) {
      try {
        const parsedData = SessionsManagerModule.DWalletSessionEvent(
          CoordinatorInnerModule.PresignRequestEvent
        ).fromBase64(event.bcs);
        if (parsedData?.event_data?.presign_id) {
          presignId = parsedData.event_data.presign_id;
          break;
        }
      } catch {
        // ignore and continue
      }
    }

    if (!presignId) {
      logger.error(
        { digest: result.digest, eventTypes },
        "Failed to get presign ID from transaction (no PresignRequestEvent decoded)"
      );
      throw new Error(
        `Failed to get presign ID from transaction ${result.digest}. ` +
          `Events seen: ${eventTypes.join(", ") || "(none)"}`
      );
    }

    return { presignId };
  }

  /**
   * Wait for a presign to complete.
   *
   * @param presignId - The presign object ID
   * @param requestLogger - Logger instance for this request
   * @returns Presign output bytes
   */
  async waitForPresignCompleted(
    presignId: string,
    requestLogger: typeof logger
  ): Promise<Uint8Array> {
    const start = Date.now();
    let lastErr: string | null = null;

    // Helper for decoding unknown "bytes" shapes
    const toUint8Array = (v: unknown, label: string): Uint8Array => {
      if (v instanceof Uint8Array) return v;
      if (
        Array.isArray(v) &&
        v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)
      ) {
        return Uint8Array.from(v);
      }
      if (typeof v === "string") {
        if (/^0x[0-9a-fA-F]*$/.test(v)) {
          const raw = v.slice(2);
          if (raw.length % 2 !== 0) throw new Error(`${label} hex has odd length`);
          const out = new Uint8Array(raw.length / 2);
          for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
          }
          return out;
        }
        // base64 best-effort
        return Uint8Array.from(Buffer.from(v, "base64"));
      }
      if (v && typeof v === "object") {
        const o = v as Record<string, unknown>;
        if (o.bytes != null) return toUint8Array(o.bytes, label);
        if (o.data != null) return toUint8Array(o.data, label);
        if (o.value != null) return toUint8Array(o.value, label);
      }
      throw new Error(`${label} is not bytes`);
    };

    while (Date.now() - start < TIMEOUTS.PRESIGN_WAIT) {
      try {
        const presign = await this.base.ikaClient.getPresignInParticularState(
          presignId,
          "Completed"
        );
        const presignOut = (presign as any)?.state?.Completed?.presign;
        const bytes = toUint8Array(presignOut, "presign output");
        if (bytes.length === 0) {
          throw new Error("Presign output is empty");
        }
        return bytes;
      } catch (err) {
        lastErr = err instanceof Error ? err.message : String(err);
        requestLogger.warn(
          { presignId, err: lastErr },
          "Presign not completed yet; retrying"
        );
        await new Promise((r) => setTimeout(r, 2000));
      }
    }

    throw new Error(
      `Timeout waiting for presign ${presignId} to reach state Completed. Last error: ${lastErr ?? "(none)"}`
    );
  }

  /**
   * Get on-chain pricing for presign operations.
   * Uses devInspect to read coordinator::current_pricing().
   *
   * @returns Pricing info or null if unavailable
   */
  async getPresignPricing(): Promise<PresignPricing | null> {
    const tx = new Transaction();
    coordinatorTransactions.currentPricing(
      this.base.ikaConfig,
      tx.object(this.base.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      tx
    );
    let entries: Array<any> | null = null;
    try {
      const res = await this.base.client.devInspectTransactionBlock({
        sender: this.base.adminKeypair.toSuiAddress(),
        transactionBlock: tx,
      });
      const bytes = res.results?.at(0)?.returnValues?.at(0)?.at(0);
      if (!bytes) {
        logger.warn(
          { network: config.sui.network },
          "Could not read return value from coordinator::current_pricing via devInspect; skipping pricing preflight"
        );
        return null;
      }
      const raw =
        Array.isArray(bytes)
          ? Uint8Array.from(bytes)
          : Buffer.from(String(bytes), "base64");
      const decoded = PricingInfoBcs.parse(raw) as any;
      const parsedEntries = decoded?.pricing_map?.contents as Array<any>;
      if (!Array.isArray(parsedEntries)) {
        logger.warn(
          { network: config.sui.network },
          "Could not decode PricingInfo.pricing_map; skipping pricing preflight"
        );
        return null;
      }
      entries = parsedEntries;
    } catch (err) {
      logger.warn(
        { err, network: config.sui.network },
        "Presign pricing devInspect failed; skipping pricing preflight"
      );
      return null;
    }

    // Constants for presign pricing lookup
    const TARGET_CURVE = 0; // SECP256K1
    const TARGET_SIGALG = 0; // ECDSA
    const TARGET_PROTOCOL = 5; // PRESIGN_PROTOCOL_FLAG

    const decodeOptU32 = (v: unknown): number | null => {
      if (v == null) return null;
      if (typeof v === "number") return v;
      if (typeof v === "string" && v.length) return Number(v);
      if (typeof v === "object" && v) {
        if ("Some" in (v as any)) return Number((v as any).Some);
      }
      return null;
    };

    const candidates = (entries ?? []).filter((e) => {
      const k = e?.key;
      const curve = Number(k?.curve);
      const protocol = Number(k?.protocol);
      const sig = decodeOptU32(k?.signature_algorithm);
      return curve === TARGET_CURVE && protocol === TARGET_PROTOCOL && sig != null;
    });

    const match =
      candidates.find(
        (e) => decodeOptU32(e?.key?.signature_algorithm) === TARGET_SIGALG
      ) ??
      candidates[0] ??
      null;

    if (!match?.value) {
      return null;
    }

    const v = match.value;
    const feeIka = BigInt(v.fee_ika);
    const gasFeeReimbursementSui = BigInt(v.gas_fee_reimbursement_sui);
    const gasFeeReimbursementSuiForSystemCalls = BigInt(
      v.gas_fee_reimbursement_sui_for_system_calls
    );
    return { feeIka, gasFeeReimbursementSui, gasFeeReimbursementSuiForSystemCalls };
  }
}
