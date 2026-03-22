import { SuiClient, type SuiObjectResponse } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import {
  getNetworkConfig,
  IkaClient,
  coordinatorTransactions,
  type IkaConfig,
  SessionsManagerModule,
  CoordinatorInnerModule,
  Curve,
  publicKeyFromCentralizedDKGOutput,
  SignatureAlgorithm,
  IkaTransaction,
  Hash,
} from "@ika.xyz/sdk";
import {
  serializeTransaction,
  type TransactionSerializableEIP1559,
  type Hex,
  recoverTransactionAddress,
  keccak256,
  toBytes,
} from "viem";
import bs58 from "bs58";
import { config } from "./config.js";
import { CustodyMode, CustodyStatus, resolveEffectiveCustodyMode } from "./custody-mode.js";
import { logger } from "./logger.js";
import type {
  DKGRequest,
  DKGSubmitInput,
  ImportedKeyVerifyRequest,
  ImportedKeyVerifySubmitInput,
  PresignRequest,
  SignRequest,
  SignRequestInput,
} from "./types.js";
import { computeAddress } from "ethers";
import { bcs } from "@mysten/sui/bcs";
import { getEvmChainName, getEvmPublicClient } from "./evm-chains.js";
import { VaultService, objectIdToBytes, chainIdToBytes, computeIntentDigestV1, NAMESPACE_EVM, NAMESPACE_BITCOIN, NAMESPACE_SOLANA } from "./services/vault-service.js";
import { PolicyDeniedError, getDenialReasonName } from "./types/errors.js";

/**
 * Wrap a SuiClient so that `getObject` calls are throttled to at most
 * `maxConcurrent` in-flight at a time, with retry + backoff on 429s.
 * This prevents the Ika SDK's bulk `Promise.all(getObject(...))` from
 * tripping Sui RPC rate limits.
 */
function throttleSuiClient(
  client: SuiClient,
  maxConcurrent = 10,
  maxRetries = 5,
): SuiClient {
  let inflight = 0;
  const queue: Array<() => void> = [];

  function release() {
    inflight--;
    if (queue.length > 0) {
      inflight++;
      queue.shift()!();
    }
  }

  function acquire(): Promise<void> {
    if (inflight < maxConcurrent) {
      inflight++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => queue.push(resolve));
  }

  const origGetObject = client.getObject.bind(client);
  (client as any).getObject = async function throttledGetObject(
    ...args: Parameters<typeof origGetObject>
  ): Promise<SuiObjectResponse> {
    await acquire();
    try {
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
          return await origGetObject(...args);
        } catch (err: any) {
          const is429 =
            err?.message?.includes("429") ||
            err?.cause?.message?.includes("429");
          if (is429 && attempt < maxRetries) {
            const delay = Math.min(1000 * 2 ** attempt, 8000);
            await new Promise((r) => setTimeout(r, delay));
            continue;
          }
          throw err;
        }
      }
      return await origGetObject(...args);
    } finally {
      release();
    }
  };

  return client;
}

// Timeout helper to prevent indefinite waits
function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(`${operation} timed out after ${timeoutMs}ms`)),
        timeoutMs
      )
    ),
  ]);
}

// Operation timeouts (in milliseconds)
const TIMEOUTS = {
  TRANSACTION_WAIT: 60_000, // 60 seconds for transaction confirmation
  SIGN_WAIT: 120_000, // 2 minutes for signature from network
  PRESIGN_WAIT: 120_000, // 2 minutes for presign completion
  ETH_RECEIPT_WAIT: 60_000, // 60 seconds for ETH transaction receipt
} as const;

// In-memory store for DKG requests
const dkgRequests = new Map<string, DKGRequest>();
// In-memory store for imported-key verification requests
const importedVerifyRequests = new Map<string, ImportedKeyVerifyRequest>();
// In-memory store for presign requests
const presignRequests = new Map<string, PresignRequest>();
// In-memory store for sign requests
const signRequests = new Map<string, SignRequest>();

// In-memory ring buffer for policy/vault audit events
type PolicyAuditEvent = {
  kind: "policy_create" | "binding_create" | "receipt_mint" | "vault_register" | "vault_sign" | "vault_denial";
  createdAtMs: number;
  digest?: string;
  objectId?: string;
  error?: string;
  meta?: Record<string, unknown>;
};
const POLICY_AUDIT_MAX = 500;
const policyAuditEvents: PolicyAuditEvent[] = [];
function pushPolicyAudit(evt: PolicyAuditEvent) {
  policyAuditEvents.push(evt);
  if (policyAuditEvents.length > POLICY_AUDIT_MAX) {
    policyAuditEvents.splice(0, policyAuditEvents.length - POLICY_AUDIT_MAX);
  }
}

// Curve constants
const CURVE_SECP256K1 = 0; // For Ethereum
const CURVE_ED25519 = 2; // For Solana (EdDSA)

// Signature algorithm numeric constants (coordinator_inner)
// NOTE: These are numeric protocol identifiers used by the on-chain coordinator.
const SIGALG_ECDSA_SECP256K1 = 0;
const SIGALG_TAPROOT = 1;
const SIGALG_ED25519 = 2;
import { bytesToHex } from "@noble/hashes/utils";

function isRpcRateLimited(err: unknown): boolean {
  const e: any = err;
  const msg = String(e?.message ?? "");
  const causeMsg = String(e?.cause?.message ?? "");
  const combined = `${msg} ${causeMsg}`;
  return /429|too many requests|rate.?limit/i.test(combined);
}

// --- Minimal BCS decoding for `ika_dwallet_2pc_mpc::pricing::PricingInfo` ---
// We use this only for better error messages & coin selection.
const PricingInfoKeyBcs = bcs.struct("PricingInfoKey", {
  curve: bcs.u32(),
  signature_algorithm: bcs.option(bcs.u32()),
  protocol: bcs.u32(),
});
const PricingInfoValueBcs = bcs.struct("PricingInfoValue", {
  fee_ika: bcs.u64(),
  gas_fee_reimbursement_sui: bcs.u64(),
  gas_fee_reimbursement_sui_for_system_calls: bcs.u64(),
});
const PricingInfoEntryBcs = bcs.struct("VecMapEntry", {
  key: PricingInfoKeyBcs,
  value: PricingInfoValueBcs,
});
const PricingInfoVecMapBcs = bcs.struct("VecMap", {
  contents: bcs.vector(PricingInfoEntryBcs),
});
const PricingInfoBcs = bcs.struct("PricingInfo", {
  pricing_map: PricingInfoVecMapBcs,
});

/**
 * Derive Ethereum address from BCS-encoded SECP256K1 public key (x-coordinate only)
 */

function deriveEthereumAddress(publicKeyBytes: Uint8Array): string {
  // accepts 33B compressed or 65B uncompressed (with 0x04)
  return computeAddress(("0x" + bytesToHex(publicKeyBytes)) as `0x${string}`);
}

function deriveSolanaAddress(publicKeyBytes: Uint8Array): string {
  // Solana addresses are base58-encoded Ed25519 public keys (32 bytes).
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid Solana public key length: ${publicKeyBytes.length} (expected 32)`);
  }
  return bs58.encode(publicKeyBytes);
}

// EVM RPC clients are created per-chainId (see evm-chains.ts).

/**
 * DKG Executor Service
 * Processes DKG requests and creates dWallets on the Ika network
 */
export class DKGExecutorService {
  private client: SuiClient;
  private ikaConfig: IkaConfig;
  private ikaClient: IkaClient;
  private adminKeypair: Ed25519Keypair;
  private initPromise: Promise<void>;
  private isRunning = false;
  private pollTimeout: NodeJS.Timeout | null = null;
  private ikaCoinTypeCache: string | null = null;
  private vaultService: VaultService | null = null;

  // Cache the latest network encryption key to avoid hammering RPC.
  // Also ensure only one fetch is inflight at a time.
  private networkEncryptionKeyCache:
    | { value: any; fetchedAtMs: number }
    | null = null;
  private networkEncryptionKeyInflight: Promise<any> | null = null;

  constructor() {
    // Get network-specific RPC URL
    const rpcUrl = config.sui.rpcUrl
      ? config.sui.rpcUrl
      : config.sui.network === "mainnet"
        ? "https://ikafn-on-sui-2-mainnet.ika-network.net/"
        : "https://rpc.testnet.sui.io";

    this.client = new SuiClient({ url: rpcUrl });
    this.ikaConfig = getNetworkConfig(config.sui.network);
    this.ikaClient = new IkaClient({
      suiClient: throttleSuiClient(this.client),
      config: this.ikaConfig,
    });

    // Initialize admin keypair
    try {
      this.adminKeypair = Ed25519Keypair.fromSecretKey(config.sui.adminSecretKey);
    } catch (err) {
      const msg = String((err as any)?.message ?? err ?? "unknown error");
      // Most common issues on Windows are truncation, invisible whitespace, or pasting the wrong key format.
      // The Sui SDK expects a Bech32 string starting with "suiprivkey" for string inputs.
      throw new Error(
        "Invalid `SUI_ADMIN_SECRET_KEY` in backend `.env`.\n" +
          "- Expected: a Bech32 private key string starting with `suiprivkey...` (ED25519).\n" +
          "- Common causes: key is truncated (missing the last 6 checksum chars), has extra whitespace, or is not ED25519.\n" +
          "- Fix (PowerShell):\n" +
          "    $addr = sui client active-address\n" +
          "    sui keytool export $addr\n" +
          "  Then copy-paste the full output into `SUI_ADMIN_SECRET_KEY=` in `external/key-spring/backend/.env`.\n" +
          `Underlying error: ${msg}`
      );
    }

    // Kick off async startup validation (e.g. coin objects, package ids, Ika client init).
    // Transactional paths await this to fail fast with a clear error message.
    // IMPORTANT: attach a catch handler so a rejection here doesn't become an "unhandled promise rejection"
    // during startup before any request path has awaited it.
    this.initPromise = this.validateConfigOrThrow();
    this.initPromise.catch((err) => {
      logger.error(
        { err },
        "Async startup validation failed (requests will fail until config is fixed)"
      );
    });

    logger.info(
      {
        signerAddress: this.adminKeypair.toSuiAddress(),
        network: config.sui.network,
      },
      "DKG Executor initialized"
    );
  }

  private async validateConfigOrThrow(): Promise<void> {
    try {
      // Ika docs require an initialized IkaClient before using dWallet operations.
      // This will also exercise RPC connectivity early and fail fast if Sui RPC egress/DNS is broken.
      await withTimeout(
        this.ikaClient.initialize(),
        45_000,
        "IkaClient.initialize"
      );

      // Validate that the admin has an IKA coin type available (we select coin objects dynamically).
      // This avoids brittle env configuration (coin object ids change whenever coins are merged/split/used).
      const ikaCoinType = await this.detectIkaCoinType();
      const ikaCoins = await this.client.getCoins({
        owner: this.adminKeypair.toSuiAddress(),
        coinType: ikaCoinType,
      });
      if (!(ikaCoins.data ?? []).length) {
        throw new Error(
          `No IKA coin objects found for admin=${this.adminKeypair.toSuiAddress()} on Sui ${config.sui.network} (coinType=${ikaCoinType}).\n` +
            `Fund the admin address with IKA on this network.`
        );
      }

      // Validate Ika package ids. On Sui, Move package ids are also object ids (type "package").
      // We have seen SDK testnet configs drift; fail fast with a clear error.
      const pkgIds = [
        this.ikaConfig.packages.ikaPackage,
        this.ikaConfig.packages.ikaCommonPackage,
        this.ikaConfig.packages.ikaSystemPackage,
        this.ikaConfig.packages.ikaDwallet2pcMpcPackage,
      ];
      for (const pid of pkgIds) {
        const p = await this.client.getObject({ id: pid, options: { showType: true } });
        const errCode = (p as any)?.error?.code as string | undefined;
        if (errCode === "notExists") {
          throw new Error(
            `Ika package id does not exist on Sui ${config.sui.network}: ${pid}\n` +
              `This usually means the SDK's network config is stale or the backend is pointing at the wrong network RPC.`
          );
        }
        const t = (p as any)?.data?.type as string | undefined;
        if (t !== "package") {
          throw new Error(
            `Ika package id is not a package object on Sui ${config.sui.network}: ${pid} (type=${t ?? "unknown"})`
          );
        }
      }

      // Sanity check: can we fetch the network encryption key?
      // This is required for DKG and imported-key verification.
      // IMPORTANT: do NOT fail backend startup on transient RPC throttling (429).
      // We'll retry/cached-fetch on demand in request paths.
      const enk = await this.getLatestNetworkEncryptionKeyCached({
        op: "StartupValidation",
        maxAgeMs: 0, // force one fetch for the log line
      });
      logger.info(
        { encryptionKeyId: (enk as any)?.id },
        "Ika network encryption key reachable"
      );
    } catch (err) {
      const e: any = err;
      const msg = String(e?.message ?? e ?? "unknown error");
      const causeMsg = e?.cause ? String(e.cause?.message ?? e.cause) : "";
      // Keep original message but include cause if present (undici often attaches useful info).
      // If the RPC is rate-limiting us, don't permanently brick the backend; log and continue.
      if (isRpcRateLimited(err)) {
        logger.warn(
          { err: msg, cause: causeMsg || undefined },
          "Startup validation hit RPC rate limit; continuing (requests may retry)"
        );
        return;
      }
      throw new Error(
        `Backend config validation failed: ${msg}` +
          (causeMsg ? ` (cause: ${causeMsg})` : "")
      );
    }
  }

  private async getLatestNetworkEncryptionKeyWithRetry(args: {
    op: string;
    attempts?: number;
  }): Promise<any> {
    const attempts = args.attempts ?? 3;
    let lastErr: unknown = null;
    for (let i = 1; i <= attempts; i++) {
      try {
        return await withTimeout(
          this.ikaClient.getLatestNetworkEncryptionKey(),
          30_000,
          `${args.op}: getLatestNetworkEncryptionKey (attempt ${i}/${attempts})`
        );
      } catch (err) {
        lastErr = err;
        const e: any = err;
        logger.warn(
          {
            attempt: i,
            attempts,
            err: e?.message ?? String(e),
            cause: e?.cause?.message ?? (e?.cause ? String(e.cause) : undefined),
          },
          "Failed to fetch network encryption key; retrying"
        );
        // Exponential backoff with jitter. If rate-limited, wait longer.
        const base = isRpcRateLimited(err) ? 8_000 : 800;
        const max = isRpcRateLimited(err) ? 60_000 : 10_000;
        const exp = Math.min(max, base * Math.pow(2, i - 1));
        const jitter = Math.floor(Math.random() * 250);
        await new Promise((r) => setTimeout(r, exp + jitter));
      }
    }
    throw lastErr instanceof Error
      ? lastErr
      : new Error(String(lastErr ?? "Failed to fetch network encryption key"));
  }

  private async getLatestNetworkEncryptionKeyCached(args: {
    op: string;
    /** Cache max age in ms. Default: 60s */
    maxAgeMs?: number;
  }): Promise<any> {
    const maxAgeMs = typeof args.maxAgeMs === "number" ? args.maxAgeMs : 60_000;
    const now = Date.now();

    const cached = this.networkEncryptionKeyCache;
    if (cached && now - cached.fetchedAtMs <= maxAgeMs) {
      return cached.value;
    }

    if (this.networkEncryptionKeyInflight) {
      return await this.networkEncryptionKeyInflight;
    }

    this.networkEncryptionKeyInflight = (async () => {
      try {
        const val = await this.getLatestNetworkEncryptionKeyWithRetry({
          op: args.op,
          attempts: 5,
        });
        this.networkEncryptionKeyCache = { value: val, fetchedAtMs: Date.now() };
        return val;
      } finally {
        this.networkEncryptionKeyInflight = null;
      }
    })();

    return await this.networkEncryptionKeyInflight;
  }

  /**
   * Execute a Sui transaction without parsing raw effects.
   *
   * Why: On fast-moving testnets, new effect/status enum variants can appear before
   * JS SDK decoders are updated. The built-in SerialTransactionExecutor parses
   * `rawEffects` for caching, which can throw errors like:
   * "Unknown value 13 for enum CommandArgumentError".
   *
   * For this backend we only need the digest here; we later call
   * `waitForTransaction({ showEvents: true })` to parse Ika events.
   */
  private async executeSuiTransaction(tx: Transaction): Promise<{ digest: string }> {
    const bytes = await tx.build({ client: this.client });
    const { signature } = await this.adminKeypair.signTransaction(bytes);
    const result = await this.client.executeTransactionBlock({
      transactionBlock: bytes,
      signature: [signature],
      requestType: "WaitForLocalExecution",
      options: {
        showInput: false,
        showEffects: false,
        showEvents: false,
        showObjectChanges: false,
        showBalanceChanges: false,
        showRawEffects: false,
      },
    });
    return { digest: result.digest };
  }

  /**
   * Get IKA client for external use
   */
  getIkaClient(): IkaClient {
    return this.ikaClient;
  }

  /**
   * Resolves when IkaClient initialization completes (or rejects).
   */
  waitForInit(): Promise<void> {
    return this.initPromise;
  }

  async activateDWallet(params: {
    dWalletId: string;
    encryptedUserSecretKeyShareId: string;
    userOutputSignature: number[];
  }): Promise<{ digest: string }> {
    await this.initPromise;

    const tx = new Transaction();
    tx.setSender(this.adminKeypair.toSuiAddress());
    await this.setAdminGas(
      tx,
      this.adminKeypair.toSuiAddress(),
      BigInt(config.sui.gasBudgetsMist.sign)
    );

    coordinatorTransactions.acceptEncryptedUserShare(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      params.dWalletId,
      params.encryptedUserSecretKeyShareId,
      new Uint8Array(params.userOutputSignature),
      tx
    );

    const result = await this.executeSuiTransaction(tx);
    return { digest: result.digest };
  }

  /**
   * Submit a new DKG request
   */
  submitRequest(data: DKGSubmitInput): DKGRequest {
    const id = crypto.randomUUID();
    const request: DKGRequest = {
      id,
      status: "pending",
      data,
      createdAt: new Date(),
    };
    dkgRequests.set(id, request);
    logger.info(
      { requestId: id, curve: data.curve ?? CURVE_SECP256K1 },
      "DKG request submitted"
    );
    return request;
  }

  /**
   * Get request status
   */
  getRequest(id: string): DKGRequest | undefined {
    return dkgRequests.get(id);
  }

  /**
   * Submit an imported-key verification request (creates an ImportedKey dWallet)
   */
  submitImportedVerifyRequest(
    data: ImportedKeyVerifySubmitInput
  ): ImportedKeyVerifyRequest {
    const id = crypto.randomUUID();
    const request: ImportedKeyVerifyRequest = {
      id,
      status: "pending",
      data,
      createdAt: new Date(),
    };
    importedVerifyRequests.set(id, request);
    logger.info({ requestId: id }, "Imported-key verification request submitted");
    return request;
  }

  /**
   * Get imported-key verification request status
   */
  getImportedVerifyRequest(id: string): ImportedKeyVerifyRequest | undefined {
    return importedVerifyRequests.get(id);
  }

  /**
   * Submit a presign request
   */
  submitPresignRequest(data: {
    dWalletId: string;
    curve?: number;
    signatureAlgorithm?: number;
    encryptedUserSecretKeyShareId?: string;
    userOutputSignature?: number[];
  }): PresignRequest {
    const id = crypto.randomUUID();
    const request: PresignRequest = {
      id,
      status: "pending",
      dWalletId: data.dWalletId,
      curve: typeof data.curve === "number" ? data.curve : undefined,
      signatureAlgorithm:
        typeof data.signatureAlgorithm === "number"
          ? data.signatureAlgorithm
          : undefined,
      encryptedUserSecretKeyShareId: data.encryptedUserSecretKeyShareId ?? "",
      userOutputSignature: data.userOutputSignature ?? [],
      createdAt: new Date(),
    };
    presignRequests.set(id, request);
    logger.info(
      { requestId: id, dWalletId: data.dWalletId },
      "Presign request submitted"
    );
    return request;
  }

  /**
   * Get presign request status
   */
  getPresignRequest(id: string): PresignRequest | undefined {
    return presignRequests.get(id);
  }

  /**
   * Submit a sign request (non-custodial)
   * The userSignMessage is computed client-side - secret share never leaves the client
   */
  submitSignRequest(data: SignRequestInput): SignRequest {
    const id = crypto.randomUUID();
    const request: SignRequest = {
      id,
      status: "pending",
      data,
      createdAt: new Date(),
    };
    signRequests.set(id, request);
    logger.info(
      { requestId: id, dWalletId: data.dWalletId, presignId: data.presignId },
      "Sign request submitted"
    );
    return request;
  }

  /**
   * Get sign request status
   */
  getSignRequest(id: string): SignRequest | undefined {
    return signRequests.get(id);
  }

  /**
   * Start the execution loop
   */
  start(): void {
    if (this.isRunning) {
      logger.warn("DKG Executor is already running");
      return;
    }

    this.isRunning = true;
    logger.info("Starting DKG Executor...");

    // Start polling with error recovery
    this.poll().catch((err) => {
      logger.error({ err }, "Error starting poll loop - will retry");
      if (this.isRunning) {
        this.pollTimeout = setTimeout(() => this.poll(), 5000);
      }
    });
  }

  /**
   * Stop the execution loop
   */
  stop(): void {
    this.isRunning = false;
    if (this.pollTimeout) {
      clearTimeout(this.pollTimeout);
      this.pollTimeout = null;
    }
    logger.info("Stopped DKG Executor");
  }

  /**
   * Poll for pending requests
   * Uses setInterval pattern for more reliable scheduling on Railway
   */
  private async poll(): Promise<void> {
    if (!this.isRunning) return;

    try {
      await this.processPendingRequests();
    } catch (error) {
      logger.error({ error }, "Error processing DKG requests");
    }

    try {
      await this.processPendingImportedVerifications();
    } catch (error) {
      logger.error({ error }, "Error processing imported-key verifications");
    }

    try {
      await this.processPendingPresigns();
    } catch (error) {
      logger.error({ error }, "Error processing presigns");
    }

    try {
      await this.processPendingSigns();
    } catch (error) {
      logger.error({ error }, "Error processing signs");
    }

    try {
      this.cleanupOldRequests();
    } catch (error) {
      logger.error({ error }, "Error cleaning up old requests");
    }

    // Schedule next poll (2 seconds) - always schedule even if errors occurred
    if (this.isRunning) {
      this.pollTimeout = setTimeout(() => {
        this.poll().catch((err) => {
          logger.error({ err }, "Fatal error in poll loop - restarting");
          // Force restart the poll loop after a delay
          if (this.isRunning) {
            this.pollTimeout = setTimeout(() => this.poll(), 5000);
          }
        });
      }, 2000);
    }
  }

  /**
   * Clean up old completed/failed requests to prevent memory leaks
   * Keeps requests for 1 hour after completion
   */
  private cleanupOldRequests(): void {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;

    for (const [id, request] of dkgRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        dkgRequests.delete(id);
      }
    }

    for (const [id, request] of importedVerifyRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        importedVerifyRequests.delete(id);
      }
    }

    for (const [id, request] of presignRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        presignRequests.delete(id);
      }
    }

    for (const [id, request] of signRequests) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < oneHourAgo
      ) {
        signRequests.delete(id);
      }
    }
  }

  /**
   * Process all pending requests
   */
  private async processPendingRequests(): Promise<void> {
    const pending = Array.from(dkgRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info({ count: pending.length }, "Processing pending DKG requests");

    for (const request of pending) {
      await this.processRequest(request);
    }
  }

  /**
   * Process all pending imported-key verification requests
   */
  private async processPendingImportedVerifications(): Promise<void> {
    const pending = Array.from(importedVerifyRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info(
      { count: pending.length },
      "Processing pending imported-key verification requests"
    );

    for (const request of pending) {
      await this.processImportedVerifyRequest(request);
    }
  }

  /**
   * Process all pending presign requests
   */
  private async processPendingPresigns(): Promise<void> {
    const pending = Array.from(presignRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info(
      { count: pending.length },
      "Processing pending presign requests"
    );

    for (const request of pending) {
      await this.processPresignRequest(request);
    }
  }

  /**
   * Process all pending sign requests
   */
  private async processPendingSigns(): Promise<void> {
    const pending = Array.from(signRequests.values()).filter(
      (r) => r.status === "pending"
    );

    if (pending.length === 0) return;

    logger.info({ count: pending.length }, "Processing pending sign requests");

    for (const request of pending) {
      await this.processSignRequest(request);
    }
  }

  /**
   * Process a single DKG request
   */
  private async processRequest(request: DKGRequest): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      // Mark as processing
      request.status = "processing";
      requestLogger.info("Processing DKG request");

      // Execute the DKG transaction
      const result = await this.executeDKGTransaction(request.data);

      // Mark as completed
      request.status = "completed";
      request.dWalletCapObjectId = result.dWalletCapObjectId;
      request.dWalletObjectId = result.dWalletObjectId;
      request.ethereumAddress = result.ethereumAddress;
      request.solanaAddress = (result as any).solanaAddress;
      request.digest = result.digest;
      request.encryptedUserSecretKeyShareId =
        result.encryptedUserSecretKeyShareId || null;

      requestLogger.info(
        {
          dWalletCapObjectId: result.dWalletCapObjectId,
          dWalletObjectId: result.dWalletObjectId,
          ethereumAddress: result.ethereumAddress,
          digest: result.digest,
          encryptedUserSecretKeyShareId: result.encryptedUserSecretKeyShareId,
        },
        "DKG request completed successfully"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error({ error: request.error }, "DKG request failed");
    }
  }

  /**
   * Process a single imported-key verification request
   */
  private async processImportedVerifyRequest(
    request: ImportedKeyVerifyRequest
  ): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      request.status = "processing";
      requestLogger.info("Processing imported-key verification request");

      const result = await this.executeImportedKeyVerificationTransaction(
        request.data
      );

      request.status = "completed";
      request.dWalletCapObjectId = result.dWalletCapObjectId;
      request.dWalletObjectId = result.dWalletObjectId;
      request.ethereumAddress = result.ethereumAddress;
      request.solanaAddress = (result as any).solanaAddress;
      request.digest = result.digest;
      request.encryptedUserSecretKeyShareId =
        result.encryptedUserSecretKeyShareId || null;

      requestLogger.info(
        {
          dWalletCapObjectId: result.dWalletCapObjectId,
          dWalletObjectId: result.dWalletObjectId,
          ethereumAddress: result.ethereumAddress,
          digest: result.digest,
          encryptedUserSecretKeyShareId: result.encryptedUserSecretKeyShareId,
        },
        "Imported-key verification completed successfully"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error(
        { error: request.error },
        "Imported-key verification failed"
      );
    }
  }

  /**
   * Process a single presign request
   */
  private async processPresignRequest(request: PresignRequest): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      request.status = "processing";
      requestLogger.info("Processing presign request");

      const result = await this.executePresignTransaction({
        dWalletId: request.dWalletId,
        curve: typeof request.curve === "number" ? request.curve : undefined,
        signatureAlgorithm:
          typeof request.signatureAlgorithm === "number"
            ? request.signatureAlgorithm
            : undefined,
        encryptedUserSecretKeyShareId: request.encryptedUserSecretKeyShareId,
        userOutputSignature: request.userOutputSignature,
      });

      request.presignId = result.presignId;

      // IMPORTANT: The presign transaction only requests presign; the network still needs time to complete it.
      // Only mark the request completed once the presign reaches Completed and we have the presign bytes.
      const presignBytes = await this.waitForPresignCompleted(result.presignId, requestLogger);
      request.presignBytes = Array.from(presignBytes);
      request.status = "completed";

      requestLogger.info(
        { presignId: result.presignId, presignBytesLen: presignBytes.length },
        "Presign request completed"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error({ error: request.error }, "Presign request failed");
    }
  }

  /**
   * Process a single sign request (non-custodial)
   * Uses the userSignMessage computed client-side
   */
  private async processSignRequest(request: SignRequest): Promise<void> {
    const requestLogger = logger.child({ requestId: request.id });

    try {
      request.status = "processing";
      requestLogger.info("Processing sign request");

      const result = await this.executeSignTransaction(request.data);

      request.signatureHex = result.signatureHex;
      request.signId = result.signId;
      request.digest = result.digest;
      request.ethTxHash = result.ethTxHash;
      request.ethBlockNumber = result.ethBlockNumber;
      // If the caller asked us to broadcast an ETH tx, treat broadcast failures as a failed request
      // (otherwise the UI can incorrectly show "sent" even though it wasn't accepted by the chain).
      if (request.data.ethTx && !result.ethTxHash) {
        request.status = "failed";
        request.error =
          result.ethBroadcastError ||
          "Failed to broadcast to Ethereum (no tx hash returned)";
      } else {
        request.status = "completed";
        request.error = result.ethBroadcastError || request.error;
      }

      requestLogger.info(
        {
          signId: result.signId,
          signatureHex: result.signatureHex?.slice(0, 20) + "...",
          ethTxHash: result.ethTxHash,
          status: request.status,
        },
        "Sign request completed"
      );
    } catch (error) {
      request.status = "failed";
      request.error = error instanceof Error ? error.message : String(error);
      requestLogger.error({ error: request.error }, "Sign request failed");
    }
  }

  /**
   * Execute the DKG transaction on Sui/Ika network
   * Based on https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet
   */
  private async executeDKGTransaction(data: DKGSubmitInput): Promise<{
    dWalletCapObjectId: string;
    dWalletObjectId: string;
    ethereumAddress?: string;
    solanaAddress?: string;
    digest: string;
    encryptedUserSecretKeyShareId: string | null;
  }> {
    await this.initPromise;
    let tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.dkg));

    // Use SECP256K1 for Ethereum by default
    const curve = data.curve ?? CURVE_SECP256K1;

    // Basic validation so we fail with a clear error before hitting opaque Move aborts.
    if (!data.sessionIdentifier || data.sessionIdentifier.length !== 32) {
      throw new Error(
        `Invalid sessionIdentifier: expected 32 bytes, got ${data.sessionIdentifier?.length ?? 0}`
      );
    }

    // Derive the Sui address that will own the encryption key entry on-chain.
    // On-chain, the key is indexed by `address::ed25519_address(signer_public_key)`, not by any caller-provided string.
    const derivedEncryptionKeyAddress = new Ed25519PublicKey(
      new Uint8Array(data.signerPublicKey)
    ).toSuiAddress();
    if (
      data.encryptionKeyAddress &&
      data.encryptionKeyAddress.toLowerCase() !== derivedEncryptionKeyAddress.toLowerCase()
    ) {
      logger.warn(
        {
          provided: data.encryptionKeyAddress,
          derived: derivedEncryptionKeyAddress,
        },
        "encryptionKeyAddress mismatch; using derived address from signerPublicKey"
      );
    }

    // Get the latest network encryption key (retry on transient RPC failures)
    const encryptionKey = await this.getLatestNetworkEncryptionKeyCached({
      op: "DKG",
    });

    logger.debug(
      { encryptionKeyId: encryptionKey.id, curve },
      "Got network encryption key"
    );

    // Step 1: Ensure the encryption key is registered.
    //
    // IMPORTANT:
    // `register_encryption_key` registers an encryption key for the address proved by
    // (signerPublicKey, encryptionKeySignature), NOT for the transaction sender.
    // If we check the admin sender address here, we'll think the key is missing and
    // attempt to register again, which aborts on-chain with:
    //   0x2::dynamic_field::add (EFieldAlreadyExists)
    // Previously we used devInspect on a "register encryption key" tx to detect "already registered".
    // On newer testnet RPCs, devInspect failures can surface new error variants that the SDK can't decode,
    // producing confusing messages like "Unknown value 13 for enum CommandArgumentError".
    //
    // NOTE: IkaClient.getActiveEncryptionKey() uses devInspect and can be flaky across RPC changes.
    // We do a direct dynamic-field existence check instead to avoid false negatives that cause
    // "dynamic_field::add (EFieldAlreadyExists)" aborts when re-registering.
    const { coordinatorInner } = (await (this.ikaClient as any).ensureInitialized()) as {
      coordinatorInner: any;
    };
    const encryptionKeysParentId = String(
      coordinatorInner?.encryption_keys?.id?.id ?? ""
    );
    if (!encryptionKeysParentId) {
      throw new Error("Failed to resolve coordinatorInner.encryption_keys table id");
    }

    const df = await this.client.getDynamicFieldObject({
      parentId: encryptionKeysParentId,
      name: { type: "address", value: derivedEncryptionKeyAddress },
    });
    const hasActiveEncryptionKey = !!(df as any)?.data;

    if (!hasActiveEncryptionKey) {
      coordinatorTransactions.registerEncryptionKeyTx(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        curve,
        new Uint8Array(data.encryptionKey),
        new Uint8Array(data.encryptionKeySignature),
        new Uint8Array(data.signerPublicKey),
        tx
      );
    }

    const latestNetworkEncryptionKeyId = encryptionKey.id;

    // Step 2: Request DKG - create the dWallet
    //
    // IMPORTANT (Sui PTB semantics):
    // `requestDWalletDKG` is a Move call that can return multiple values (at minimum the dWallet cap,
    // and sometimes an additional returned object/value depending on on-chain package version / options).
    // If we only use the first return value, Sui will reject the transaction with UnusedValueWithoutDrop.
    const ikaPaymentCoinId = await this.selectIkaPaymentCoinOrThrow({
      owner: adminAddress,
      context: "DKG",
    });
    const dkgResult = coordinatorTransactions.requestDWalletDKG(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      latestNetworkEncryptionKeyId,
      curve,
      new Uint8Array(data.userDkgMessage),
      new Uint8Array(data.encryptedUserShareAndProof),
      data.encryptionKeyAddress,
      new Uint8Array(data.userPublicOutput),
      new Uint8Array(data.signerPublicKey),
      coordinatorTransactions.registerSessionIdentifier(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        new Uint8Array(data.sessionIdentifier),
        tx
      ),
      null,
      tx.object(ikaPaymentCoinId),
      tx.gas,
      tx
    );

    const dWalletCap = (dkgResult as any)[0];

    // Step 3: Transfer the returned dWallet capability to the admin address.
    // `requestDWalletDKG` returns a TransactionResult which may include additional *non-object* return values
    // (depending on the on-chain package). Transferring non-objects causes on-chain errors like:
    //   CommandArgumentError { kind: InvalidTransferObject }
    // We therefore only transfer the cap (index 0), and allow any additional droppable return values
    // to be ignored.
    tx.transferObjects([dWalletCap], adminAddress);

    logger.debug("Executing DKG transaction...");

    // Execute transaction
    const result = await this.executeSuiTransaction(tx);

    logger.debug({ digest: result.digest }, "Transaction executed");

    // Wait for transaction and parse events (with timeout)
    const txResult = await withTimeout(
      this.client.waitForTransaction({
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

    // Fail fast with the on-chain error (instead of "could not parse")
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

    // Fallback: extract from object changes (more reliable across SDK/event format changes).
    if ((!dWalletCapObjectId || !dWalletObjectId) && (txResult as any)?.objectChanges) {
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

      // Note: package id differs per network; match by stable suffix only.
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

    // Derive address from the dWallet's combined public output (not user's contribution)
    let ethereumAddress: string | undefined;
    let solanaAddress: string | undefined;
    const ikaCurve = curve === CURVE_ED25519 ? Curve.ED25519 : Curve.SECP256K1;
    const publicKey = await publicKeyFromCentralizedDKGOutput(
      ikaCurve,
      new Uint8Array(data.userPublicOutput)
    );
    if (curve === CURVE_ED25519) {
      solanaAddress = deriveSolanaAddress(publicKey);
    } else {
      ethereumAddress = deriveEthereumAddress(publicKey);
    }

    return {
      dWalletCapObjectId,
      dWalletObjectId,
      ethereumAddress,
      solanaAddress,
      digest: result.digest,
      encryptedUserSecretKeyShareId,
    };
  }

  /**
   * Execute imported-key verification transaction on Sui/Ika network.
   * This creates an ImportedKey dWallet without the backend ever seeing the private key.
   *
   * The client prepares `importInput` offline via `prepareImportedKeyDWalletVerification(...)`.
   */
  private async executeImportedKeyVerificationTransaction(
    data: ImportedKeyVerifySubmitInput
  ): Promise<{
    dWalletCapObjectId: string;
    dWalletObjectId: string;
    ethereumAddress?: string;
    solanaAddress?: string;
    digest: string;
    encryptedUserSecretKeyShareId: string | null;
  }> {
    await this.initPromise;
    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(
      tx,
      adminAddress,
      BigInt(config.sui.gasBudgetsMist.dkg)
    );

    // Basic validation so we fail with a clear error before hitting opaque Move aborts.
    if (!data.sessionIdentifier || data.sessionIdentifier.length !== 32) {
      throw new Error(
        `Invalid sessionIdentifier: expected 32 bytes, got ${data.sessionIdentifier?.length ?? 0}`
      );
    }

    // Derive the Sui address that will own the encryption key entry on-chain.
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

    // Ensure encryption key is registered (same dynamic-field check as DKG path).
    const encryptionKey = await this.getLatestNetworkEncryptionKeyCached({
      op: "ImportedKeyVerify",
    });
    const { coordinatorInner } = (await (this.ikaClient as any).ensureInitialized()) as {
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
    const df = await this.client.getDynamicFieldObject({
      parentId: encryptionKeysParentId,
      name: { type: "address", value: derivedEncryptionKeyAddress },
    });
    const hasActiveEncryptionKey = !!(df as any)?.data;
    if (!hasActiveEncryptionKey) {
      coordinatorTransactions.registerEncryptionKeyTx(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        CURVE_SECP256K1,
        new Uint8Array(data.encryptionKey),
        new Uint8Array(data.encryptionKeySignature),
        new Uint8Array(data.signerPublicKey),
        tx
      );
    }

    // Payment coin for protocol fees
    const ikaPaymentCoinId = await this.selectIkaPaymentCoinOrThrow({
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

    // NOTE:
    // The SDK's IkaTransaction.requestImportedKeyDWalletVerification currently requires
    // `userShareEncryptionKeys` to be set on the IkaTransaction instance (even though on-chain
    // the request only needs the *address* and public material which the client provides).
    // The backend never has the user's share keys, so we call the lower-level tx builder directly.
    // Cast through `any` to avoid type duplication between SDK-bundled @mysten/sui and app @mysten/sui.
    const coordinatorObjectRef = (tx as any).sharedObjectRef({
      objectId: this.ikaConfig.objects.ikaDWalletCoordinator.objectID,
      initialSharedVersion:
        this.ikaConfig.objects.ikaDWalletCoordinator.initialSharedVersion,
      mutable: true,
    });
    const sessionIdentifierObj = (coordinatorTransactions as any).registerSessionIdentifier(
      this.ikaConfig as any,
      coordinatorObjectRef,
      new Uint8Array(data.sessionIdentifier),
      tx as any
    );
    const importedCap = (coordinatorTransactions as any).requestImportedKeyDwalletVerification(
      this.ikaConfig as any,
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
      // For simplicity, use tx.gas as SUI reimbursement coin.
      (tx as any).gas,
      tx as any
    );

    // Transfer returned cap to admin
    tx.transferObjects([importedCap], adminAddress);

    const result = await this.executeSuiTransaction(tx);
    const txResult = await withTimeout(
      this.client.waitForTransaction({
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

    // Extract created objects.
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
        findCreatedBySuffix("::coordinator_inner::EncryptedUserSecretKeyShare") ??
        null;
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
      throw new Error("Failed to parse imported dWallet objects from transaction");
    }

    // Best-effort derive chain address from the public output contribution (may vary by protocol version).
    let ethereumAddress: string | undefined;
    let solanaAddress: string | undefined;
    try {
      const ikaCurve = data.curve === CURVE_ED25519 ? Curve.ED25519 : Curve.SECP256K1;
      const publicKey = await publicKeyFromCentralizedDKGOutput(
        ikaCurve,
        new Uint8Array(data.importInput.userPublicOutput)
      );
      if (data.curve === CURVE_ED25519) {
        solanaAddress = deriveSolanaAddress(publicKey);
      } else {
        ethereumAddress = deriveEthereumAddress(publicKey);
      }
    } catch {
      // ignore; UI can still proceed with dWallet id.
    }

    return {
      dWalletCapObjectId,
      dWalletObjectId,
      ethereumAddress,
      solanaAddress,
      digest: result.digest,
      encryptedUserSecretKeyShareId,
    };
  }

  /**
   * Execute presign transaction
   * Presigns are needed before signing messages
   */
  private async executePresignTransaction(params: {
    dWalletId: string;
    curve?: number;
    signatureAlgorithm?: number;
    encryptedUserSecretKeyShareId: string;
    userOutputSignature: number[];
  }): Promise<{
    presignId: string;
  }> {
    await this.initPromise;
    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    // We'll set gas budget after we compute required reimbursements.

    // IMPORTANT (Sui semantics):
    // The Move code will `split` from `payment_sui` to fund gas reimbursements for the Ika protocol.
    // If we pass `tx.gas` as `payment_sui`, we can accidentally drain the gas coin below the gas budget
    // even when the account has "enough SUI" overall. Prefer a dedicated SUI coin object for `payment_sui`.
    //
    // We'll also try to pin the gas payment coin explicitly to avoid unpredictable coin selection.
    const suiCoins = await this.client.getCoins({
      owner: adminAddress,
      coinType: "0x2::sui::SUI",
    });
    const sortedSuiCoins = [...(suiCoins.data ?? [])].sort(
      (a, b) => Number(BigInt(b.balance) - BigInt(a.balance))
    );

    // Resolve curve + signature algorithm for presign (pricing and presign request are curve/alg-specific).
    const dWallet = await this.ikaClient.getDWallet(params.dWalletId);
    const curveNumber =
      typeof params.curve === "number" ? Number(params.curve) : Number((dWallet as any)?.curve);
    if (!Number.isFinite(curveNumber)) {
      throw new Error("Failed to resolve dWallet curve for presign");
    }
    const signatureAlgorithmNumber =
      typeof params.signatureAlgorithm === "number"
        ? Number(params.signatureAlgorithm)
        : curveNumber === CURVE_ED25519
          ? SIGALG_ED25519
          : SIGALG_ECDSA_SECP256K1;

    // Fetch on-chain pricing for presign so we can select payment coins correctly.
    const presignPricing = await this.getPresignPricing({
      curve: curveNumber,
      signatureAlgorithm: signatureAlgorithmNumber,
    });
    const requiredIka = presignPricing?.feeIka ?? 0n;
    const requiredSui = presignPricing
      ? presignPricing.gasFeeReimbursementSui +
        presignPricing.gasFeeReimbursementSuiForSystemCalls
      : 0n;

    // Keep gas budget modest; if we only have a single SUI coin object, we may use the gas coin
    // itself as `payment_sui`, so we must leave headroom for gas.
    const gasBudget = 50_000_000n;
    tx.setGasBudget(gasBudget);

    // Choose an IKA coin object with enough balance.
    const ikaPaymentCoinId = await this.selectIkaPaymentCoinOrThrow({
      owner: adminAddress,
      requiredIka,
      context: "presign",
    });
    const ikaPaymentCoinArg = tx.object(ikaPaymentCoinId);

    // Choose SUI payment coin:
    // - If we have 2+ SUI coins, use the non-gas coin with enough balance for reimbursement.
    // - Otherwise, use tx.gas directly as `payment_sui` (the Move call will split out what it needs),
    //   and we keep gasBudget low to avoid starving the gas coin.
    const gasCoin = sortedSuiCoins[0];
    const secondCoin = sortedSuiCoins[1];

    const pickSecondIfSufficient =
      requiredSui > 0n && secondCoin && BigInt(secondCoin.balance) >= requiredSui
        ? secondCoin
        : null;

    const paymentSuiCoinArg = pickSecondIfSufficient
      ? tx.object(pickSecondIfSufficient.coinObjectId)
      : tx.gas;

    if (gasCoin && pickSecondIfSufficient) {
      // Pin gas coin only when payment uses a different object.
      tx.setGasPayment([
        {
          objectId: gasCoin.coinObjectId,
          version: gasCoin.version,
          digest: gasCoin.digest,
        },
      ]);
    }

    // If we're forced to use a single coin for both gas + reimbursement, preflight the math.
    if (!pickSecondIfSufficient && requiredSui > 0n) {
      const totalSui = gasCoin ? BigInt(gasCoin.balance) : 0n;
      // This is a conservative check; actual gas used will be <= gasBudget, and reimbursement splits happen in Move.
      if (totalSui < requiredSui + gasBudget) {
        throw new Error(
          `Insufficient SUI for presign with a single SUI coin object: need >= (required_reimbursement=${requiredSui} + gas_budget=${gasBudget}) raw, ` +
            `have ${totalSui}. Top up SUI or consolidate into 2 SUI coin objects.`
        );
      }
    }

    const random32Bytes = new Uint8Array(32);
    crypto.getRandomValues(random32Bytes);

    // dWallet state can lag behind the DKG transaction; wait until it is ready for activation/presign.
    const dWalletState = await this.waitForDWalletReadyForPresign(params.dWalletId);
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
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
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

    // Decide whether to request a dWallet-specific presign or a global presign.
    //
    // On newer dWallet versions, dWallet-specific presign is disallowed on-chain and aborts with:
    //   EOnlyGlobalPresignAllowed (abort code 31) in coordinator_inner::request_presign
    //
    // We mirror the SDK logic: non-imported dWallets can only do "normal presign" if version==1,
    // otherwise we must use global presign.
    const isImported = Boolean((dWallet as any)?.is_imported_key_dwallet);
    const publicOutputBytes: number[] | undefined =
      (dWallet as any)?.state?.Active?.public_output ??
      (dWallet as any)?.state?.AwaitingKeyHolderSignature?.public_output;
    const dWalletVersion =
      publicOutputBytes && publicOutputBytes.length > 0
        ? Number(publicOutputBytes[0] ?? 0) + 1
        : null;

    const useGlobalPresign =
      // For non-ECDSA algorithms, prefer global presign (more widely supported).
      signatureAlgorithmNumber !== SIGALG_ECDSA_SECP256K1 ||
      // Imported-key dWallets are allowed to use normal presign for ECDSA.
      (!isImported && dWalletVersion !== 1) ||
      // If we can't determine the version, prefer global presign (more widely allowed).
      dWalletVersion == null;

    // Build the Move calls directly (avoid SDK-side "public output not set" assertions).
    const sessionIdentifier = coordinatorTransactions.registerSessionIdentifier(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      random32Bytes,
      tx
    );
    const presign = useGlobalPresign
      ? coordinatorTransactions.requestGlobalPresign(
          this.ikaConfig,
          tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
          // Global presign is tied to the network encryption key, not to a specific dWallet.
          String((dWallet as any)?.dwallet_network_encryption_key_id),
          // Curve is stored on the dWallet as a u32.
          curveNumber,
          signatureAlgorithmNumber,
          sessionIdentifier,
          ikaPaymentCoinArg,
          paymentSuiCoinArg,
          tx
        )
      : coordinatorTransactions.requestPresign(
          this.ikaConfig,
          tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
          params.dWalletId,
          signatureAlgorithmNumber,
          sessionIdentifier,
          ikaPaymentCoinArg,
          paymentSuiCoinArg,
          tx
        );

    // Transfer presign to admin
    tx.transferObjects([presign], adminAddress);

    // If `paymentSuiCoinArg` is `tx.gas`, it is already consumed as gas payment.
    // If it's a separate owned coin object, it's also an input and will remain owned by the sender after the tx.

    const result = await this.executeSuiTransaction(tx);

    // Parse presign ID from events (with timeout)
    const txResult = await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true, showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Presign transaction confirmation"
    );

    const status = txResult.effects?.status?.status;
    if (status && status !== "success") {
      const err = String((txResult.effects?.status as any)?.error ?? "unknown error");

      // Provide a more actionable error for common MoveAbort cases.
      let balancesSummary = "";
      try {
        const balances = await this.client.getAllBalances({ owner: adminAddress });
        const byType = new Map(balances.map((b) => [b.coinType, b.totalBalance]));
        const suiBal = byType.get("0x2::sui::SUI");
        // IKA coin type is stable on Ika networks; include if present.
        const ikaTypePrefix = "::ika::IKA";
        const ikaEntry = balances.find((b) => b.coinType.endsWith(ikaTypePrefix));
        const ikaBal = ikaEntry?.totalBalance;
        balancesSummary =
          ` Admin balances (raw):` +
          (suiBal ? ` SUI=${suiBal}` : ` SUI=(unknown)`) +
          (ikaBal ? ` IKA=${ikaBal}` : ` IKA=(unknown)`);
      } catch {
        // ignore balance fetch errors; we still throw the underlying MoveAbort string
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
      // Depending on SDK/network, the presign request may appear as a DWalletSessionEvent wrapper.
      // We attempt to decode every event as a session event and pick the one that matches.
      try {
        const parsedData = SessionsManagerModule.DWalletSessionEvent(
          CoordinatorInnerModule.PresignRequestEvent
        ).fromBase64(event.bcs);
        if (parsedData?.event_data?.presign_id) {
          presignId = parsedData.event_data.presign_id;
          break;
        }
      } catch (err) {
        // ignore and continue; we log a summary if nothing matches
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

  private async waitForPresignCompleted(
    presignId: string,
    requestLogger: typeof logger
  ): Promise<Uint8Array> {
    const start = Date.now();
    let lastErr: string | null = null;

    // Helper for decoding unknown "bytes" shapes (SDK JSON changes).
    const toUint8Array = (v: unknown, label: string): Uint8Array => {
      if (v instanceof Uint8Array) return v;
      if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
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
        const presign = await this.ikaClient.getPresignInParticularState(presignId, "Completed");
        const presignOut = (presign as any)?.state?.Completed?.presign;
        const bytes = toUint8Array(presignOut, "presign output");
        if (bytes.length === 0) {
          throw new Error("Presign output is empty");
        }
        return bytes;
      } catch (err) {
        lastErr = err instanceof Error ? err.message : String(err);
        requestLogger.warn({ presignId, err: lastErr }, "Presign not completed yet; retrying");
        await new Promise((r) => setTimeout(r, 2000));
      }
    }

    throw new Error(
      `Timeout waiting for presign ${presignId} to reach state Completed. Last error: ${lastErr ?? "(none)"}`
    );
  }

  private async waitForDWalletReadyForPresign(dWalletId: string): Promise<{
    kind: "Active" | "AwaitingKeyHolderSignature" | "Unknown" | string;
  }> {
    const start = Date.now();
    while (Date.now() - start < TIMEOUTS.PRESIGN_WAIT) {
      const dWallet = await this.ikaClient.getDWallet(dWalletId);
      const kind = this.getDWalletStateKind(dWallet);
      if (kind === "Active" || kind === "AwaitingKeyHolderSignature") return { kind };
      await new Promise((r) => setTimeout(r, 1000));
    }
    return { kind: "Unknown" };
  }

  private getDWalletStateKind(dWallet: unknown): string {
    const state = (dWallet as any)?.state;
    if (!state) return "Unknown";
    if (state.$kind) return String(state.$kind);
    if (state.Active) return "Active";
    if (state.AwaitingKeyHolderSignature) return "AwaitingKeyHolderSignature";
    // fall back to first key present
    const keys = Object.keys(state);
    return keys.length ? keys[0] : "Unknown";
  }

  private async detectIkaCoinType(): Promise<string> {
    if (this.ikaCoinTypeCache) return this.ikaCoinTypeCache;
    const balances = await this.client.getAllBalances({
      owner: this.adminKeypair.toSuiAddress(),
    });
    const ikaEntry = balances.find((b) => b.coinType.endsWith("::ika::IKA"));
    if (!ikaEntry?.coinType) {
      throw new Error(
        "Could not detect IKA coin type on this network (no coinType ending with ::ika::IKA in balances)."
      );
    }
    this.ikaCoinTypeCache = ikaEntry.coinType;
    return ikaEntry.coinType;
  }

  private async selectIkaPaymentCoinOrThrow(args: {
    owner: string;
    requiredIka?: bigint;
    context: string;
  }): Promise<string> {
    const coinType = await this.detectIkaCoinType();
    const ikaCoins = await this.client.getCoins({
      owner: args.owner,
      coinType,
    });
    const sorted = [...(ikaCoins.data ?? [])].sort(
      (a, b) => Number(BigInt(b.balance) - BigInt(a.balance))
    );
    const best = sorted[0];
    if (!best) {
      throw new Error(
        `No IKA coins found for ${args.context} (admin=${args.owner}, coinType=${coinType}).`
      );
    }
    const required = args.requiredIka ?? 0n;
    if (required > 0n && BigInt(best.balance) < required) {
      throw new Error(
        `Insufficient IKA for ${args.context}: need >= ${required} (raw), have ${best.balance} on best IKA coin (${best.coinObjectId}).`
      );
    }
    return best.coinObjectId;
  }

  private async getPresignPricing(args: {
    curve: number;
    signatureAlgorithm: number;
  }): Promise<{
    feeIka: bigint;
    gasFeeReimbursementSui: bigint;
    gasFeeReimbursementSuiForSystemCalls: bigint;
  } | null> {
    // coordinator::current_pricing() returns `PricingInfo`.
    // We devInspect to avoid any state change and decode the VecMap.
    const tx = new Transaction();
    coordinatorTransactions.currentPricing(
      this.ikaConfig,
      tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
      tx
    );
    let entries: Array<any> | null = null;
    try {
      const res = await this.client.devInspectTransactionBlock({
        sender: this.adminKeypair.toSuiAddress(),
        transactionBlock: tx,
      });
      const bytes = res.results?.at(0)?.returnValues?.at(0)?.at(0);
      if (!bytes) {
        // DevInspect JSON shapes can drift; treat as best-effort.
        logger.warn(
          { network: config.sui.network },
          "Could not read return value from coordinator::current_pricing via devInspect; skipping pricing preflight"
        );
        return null;
      }
      const raw =
        Array.isArray(bytes) ? Uint8Array.from(bytes) : Buffer.from(String(bytes), "base64");
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
      // IMPORTANT: devInspect can fail or become undecodable on fast-moving testnets.
      // Pricing preflight is only for better error messages/coin selection; do not hard-fail presign.
      logger.warn({ err, network: config.sui.network }, "Presign pricing devInspect failed; skipping pricing preflight");
      return null;
    }

    // Protocol flag for presign => 5 (PRESIGN_PROTOCOL_FLAG in coordinator_inner.move)
    const TARGET_CURVE = Number(args.curve);
    const TARGET_SIGALG = Number(args.signatureAlgorithm);
    const TARGET_PROTOCOL = 5;

    const decodeOptU32 = (v: unknown): number | null => {
      if (v == null) return null;
      if (typeof v === "number") return v;
      if (typeof v === "string" && v.length) return Number(v);
      if (typeof v === "object" && v) {
        // Some decoders return { Some: number } for option types.
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

    // Prefer the exact signature algorithm if present; otherwise fall back to "any presign pricing for this curve".
    const match =
      candidates.find((e) => decodeOptU32(e?.key?.signature_algorithm) === TARGET_SIGALG) ??
      candidates[0] ??
      null;

    if (!match?.value) {
      // If there is no presign pricing entry, we can't preflight. Return null and let the tx attempt run.
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

  /**
   * Execute sign transaction (non-custodial)
   * Uses userSignMessage computed by the client via createUserSignMessageWithPublicOutput
   * Based on https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet#signing-a-message
   *
   * After signing, optionally broadcasts to Base Sepolia testnet
   */
  private async executeSignTransaction(data: SignRequestInput): Promise<{
    signatureHex: string;
    signId: string;
    digest: string;
    ethTxHash?: string;
    ethBlockNumber?: number;
    ethBroadcastError?: string;
  }> {
    await this.initPromise;
    // --- Kairo hard gate: require a valid Sui PolicyReceipt before signing ---
    if (!data.ethTx) {
      // Currently we only support gating EVM tx signing requests.
      throw new Error("Policy gate requires ethTx to be provided");
    }

    const expectedPolicyId = String(
      data.policyObjectId ?? config.kairo.policyId
    ).trim();
    const expectedPolicyVersion = String(
      data.policyVersion ?? config.kairo.policyVersion
    ).trim();
    if (!expectedPolicyId.startsWith("0x")) {
      throw new Error(
        "Missing policyObjectId. Configure KAIRO_POLICY_ID in the backend or pass policyObjectId in the sign request."
      );
    }
    if (!expectedPolicyVersion) {
      throw new Error(
        "Missing policyVersion. Configure KAIRO_POLICY_VERSION in the backend or pass policyVersion in the sign request."
      );
    }

    await this.verifyPolicyReceiptOrThrow({
      receiptId: data.policyReceiptId,
      expectedPolicyId,
      expectedPolicyVersion,
      policyBindingObjectId: data.policyBindingObjectId,
      evmChainId: data.ethTx.chainId,
      toEvm: data.ethTx.to,
      // intent_hash = keccak256(unsignedTxBytes)
      intentHashHex: keccak256(toBytes((`0x${data.messageHex.replace(/^0x/, "")}`) as Hex)),
    });

    // Verify presign exists (with timeout to prevent indefinite wait)
    const presign = await withTimeout(
      this.ikaClient.getPresignInParticularState(data.presignId, "Completed"),
      TIMEOUTS.PRESIGN_WAIT,
      "Presign state check"
    );

    if (!presign) {
      throw new Error(`Presign ${data.presignId} not found or not completed`);
    }

    logger.info(
      {
        messageHex: data.messageHex.slice(0, 20) + "...",
        policyReceiptId: data.policyReceiptId,
        userSignMessageLength: data.userSignMessage.length,
        userOutputSignatureLength: data.userOutputSignature.length,
        encryptedUserSecretKeyShareId: data.encryptedUserSecretKeyShareId,
        presignId: data.presignId,
        dWalletId: data.dWalletId,
        dWalletCapId: data.dWalletCapId,
        ethTx: data.ethTx,
      },
      "Processing sign request"
    );

    const tx = new Transaction();
    const ikaTx = new IkaTransaction({
      ikaClient: this.ikaClient,
      transaction: tx,
    });
    tx.setSender(this.adminKeypair.toSuiAddress());
    await this.setAdminGas(
      tx,
      this.adminKeypair.toSuiAddress(),
      BigInt(config.sui.gasBudgetsMist.sign)
    );

    // ====== VAULT AUTHORIZATION (MANDATORY FOR EVM) ======
    // All signing must go through the PolicyVault's policy_gated_authorize_sign_v4
    const vaultObjectId = config.kairo.policyVaultObjectId;
    const policyPackageId = config.kairo.policyMintPackageId;
    
    if (vaultObjectId?.startsWith("0x") && policyPackageId?.startsWith("0x") && data.policyBindingObjectId?.startsWith("0x")) {
      // Use the SAME intent hash that was stored in the receipt (keccak256 of message bytes)
      // This must match what was used when minting the PolicyReceiptV4
      const intentHashHex = keccak256(toBytes((`0x${data.messageHex.replace(/^0x/, "")}`) as Hex));
      const intentDigest = new Uint8Array(Buffer.from(intentHashHex.replace(/^0x/, ""), "hex"));
      
      // Use the exact chain_id bytes from the receipt when available.
      // This avoids false mismatches across legacy/new encoding variants.
      const receiptChainIdBytes = await this.getReceiptChainIdBytes(data.policyReceiptId);
      const chainIdBytes = receiptChainIdBytes ?? chainIdToBytes(NAMESPACE_EVM, data.ethTx.chainId);
      // EVM: destination is 20-byte address
      const destinationBytes = new Uint8Array(Buffer.from(data.ethTx.to.replace(/^0x/, ""), "hex"));
      const dwalletIdBytes = objectIdToBytes(data.dWalletId);
      
      // Add vault authorization to transaction
      tx.moveCall({
        target: `${policyPackageId}::dwallet_policy_vault::policy_gated_authorize_sign_v4`,
        arguments: [
          tx.object(vaultObjectId), // &mut PolicyVault
          tx.object(data.policyReceiptId), // PolicyReceiptV4 (consumed)
          tx.object(data.policyBindingObjectId), // &PolicyBinding
          tx.object("0x6"), // Clock
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(dwalletIdBytes))), // dwallet_id: vector<u8>
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(intentDigest))), // intent_digest: vector<u8>
          tx.pure.u8(NAMESPACE_EVM), // namespace: u8
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(chainIdBytes))), // chain_id: vector<u8>
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(destinationBytes))), // destination: vector<u8>
          tx.pure.u64(0), // receipt_ttl_ms: u64 (0 = no expiry check)
        ],
      });
      
      logger.info(
        {
          vaultObjectId,
          receiptObjectId: data.policyReceiptId,
          bindingObjectId: data.policyBindingObjectId,
          intentDigestHex: Buffer.from(intentDigest).toString("hex").slice(0, 16) + "...",
        },
        "Added vault authorization to sign transaction"
      );
    } else {
      logger.warn(
        { vaultObjectId, policyPackageId, bindingObjectId: data.policyBindingObjectId },
        "Skipping vault authorization - missing configuration (vault, package, or binding)"
      );
    }

    const random32Bytes = new Uint8Array(32);
    crypto.getRandomValues(random32Bytes);

    // Only accept the encrypted user share if the dWallet is still awaiting key-holder signature.
    // If the dWallet is already Active, re-accepting can fail or be redundant.
    const dWallet = await this.ikaClient.getDWallet(data.dWalletId);
    const stateKind = this.getDWalletStateKind(dWallet);
    if (stateKind === "AwaitingKeyHolderSignature") {
      if (!data.encryptedUserSecretKeyShareId || data.userOutputSignature.length === 0) {
        throw new Error(
          "dWallet requires activation (AwaitingKeyHolderSignature) but activation inputs are missing (encryptedUserSecretKeyShareId/userOutputSignature)."
        );
      }
      coordinatorTransactions.acceptEncryptedUserShare(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
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

    // Imported-key dWallets must use approveImportedKeyMessage + requestImportedKeySign.
    // See: https://docs.ika.xyz/sdk/ika-transaction/imported-key-dwallet
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

    const ikaPaymentCoinId = await this.selectIkaPaymentCoinOrThrow({
      owner: this.adminKeypair.toSuiAddress(),
      context: "sign request",
    });

    if (isImported) {
      coordinatorTransactions.requestImportedKeySign(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
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
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        verifiedPresignCap,
        verifiedMessageApproval,
        new Uint8Array(data.userSignMessage),
        ikaTx.createSessionIdentifier(),
        tx.object(ikaPaymentCoinId),
        tx.gas,
        tx
      );
    }

    const result = await this.executeSuiTransaction(tx);

    // Wait for sign transaction confirmation (with timeout)
    const txResult = await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true, showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Sign transaction confirmation"
    );

    // Check if transaction was successful
    const txStatus = (txResult as any).effects?.status?.status;
    if (txStatus !== "success") {
      const txError = (txResult as any).effects?.status?.error;
      logger.error(
        { digest: result.digest, status: txStatus, error: txError },
        "Sign transaction failed on-chain"
      );
      throw new Error(`Sign transaction failed on-chain: ${txError || txStatus || "unknown error"}`);
    }

    // Log all events for debugging
    logger.info(
      { 
        digest: result.digest, 
        eventCount: txResult.events?.length ?? 0,
        eventTypes: txResult.events?.map(e => e.type) ?? [],
      },
      "Sign transaction events"
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
      // Log more details for debugging
      logger.error(
        { 
          digest: result.digest, 
          events: txResult.events?.map(e => ({ type: e.type, parsedJson: e.parsedJson })) ?? [],
        },
        "No SignRequestEvent found in transaction"
      );
      throw new Error("Failed to get sign ID from transaction - no SignRequestEvent emitted. Check if dWallet is registered in vault.");
    }

    // Wait for network to complete the signature (with timeout to prevent indefinite wait)
    const signResult = await withTimeout(
      this.ikaClient.getSignInParticularState(
        signId,
        Curve.SECP256K1,
        SignatureAlgorithm.ECDSASecp256k1,
        "Completed"
      ),
      TIMEOUTS.SIGN_WAIT,
      "Signature from Ika network"
    );

    const signatureBytes = signResult.state.Completed.signature;
    const signatureHex = Buffer.from(signatureBytes).toString("hex");

    logger.info(
      { signId, signatureLength: signatureBytes.length },
      "Got signature from Ika network"
    );

    // If Ethereum transaction details provided, broadcast to Base Sepolia
    let ethTxHash: string | undefined;
    let ethBlockNumber: number | undefined;
    let ethBroadcastError: string | undefined;

    if (data.ethTx) {
      try {
        const broadcastResult = await this.broadcastToEthereum(
          data.ethTx,
          new Uint8Array(signatureBytes)
        );
        ethTxHash = broadcastResult.txHash;
        ethBlockNumber = broadcastResult.blockNumber;

        logger.info(
          { ethTxHash, ethBlockNumber },
          "Ethereum transaction broadcast successful"
        );

        // Append a second custody event after broadcast to link actual EVM tx hash.
        // Respects custody enforcement mode.
        const effectiveCustodyMode = resolveEffectiveCustodyMode(
          data.custodyMode,
          config.kairo.custodyMode
        );

        if (effectiveCustodyMode !== CustodyMode.DISABLED) {
          try {
            const custodyChainObjectId = String(data.custodyChainObjectId ?? "").trim();
            const custodyPkgCandidate = String(data.custodyPackageId ?? config.kairo.custodyPackageId ?? "").trim();
            if (custodyChainObjectId.startsWith("0x")) {
              const custodyPkg = custodyPkgCandidate.startsWith("0x")
                ? custodyPkgCandidate
                : // default to policy mint package on testnet
                  String(config.kairo.policyMintPackageId || "");

              await this.appendCustodyEventWithReceipt({
                custodyPackageId: custodyPkg,
                custodyChainObjectId,
                receiptObjectId: data.policyReceiptId,
                policyObjectId: expectedPolicyId,
                intentHashHex: keccak256(toBytes((`0x${data.messageHex.replace(/^0x/, "")}`) as Hex)),
                toEvm: data.ethTx.to,
                mintDigest: result.digest,
                kind: 2, // broadcasted
                srcNamespace: 2, // evm
                srcChainId: BigInt(data.ethTx.chainId),
                srcTxHashHex: ethTxHash as any,
                payloadExtra: { ethTxHash, ethBlockNumber },
              });
            }
          } catch (err) {
            if (effectiveCustodyMode === CustodyMode.REQUIRED) {
              // Post-broadcast custody failure is critical - EVM tx already happened but custody gap exists.
              // Log error but don't throw (signature already returned, can't undo the broadcast).
              logger.error(
                { err, ethTxHash, custodyMode: effectiveCustodyMode },
                "CRITICAL: Post-broadcast custody append failed (REQUIRED mode) - custody gap in audit trail"
              );
            } else {
              logger.warn(
                { err, ethTxHash, custodyMode: effectiveCustodyMode },
                "Post-broadcast custody append failed (BEST_EFFORT mode)"
              );
            }
          }
        }
      } catch (err) {
        ethBroadcastError = err instanceof Error ? err.message : String(err);
        logger.error({ err }, "Failed to broadcast to Ethereum");
      }
    }

    return {
      signatureHex,
      signId,
      digest: result.digest,
      ethTxHash,
      ethBlockNumber,
      ethBroadcastError,
    };
  }

  /**
   * Get a completed presign from the Ika network.
   * @param presignId - The presign object ID
   * @returns The presign bytes when completed
   */
  async getCompletedPresign(presignId: string): Promise<{
    presignBytes: Uint8Array;
    presignId: string;
  }> {
    const presign = await withTimeout(
      this.ikaClient.getPresignInParticularState(presignId, "Completed"),
      TIMEOUTS.PRESIGN_WAIT,
      "Presign state check"
    );

    const presignOut = (presign as any)?.state?.Completed?.presign;
    if (!presignOut) {
      throw new Error(`Presign ${presignId} has no presign output`);
    }

    // Convert to Uint8Array
    let presignBytes: Uint8Array;
    if (presignOut instanceof Uint8Array) {
      presignBytes = presignOut;
    } else if (Array.isArray(presignOut)) {
      presignBytes = new Uint8Array(presignOut);
    } else if (typeof presignOut === "string") {
      presignBytes = presignOut.startsWith("0x")
        ? new Uint8Array(Buffer.from(presignOut.slice(2), "hex"))
        : new Uint8Array(Buffer.from(presignOut, "base64"));
    } else {
      throw new Error("Invalid presign output format");
    }

    return { presignBytes, presignId };
  }

  /**
   * Execute Bitcoin MPC signing.
   * Supports both ECDSA (P2PKH, P2WPKH) and Schnorr (P2TR) signatures.
   */
  async executeBitcoinSign(data: {
    dWalletId: string;
    dWalletCapId: string;
    presignId: string;
    /** The message/preimage to sign (sighash for ECDSA, full preimage for Taproot) */
    messageBytes: Uint8Array;
    /** User's sign message (from createUserSignMessageWithPublicOutput) */
    userSignMessage: number[];
    /** User output signature for activation (if dWallet is still in AwaitingKeyHolderSignature state) */
    userOutputSignature?: number[];
    /** Encrypted user secret key share ID (for dWallet activation) */
    encryptedUserSecretKeyShareId?: string;
    /** Use Taproot (Schnorr) instead of ECDSA */
    useTaproot?: boolean;
    /** Policy receipt ID for verification (optional) */
    policyReceiptId?: string;
    /** Expected policy object ID */
    policyObjectId?: string;
    /** Expected policy version */
    policyVersion?: string;
    /** Policy binding object ID */
    policyBindingObjectId?: string;
    /** Intent hash for policy verification */
    intentHashHex?: string;
    /** Bitcoin network for logging */
    network?: string;
    /** Destinations for logging */
    destinations?: string[];
  }): Promise<{
    signatureBytes: Uint8Array;
    signatureHex: string;
    signId: string;
    digest: string;
  }> {
    logger.info(
      {
        dWalletId: data.dWalletId,
        presignId: data.presignId,
        useTaproot: data.useTaproot,
        network: data.network,
        destinations: data.destinations,
      },
      "Processing Bitcoin sign request"
    );

    // Policy hard gate (BTC): require a PolicyReceiptV3 matching this intent + destination.
    // The client is expected to mint the receipt after parsing the PSBT intent hash.
    if (!data.policyReceiptId) {
      throw new Error("policyReceiptId is required for Bitcoin signing");
    }
    const expectedPolicyId = String(data.policyObjectId ?? config.kairo.policyId ?? "").trim();
    const expectedPolicyVersion = String(
      data.policyVersion ?? config.kairo.policyVersion ?? ""
    ).trim();
    if (!expectedPolicyId.startsWith("0x") || !expectedPolicyVersion) {
      throw new Error(
        "Missing policyObjectId/policyVersion. Configure KAIRO_POLICY_ID + KAIRO_POLICY_VERSION or pass overrides."
      );
    }
    const network = String(data.network ?? "").trim();
    if (!network) throw new Error("Missing network (required for BTC receipt verification)");
    const destination = String((data.destinations ?? [])[0] ?? "").trim();
    if (!destination) {
      throw new Error("Missing destination (expected at least one parsed output address)");
    }
    const intentHex = String(data.intentHashHex ?? "").trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(intentHex)) {
      throw new Error("Invalid intentHashHex (expected 32-byte hex with 0x prefix)");
    }
    await this.verifyPolicyReceiptV3OrThrow({
      receiptId: data.policyReceiptId,
      expectedPolicyId,
      expectedPolicyVersion,
      policyBindingObjectId: data.policyBindingObjectId,
      namespace: 2, // Bitcoin
      chainId: network,
      destination,
      intentHashHex: intentHex as any,
    });

    // Verify presign exists and is completed
    const presign = await withTimeout(
      this.ikaClient.getPresignInParticularState(data.presignId, "Completed"),
      TIMEOUTS.PRESIGN_WAIT,
      "Presign state check"
    );

    if (!presign) {
      throw new Error(`Presign ${data.presignId} not found or not completed`);
    }

    // Get dWallet state
    const dWallet = await this.ikaClient.getDWallet(data.dWalletId);
    const stateKind = this.getDWalletStateKind(dWallet);
    const isImported = Boolean((dWallet as any)?.is_imported_key_dwallet);

    // Build transaction
    const tx = new Transaction();
    const ikaTx = new IkaTransaction({
      ikaClient: this.ikaClient,
      transaction: tx,
    });
    tx.setSender(this.adminKeypair.toSuiAddress());
    await this.setAdminGas(
      tx,
      this.adminKeypair.toSuiAddress(),
      BigInt(config.sui.gasBudgetsMist.sign)
    );

    // ====== VAULT AUTHORIZATION (MANDATORY FOR BITCOIN) ======
    // All signing must go through the PolicyVault's policy_gated_authorize_sign_v4
    const vaultObjectId = config.kairo.policyVaultObjectId;
    const policyPackageId = config.kairo.policyMintPackageId;
    
    if (vaultObjectId?.startsWith("0x") && policyPackageId?.startsWith("0x") && data.policyBindingObjectId?.startsWith("0x")) {
      // Use the SAME intent hash that was stored in the receipt (keccak256 of message bytes)
      const intentDigest = new Uint8Array(Buffer.from(intentHex.replace(/^0x/, ""), "hex"));
      
      // Bitcoin: chain_id is the network name as UTF-8 bytes
      const btcChainIdBytes = chainIdToBytes(NAMESPACE_BITCOIN, network);
      // Bitcoin: destination is UTF-8 encoded address string
      const btcDestinationBytes = new TextEncoder().encode(destination);
      const btcDwalletIdBytes = objectIdToBytes(data.dWalletId);
      
      // Add vault authorization to transaction
      tx.moveCall({
        target: `${policyPackageId}::dwallet_policy_vault::policy_gated_authorize_sign_v4`,
        arguments: [
          tx.object(vaultObjectId), // &mut PolicyVault
          tx.object(data.policyReceiptId), // PolicyReceiptV4 (consumed)
          tx.object(data.policyBindingObjectId), // &PolicyBinding
          tx.object("0x6"), // Clock
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(btcDwalletIdBytes))), // dwallet_id: vector<u8>
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(intentDigest))), // intent_digest: vector<u8>
          tx.pure.u8(NAMESPACE_BITCOIN), // namespace: u8
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(btcChainIdBytes))), // chain_id: vector<u8>
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(btcDestinationBytes))), // destination: vector<u8>
          tx.pure.u64(0), // receipt_ttl_ms: u64 (0 = no expiry check)
        ],
      });
      
      logger.info(
        {
          vaultObjectId,
          receiptObjectId: data.policyReceiptId,
          bindingObjectId: data.policyBindingObjectId,
          network,
          destination,
          intentDigestHex: Buffer.from(intentDigest).toString("hex").slice(0, 16) + "...",
        },
        "Added vault authorization to Bitcoin sign transaction"
      );
    } else {
      // Vault authorization is MANDATORY - fail if not configured
      throw new Error(
        `Vault authorization required for Bitcoin signing but missing configuration. ` +
        `vaultObjectId=${vaultObjectId}, policyPackageId=${policyPackageId}, ` +
        `bindingObjectId=${data.policyBindingObjectId}`
      );
    }

    // Activate dWallet if needed
    if (stateKind === "AwaitingKeyHolderSignature") {
      if (!data.encryptedUserSecretKeyShareId || !data.userOutputSignature?.length) {
        throw new Error(
          "dWallet requires activation but activation inputs are missing (encryptedUserSecretKeyShareId/userOutputSignature)"
        );
      }
      coordinatorTransactions.acceptEncryptedUserShare(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        data.dWalletId,
        data.encryptedUserSecretKeyShareId,
        new Uint8Array(data.userOutputSignature),
        tx
      );
    }

    // Verify presign
    const verifiedPresignCap = ikaTx.verifyPresignCap({ presign });

    // Determine signature algorithm based on address type
    const sigAlgorithm = data.useTaproot 
      ? SignatureAlgorithm.Taproot 
      : SignatureAlgorithm.ECDSASecp256k1;
    
    // For Taproot, we use SHA256 hash scheme; for ECDSA we also use SHA256 for Bitcoin
    const hashScheme = Hash.SHA256;

    // Approve message
    const verifiedMessageApproval = isImported
      ? ikaTx.approveImportedKeyMessage({
          curve: Curve.SECP256K1,
          hashScheme,
          signatureAlgorithm: sigAlgorithm,
          dWalletCap: data.dWalletCapId,
          message: data.messageBytes,
        })
      : ikaTx.approveMessage({
          curve: Curve.SECP256K1,
          hashScheme,
          signatureAlgorithm: sigAlgorithm,
          dWalletCap: data.dWalletCapId,
          message: data.messageBytes,
        });

    // Get IKA payment coin
    const ikaPaymentCoinId = await this.selectIkaPaymentCoinOrThrow({
      owner: this.adminKeypair.toSuiAddress(),
      context: "bitcoin sign request",
    });

    // Request sign
    if (isImported) {
      coordinatorTransactions.requestImportedKeySign(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
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
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        verifiedPresignCap,
        verifiedMessageApproval,
        new Uint8Array(data.userSignMessage),
        ikaTx.createSessionIdentifier(),
        tx.object(ikaPaymentCoinId),
        tx.gas,
        tx
      );
    }

    // Execute transaction
    const result = await this.executeSuiTransaction(tx);

    // Wait for transaction confirmation
    const txResult = await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEvents: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Sign transaction confirmation"
    );

    // Extract sign ID from events
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

    // Wait for signature from Ika network
    const signResult = await withTimeout(
      this.ikaClient.getSignInParticularState(
        signId,
        Curve.SECP256K1,
        sigAlgorithm,
        "Completed"
      ),
      TIMEOUTS.SIGN_WAIT,
      "Signature from Ika network"
    );

    const signatureBytes = new Uint8Array(signResult.state.Completed.signature);
    const signatureHex = Buffer.from(signatureBytes).toString("hex");

    logger.info(
      {
        signId,
        signatureLength: signatureBytes.length,
        network: data.network,
        useTaproot: data.useTaproot,
      },
      "Got Bitcoin signature from Ika network"
    );

    return {
      signatureBytes,
      signatureHex,
      signId,
      digest: result.digest,
    };
  }

  /**
   * Execute Solana MPC signing (Ed25519).
   * Returns a 64-byte Ed25519 signature which can be attached to the transaction.
   */
  async executeSolanaSign(data: {
    dWalletId: string;
    dWalletCapId: string;
    presignId: string;
    /** Solana message bytes (canonical message serialization) */
    messageBytes: Uint8Array;
    userSignMessage: number[];
    userOutputSignature?: number[];
    encryptedUserSecretKeyShareId?: string;
    policyReceiptId: string;
    policyObjectId?: string;
    policyVersion?: string;
    policyBindingObjectId?: string;
    intentHashHex: string;
    cluster: string;
    destinations?: string[];
  }): Promise<{
    signatureBytes: Uint8Array;
    signatureHex: string;
    signId: string;
    digest: string;
  }> {
    // Policy hard gate (SOL): require a PolicyReceiptV3 matching this intent + destination.
    const expectedPolicyId = String(data.policyObjectId ?? config.kairo.policyId ?? "").trim();
    const expectedPolicyVersion = String(
      data.policyVersion ?? config.kairo.policyVersion ?? ""
    ).trim();
    if (!expectedPolicyId.startsWith("0x") || !expectedPolicyVersion) {
      throw new Error(
        "Missing policyObjectId/policyVersion. Configure KAIRO_POLICY_ID + KAIRO_POLICY_VERSION or pass overrides."
      );
    }
    if (!data.policyReceiptId?.startsWith("0x")) {
      throw new Error("policyReceiptId is required for Solana signing");
    }
    const destination = String((data.destinations ?? [])[0] ?? "").trim();
    if (!destination) throw new Error("Missing destination (expected at least one destination)");
    const intentHex = String(data.intentHashHex ?? "").trim();
    if (!/^0x[0-9a-fA-F]{64}$/.test(intentHex)) {
      throw new Error("Invalid intentHashHex (expected 32-byte hex with 0x prefix)");
    }
    await this.verifyPolicyReceiptV3OrThrow({
      receiptId: data.policyReceiptId,
      expectedPolicyId,
      expectedPolicyVersion,
      policyBindingObjectId: data.policyBindingObjectId,
      namespace: 3, // Solana
      chainId: data.cluster,
      destination,
      intentHashHex: intentHex as any,
    });

    // Verify presign exists and is completed
    await withTimeout(
      this.ikaClient.getPresignInParticularState(data.presignId, "Completed"),
      TIMEOUTS.PRESIGN_WAIT,
      "Presign state check"
    );

    // Get dWallet state
    const dWallet = await this.ikaClient.getDWallet(data.dWalletId);
    const stateKind = this.getDWalletStateKind(dWallet);
    const isImported = Boolean((dWallet as any)?.is_imported_key_dwallet);

    // Build transaction
    const tx = new Transaction();
    const ikaTx = new IkaTransaction({
      ikaClient: this.ikaClient,
      transaction: tx,
    });
    tx.setSender(this.adminKeypair.toSuiAddress());
    await this.setAdminGas(
      tx,
      this.adminKeypair.toSuiAddress(),
      BigInt(config.sui.gasBudgetsMist.sign)
    );

    // ====== VAULT AUTHORIZATION (MANDATORY FOR SOLANA) ======
    // All signing must go through the PolicyVault's policy_gated_authorize_sign_v4
    const vaultObjectId = config.kairo.policyVaultObjectId;
    const policyPackageId = config.kairo.policyMintPackageId;
    
    if (vaultObjectId?.startsWith("0x") && policyPackageId?.startsWith("0x") && data.policyBindingObjectId?.startsWith("0x")) {
      // Use the SAME intent hash that was stored in the receipt (keccak256 of message bytes)
      const solIntentDigest = new Uint8Array(Buffer.from(intentHex.replace(/^0x/, ""), "hex"));
      
      // Solana: chain_id is the cluster name as UTF-8 bytes
      const solChainIdBytes = chainIdToBytes(NAMESPACE_SOLANA, data.cluster);
      // Solana: destination is UTF-8 encoded address string
      const solDestinationBytes = new TextEncoder().encode(destination);
      const solDwalletIdBytes = objectIdToBytes(data.dWalletId);
      
      // Add vault authorization to transaction
      tx.moveCall({
        target: `${policyPackageId}::dwallet_policy_vault::policy_gated_authorize_sign_v4`,
        arguments: [
          tx.object(vaultObjectId), // &mut PolicyVault
          tx.object(data.policyReceiptId), // PolicyReceiptV4 (consumed)
          tx.object(data.policyBindingObjectId), // &PolicyBinding
          tx.object("0x6"), // Clock
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(solDwalletIdBytes))), // dwallet_id: vector<u8>
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(solIntentDigest))), // intent_digest: vector<u8>
          tx.pure.u8(NAMESPACE_SOLANA), // namespace: u8
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(solChainIdBytes))), // chain_id: vector<u8>
          tx.pure(bcs.vector(bcs.u8()).serialize(Array.from(solDestinationBytes))), // destination: vector<u8>
          tx.pure.u64(0), // receipt_ttl_ms: u64 (0 = no expiry check)
        ],
      });
      
      logger.info(
        {
          vaultObjectId,
          receiptObjectId: data.policyReceiptId,
          bindingObjectId: data.policyBindingObjectId,
          cluster: data.cluster,
          destination,
          intentDigestHex: Buffer.from(solIntentDigest).toString("hex").slice(0, 16) + "...",
        },
        "Added vault authorization to Solana sign transaction"
      );
    } else {
      // Vault authorization is MANDATORY - fail if not configured
      throw new Error(
        `Vault authorization required for Solana signing but missing configuration. ` +
        `vaultObjectId=${vaultObjectId}, policyPackageId=${policyPackageId}, ` +
        `bindingObjectId=${data.policyBindingObjectId}`
      );
    }

    // Activate dWallet if needed
    if (stateKind === "AwaitingKeyHolderSignature") {
      if (!data.encryptedUserSecretKeyShareId || !data.userOutputSignature?.length) {
        throw new Error(
          "dWallet requires activation but activation inputs are missing (encryptedUserSecretKeyShareId/userOutputSignature)"
        );
      }
      coordinatorTransactions.acceptEncryptedUserShare(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        data.dWalletId,
        data.encryptedUserSecretKeyShareId,
        new Uint8Array(data.userOutputSignature),
        tx
      );
    }

    // Verify presign
    const presign = await this.ikaClient.getPresignInParticularState(data.presignId, "Completed");
    const verifiedPresignCap = ikaTx.verifyPresignCap({ presign });

    // Solana: Ed25519
    const sigAlgorithm = SignatureAlgorithm.EdDSA;
    const hashScheme = Hash.SHA512;

    const verifiedMessageApproval = isImported
      ? ikaTx.approveImportedKeyMessage({
          curve: Curve.ED25519,
          hashScheme,
          signatureAlgorithm: sigAlgorithm,
          dWalletCap: data.dWalletCapId,
          message: data.messageBytes,
        })
      : ikaTx.approveMessage({
          curve: Curve.ED25519,
          hashScheme,
          signatureAlgorithm: sigAlgorithm,
          dWalletCap: data.dWalletCapId,
          message: data.messageBytes,
        });

    const ikaPaymentCoinId = await this.selectIkaPaymentCoinOrThrow({
      owner: this.adminKeypair.toSuiAddress(),
      context: "solana sign request",
    });

    if (isImported) {
      coordinatorTransactions.requestImportedKeySign(
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
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
        this.ikaConfig,
        tx.object(this.ikaConfig.objects.ikaDWalletCoordinator.objectID),
        verifiedPresignCap,
        verifiedMessageApproval,
        new Uint8Array(data.userSignMessage),
        ikaTx.createSessionIdentifier(),
        tx.object(ikaPaymentCoinId),
        tx.gas,
        tx
      );
    }

    const result = await this.executeSuiTransaction(tx);

    const txResult = await withTimeout(
      this.client.waitForTransaction({
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
    if (!signId) throw new Error("Failed to get sign ID from transaction");

    const signResult = await withTimeout(
      this.ikaClient.getSignInParticularState(signId, Curve.ED25519, sigAlgorithm, "Completed"),
      TIMEOUTS.SIGN_WAIT,
      "Signature from Ika network"
    );

    const signatureBytes = new Uint8Array(signResult.state.Completed.signature);
    const signatureHex = Buffer.from(signatureBytes).toString("hex");

    return {
      signatureBytes,
      signatureHex,
      signId,
      digest: result.digest,
    };
  }

  private async verifyPolicyReceiptOrThrow(params: {
    receiptId: string;
    expectedPolicyId: string;
    expectedPolicyVersion: string;
    policyBindingObjectId?: string;
    evmChainId: number;
    toEvm: string;
    intentHashHex: Hex;
  }): Promise<void> {
    const obj = await this.client.getObject({
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
      return this.verifyPolicyReceiptV3OrThrow({
        receiptId: params.receiptId,
        expectedPolicyId: params.expectedPolicyId,
        expectedPolicyVersion: params.expectedPolicyVersion,
        policyBindingObjectId: params.policyBindingObjectId,
        namespace: NAMESPACE_EVM,
        chainId: params.evmChainId,
        destination: params.toEvm,
        intentHashHex: params.intentHashHex,
      });
    }

    if (receiptType.endsWith("::policy_registry::PolicyReceiptV2")) {
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
      const policyVersion = this.bytesFieldToUtf8(policyVersionBytes);
      if (policyVersion !== params.expectedPolicyVersion) {
        throw new Error("PolicyReceipt policy_version mismatch");
      }

      const policyRootHex = this.bytesFieldToHex(fields["policy_root"]);
      if (!policyRootHex || toBytes(policyRootHex as any).length !== 32) {
        throw new Error("PolicyReceipt policy_root missing/invalid (expected 32 bytes)");
      }
      const versionId = String(fields["policy_version_id"] ?? "").trim();
      if (!versionId.startsWith("0x")) {
        throw new Error("PolicyReceipt policy_version_id missing/invalid");
      }

      // Continuous compliance: if a PolicyBinding is provided, require the receipt to match the binding's
      // currently affirmed PolicyVersion. Otherwise, require the receipt to match the latest registry version.
      const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();
      const stableId = this.bytesFieldToUtf8(fields["policy_stable_id"]);
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

      const selectorHex = this.bytesFieldToHex(fields["evm_selector"]);
      if (selectorHex) {
        const n = this.bytesFieldToU8(fields["evm_selector"])?.length ?? 0;
        if (n !== 4)
          throw new Error(
            `PolicyReceipt evm_selector invalid (expected 4 bytes or empty, got ${n})`
          );
      }
      const amtHex = this.bytesFieldToHex(fields["erc20_amount"]);
      if (amtHex) {
        const n = this.bytesFieldToU8(fields["erc20_amount"])?.length ?? 0;
        if (n !== 32)
          throw new Error(
            `PolicyReceipt erc20_amount invalid (expected 32 bytes or empty, got ${n})`
          );
      }

      const evmChainId = Number(String(fields["evm_chain_id"] ?? ""));
      if (!Number.isFinite(evmChainId) || evmChainId !== params.evmChainId) {
        throw new Error("PolicyReceipt evm_chain_id mismatch");
      }

      const receiptTo = this.bytesFieldToHex(fields["to_evm"]);
      if (receiptTo && receiptTo.toLowerCase() !== params.toEvm.toLowerCase()) {
        throw new Error("PolicyReceipt to_evm mismatch");
      }

      const receiptIntentHash = this.bytesFieldToHex(fields["intent_hash"]);
      if (!receiptIntentHash || receiptIntentHash.toLowerCase() !== params.intentHashHex.toLowerCase()) {
        throw new Error(
          `PolicyReceipt intent_hash mismatch (expected=${params.intentHashHex}, receipt=${receiptIntentHash ?? "(unreadable)"})`
        );
      }
      return;
    }

    // Legacy PolicyReceipt (MVP)
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
    const policyVersion = this.bytesFieldToUtf8(policyVersionBytes);
    if (policyVersion !== params.expectedPolicyVersion) {
      throw new Error("PolicyReceipt policy_version mismatch");
    }

    const evmChainId = Number(String(fields["evm_chain_id"] ?? ""));
    if (!Number.isFinite(evmChainId) || evmChainId !== params.evmChainId) {
      throw new Error("PolicyReceipt evm_chain_id mismatch");
    }

    const receiptTo = this.bytesFieldToHex(fields["to_evm"]);
    if (receiptTo && receiptTo.toLowerCase() !== params.toEvm.toLowerCase()) {
      throw new Error("PolicyReceipt to_evm mismatch");
    }

    const receiptIntentHash = this.bytesFieldToHex(fields["intent_hash"]);
    if (!receiptIntentHash || receiptIntentHash.toLowerCase() !== params.intentHashHex.toLowerCase()) {
      throw new Error(
        `PolicyReceipt intent_hash mismatch (expected=${params.intentHashHex}, receipt=${receiptIntentHash ?? "(unreadable)"})`
      );
    }
  }

  /**
   * Check if a PolicyReceiptV4 (or V3) is allowed. If denied, record the denial
   * on-chain via the vault's record_vault_denial_v4 function, then throw PolicyDeniedError.
   *
   * If allowed, validates all fields match expectations (policy, namespace, chain, etc.)
   */
  private async verifyPolicyReceiptV3OrThrow(params: {
    receiptId: string;
    expectedPolicyId: string;
    expectedPolicyVersion: string;
    policyBindingObjectId?: string;
    namespace: number;
    chainId: string | number;
    destination: string;
    intentHashHex: Hex;
  }): Promise<void> {
    const obj = await this.client.getObject({
      id: params.receiptId,
      options: { showContent: true, showType: true },
    });

    if (!obj.data?.content || obj.data.content.dataType !== "moveObject") {
      throw new Error("Invalid policyReceiptId: receipt not found or not a Move object");
    }

    const receiptType = String((obj as any)?.data?.type ?? "");
    if (
      !receiptType.endsWith("::policy_registry::PolicyReceiptV4") &&
      !receiptType.endsWith("::policy_registry::PolicyReceiptV3")
    ) {
      throw new Error(`Invalid receipt type for V4/V3 verification (type=${receiptType})`);
    }

    const fields = (obj.data.content.fields ?? {}) as Record<string, unknown>;
    const allowed = Boolean(fields["allowed"]);
    if (!allowed) {
      const denialReason = Number(fields["denial_reason"] ?? 0);
      // Record the denial on-chain so the event persists for the explorer
      await this.recordVaultDenialOnChain(params.receiptId);
      throw new PolicyDeniedError(denialReason);
    }

    const policyObjectId = String(fields["policy_object_id"] ?? "");
    if (policyObjectId.toLowerCase() !== params.expectedPolicyId.toLowerCase()) {
      throw new Error("PolicyReceipt policy_object_id mismatch");
    }

    const policyVersionBytes = fields["policy_version"];
    const policyVersion = this.bytesFieldToUtf8(policyVersionBytes);
    if (policyVersion !== params.expectedPolicyVersion) {
      throw new Error("PolicyReceipt policy_version mismatch");
    }

    const policyRootHex = this.bytesFieldToHex(fields["policy_root"]);
    if (!policyRootHex || toBytes(policyRootHex as any).length !== 32) {
      throw new Error("PolicyReceipt policy_root missing/invalid (expected 32 bytes)");
    }

    const versionId = String(fields["policy_version_id"] ?? "").trim();
    if (!versionId.startsWith("0x")) {
      throw new Error("PolicyReceipt policy_version_id missing/invalid");
    }

    // Continuous compliance: enforce PolicyBinding (if provided) or latest registry version.
    const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();
    const stableId = this.bytesFieldToUtf8(fields["policy_stable_id"]);
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

    const receiptNamespace = Number(String(fields["namespace"] ?? ""));
    if (!Number.isFinite(receiptNamespace) || receiptNamespace !== params.namespace) {
      throw new Error("PolicyReceipt namespace mismatch");
    }

    const chainBytes = this.bytesFieldToU8(fields["chain_id"]) ?? new Uint8Array();
    if (receiptNamespace === 1) {
      // EVM chain_id historically appeared in two encodings:
      // 1) BCS u64 little-endian (newer/canonical for vault calls)
      // 2) Raw hex bytes from API input (older path, often big-endian)
      // Accept either to avoid rejecting valid receipts minted by older clients.
      const candidates = this.evmChainIdEncodingCandidates(params.chainId);
      const matched = candidates.some((c) => this.bytesEqual(chainBytes, c));
      if (!matched) {
        throw new Error("PolicyReceipt chain_id mismatch");
      }
    } else {
      const expectedChainBytes = new TextEncoder().encode(String(params.chainId));
      if (!this.bytesEqual(chainBytes, expectedChainBytes)) {
        throw new Error("PolicyReceipt chain_id mismatch");
      }
    }

    const destBytes = this.bytesFieldToU8(fields["destination"]) ?? new Uint8Array();
    const expectedDestBytes =
      receiptNamespace === 1
        ? toBytes(String(params.destination) as any)
        : new TextEncoder().encode(String(params.destination));
    if (
      destBytes.length !== expectedDestBytes.length ||
      destBytes.some((b, i) => b !== expectedDestBytes[i])
    ) {
      throw new Error("PolicyReceipt destination mismatch");
    }

    const receiptIntentHash = this.bytesFieldToHex(fields["intent_hash"]);
    if (!receiptIntentHash || receiptIntentHash.toLowerCase() !== params.intentHashHex.toLowerCase()) {
      throw new Error(
        `PolicyReceipt intent_hash mismatch (expected=${params.intentHashHex}, receipt=${receiptIntentHash ?? "(unreadable)"})`
      );
    }
  }

  /**
   * Record a policy denial on-chain by calling the vault's record_vault_denial_v4 function.
   * This emits a VaultSigningDeniedEvent that persists (the tx succeeds, unlike the
   * abort path in policy_gated_authorize_sign_v4).
   */
  private async recordVaultDenialOnChain(receiptId: string): Promise<void> {
    try {
      const vaultId = config.kairo.policyVaultObjectId;
      if (!vaultId || !vaultId.startsWith("0x")) {
        logger.warn("Cannot record vault denial: KAIRO_POLICY_VAULT_OBJECT_ID not set");
        return;
      }

      const packageId = config.kairo.policyMintPackageId;
      if (!packageId || !packageId.startsWith("0x")) {
        logger.warn("Cannot record vault denial: policy package ID not configured");
        return;
      }

      // Resolve vault shared object version
      const vaultObj = await this.client.getObject({
        id: vaultId,
        options: { showOwner: true },
      });
      const vaultSharedVersion = Number(
        (vaultObj as any)?.data?.owner?.Shared?.initial_shared_version ?? 0
      );
      if (!vaultSharedVersion) {
        logger.warn("Cannot record vault denial: failed to resolve vault shared version");
        return;
      }

      const tx = new Transaction();
      const adminAddress = this.adminKeypair.toSuiAddress();
      tx.setSender(adminAddress);
      await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

      tx.moveCall({
        target: `${packageId}::dwallet_policy_vault::record_vault_denial_v4`,
        arguments: [
          tx.sharedObjectRef({
            objectId: vaultId,
            initialSharedVersion: vaultSharedVersion,
            mutable: false, // &PolicyVault (read-only)
          }),
          tx.object(receiptId), // PolicyReceiptV4 (consumed)
          tx.object("0x6"), // Clock
        ],
      });

      const result = await this.executeSuiTransaction(tx);
      const txResult = await withTimeout(
        this.client.waitForTransaction({
          digest: result.digest,
          options: { showEffects: true },
        }),
        TIMEOUTS.TRANSACTION_WAIT,
        "record_vault_denial_v4 confirmation"
      );

      const status = (txResult as any)?.effects?.status;
      if (status?.status === "success") {
        logger.info(
          { receiptId, digest: result.digest },
          "Vault denial recorded on-chain (VaultSigningDeniedEvent emitted)"
        );
      } else {
        logger.warn(
          { receiptId, digest: result.digest, error: status?.error },
          "record_vault_denial_v4 tx failed on-chain"
        );
      }
    } catch (err) {
      logger.warn(
        { receiptId, error: err instanceof Error ? err.message : String(err) },
        "Failed to record vault denial on-chain (non-fatal)"
      );
    }
  }

  // ---------------- Policy V3 (Multi-Chain) ----------------

  /**
   * Detect chain namespace from address format.
   * Returns: 1=EVM, 2=Bitcoin, 3=Solana (matches Move custody_ledger + PolicyV3 constants)
   */
  private detectNamespace(addr: string): number {
    const NAMESPACE_EVM = 1;
    const NAMESPACE_BITCOIN = 2;
    const NAMESPACE_SOLANA = 3;

    const a = addr.trim();
    // EVM: 0x + 40 hex
    if (/^0x[0-9a-fA-F]{40}$/.test(a)) return NAMESPACE_EVM;
    // Bitcoin Legacy/P2SH
    if (/^[1mn32][1-9A-HJ-NP-Za-km-z]{24,33}$/.test(a)) return NAMESPACE_BITCOIN;
    // Bitcoin SegWit/Taproot
    if (/^(bc1|tb1)[0-9a-z]{39,62}$/i.test(a)) return NAMESPACE_BITCOIN;
    // Solana: Base58, 32-44 chars
    if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return NAMESPACE_SOLANA;
    throw new Error(`Unknown address format: ${a}`);
  }

  /**
   * Convert address to raw bytes based on namespace.
   */
  private addressToBytes(addr: string, namespace: number): Uint8Array {
    const NAMESPACE_EVM = 1;
    const NAMESPACE_BITCOIN = 2;
    const NAMESPACE_SOLANA = 3;

    const a = addr.trim();
    if (namespace === NAMESPACE_EVM) {
      // EVM: 20 bytes
      const raw = a.startsWith("0x") ? a.slice(2) : a;
      if (!/^[0-9a-fA-F]{40}$/.test(raw)) throw new Error(`Invalid EVM address: ${a}`);
      const out = new Uint8Array(20);
      for (let i = 0; i < 20; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
      return out;
    } else if (namespace === NAMESPACE_BITCOIN) {
      // Bitcoin: store as UTF-8 encoded address string (decoded on-chain or by verifier)
      return new TextEncoder().encode(a);
    } else if (namespace === NAMESPACE_SOLANA) {
      // Solana: store as UTF-8 encoded base58 address (32-44 chars)
      return new TextEncoder().encode(a);
    }
    throw new Error(`Unknown namespace: ${namespace}`);
  }

  // ---------------- Policy Registry + Binding (Phase 1) ----------------

  async createAndSharePolicyRegistry(): Promise<{ registryObjectId: string; digest: string }> {
    await this.initPromise;

    const policyPkg =
      config.kairo.policyMintPackageId &&
      String(config.kairo.policyMintPackageId).startsWith("0x")
        ? String(config.kairo.policyMintPackageId)
        : "";
    if (!policyPkg) {
      throw new Error(
        "Missing KAIRO_POLICY_MINT_PACKAGE_ID (required to create a PolicyRegistry)"
      );
    }

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::create_and_share_policy_registry`,
      arguments: [],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Policy registry creation confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      throw new Error(`Policy registry creation failed on-chain: ${err}`);
    }

    const suffix = "::policy_registry::PolicyRegistry";
    const changes = ((txResult as any)?.objectChanges ?? []) as Array<any>;
    let registryObjectId: string | null = null;
    for (const c of changes) {
      if (c?.type !== "created") continue;
      const t = String(c.objectType ?? "");
      const id = String(c.objectId ?? "");
      if (id && t.endsWith(suffix)) {
        registryObjectId = id;
        break;
      }
    }
    // Fallback: recover via effects.created and fetch types.
    if (!registryObjectId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.endsWith(suffix)) {
            registryObjectId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }
    if (!registryObjectId) {
      throw new Error("Failed to find created PolicyRegistry object in transaction result");
    }
    return { registryObjectId, digest: result.digest };
  }

  async registerPolicyVersionFromPolicy(params: {
    registryObjectId?: string;
    policyObjectId: string;
    note?: string;
  }): Promise<{ policyVersionObjectId: string; digest: string }> {
    await this.initPromise;

    const configPkg = this.getPolicyPkg();

    const registryId = String(
      params.registryObjectId ?? (config.kairo as any).policyRegistryId ?? ""
    ).trim();
    if (!registryId.startsWith("0x")) {
      throw new Error(
        "Missing KAIRO_POLICY_REGISTRY_ID (required to register policy versions)"
      );
    }
    if (!String(params.policyObjectId ?? "").startsWith("0x")) {
      throw new Error("Invalid policyObjectId");
    }

    const noteBytes = new TextEncoder().encode(String(params.note ?? "policy publish"));
    const VecU8 = bcs.vector(bcs.u8());

    const objTypeInfo = await this.client.getObject({
      id: params.policyObjectId,
      options: { showType: true, showContent: true },
    });
    const policyType = String((objTypeInfo as any)?.data?.type ?? "");

    // Always call the configured latest package for registry/vault entrypoints.
    // On Sui upgrades, object type origins can differ from the latest package id.
    // Using configPkg keeps all backend calls on the current deployment.
    const policyPkg = configPkg;

    const isPolicyV2 = policyType.endsWith("::policy_registry::PolicyV2");
    const isPolicyV3 = policyType.endsWith("::policy_registry::PolicyV3");
    const isPolicyV4 = policyType.endsWith("::policy_registry::PolicyV4");

    // Single getNormalizedMoveModule call to check function availability
    let hasFromPolicy = false;
    let hasFromPolicyV2 = false;
    let hasFromPolicyV3 = false;
    let hasFromPolicyV4 = false;
    try {
      const mod = await this.client.getNormalizedMoveModule({
        package: policyPkg,
        module: "policy_registry",
      });
      const fns = (mod as any)?.exposedFunctions ?? (mod as any)?.functions ?? {};
      hasFromPolicy = Boolean(fns?.["register_policy_version_from_policy"]);
      hasFromPolicyV2 = Boolean(fns?.["register_policy_version_from_policy_v2"]);
      hasFromPolicyV3 = Boolean(fns?.["register_policy_version_from_policy_v3"]);
      hasFromPolicyV4 = Boolean(fns?.["register_policy_version_from_policy_v4"]);
    } catch {
      // ignore — will fall through to the manual fallback
    }

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    if (isPolicyV4 && hasFromPolicyV4) {
      tx.moveCall({
        target: `${policyPkg}::policy_registry::register_policy_version_from_policy_v4`,
        arguments: [
          tx.object(registryId),
          tx.object("0x6"), // Clock
          tx.object(params.policyObjectId),
          tx.pure(VecU8.serialize(Array.from(noteBytes)).toBytes()),
        ],
      });
    } else if (isPolicyV3 && hasFromPolicyV3) {
      tx.moveCall({
        target: `${policyPkg}::policy_registry::register_policy_version_from_policy_v3`,
        arguments: [
          tx.object(registryId),
          tx.object("0x6"), // Clock
          tx.object(params.policyObjectId),
          tx.pure(VecU8.serialize(Array.from(noteBytes)).toBytes()),
        ],
      });
    } else if (isPolicyV2 && hasFromPolicyV2) {
      tx.moveCall({
        target: `${policyPkg}::policy_registry::register_policy_version_from_policy_v2`,
        arguments: [
          tx.object(registryId),
          tx.object("0x6"), // Clock
          tx.object(params.policyObjectId),
          tx.pure(VecU8.serialize(Array.from(noteBytes)).toBytes()),
        ],
      });
    } else if (!isPolicyV2 && !isPolicyV3 && !isPolicyV4 && hasFromPolicy) {
      tx.moveCall({
        target: `${policyPkg}::policy_registry::register_policy_version_from_policy`,
        arguments: [
          tx.object(registryId),
          tx.object("0x6"), // Clock
          tx.object(params.policyObjectId),
          tx.pure(VecU8.serialize(Array.from(noteBytes)).toBytes()),
        ],
      });
    } else {
      // Fallback: read policy fields and call
      // register_policy_version(registry, clock, stable_id, version, root, note)
      const obj = await this.client.getObject({
        id: params.policyObjectId,
        options: { showContent: true, showType: true },
      });
      const t = String((obj as any)?.data?.type ?? "");
      const fields: any = (obj as any)?.data?.content?.fields ?? {};
      const decodeVecU8 = (v: any): Uint8Array => {
        if (!v) return new Uint8Array();
        if (v instanceof Uint8Array) return v;
        if (Array.isArray(v)) {
          try {
            return Uint8Array.from(v.map((x: any) => Number(x)));
          } catch {
            return new Uint8Array();
          }
        }
        if (typeof v === "string") {
          // Allow hex string vectors (best-effort)
          if (/^0x[0-9a-fA-F]*$/.test(v)) {
            try {
              return toBytes(v as Hex);
            } catch {
              return new Uint8Array();
            }
          }
          try {
            return new TextEncoder().encode(v);
          } catch {
            return new Uint8Array();
          }
        }
        if (typeof v === "object") {
          const inner = (v as any).bytes ?? (v as any).data ?? (v as any).value;
          if (inner !== undefined) return decodeVecU8(inner);
        }
        return new Uint8Array();
      };
      const stableIdBytes = decodeVecU8(fields["policy_id"]);
      const versionBytes = decodeVecU8(fields["policy_version"]);
      if (stableIdBytes.length === 0) throw new Error("Policy missing policy_id");
      if (versionBytes.length === 0) throw new Error("Policy missing policy_version");

      const rootBytes = (() => {
        if (t.endsWith("::policy_registry::Policy")) {
          const allowToEvmRaw = Array.isArray(fields["allow_to_evm"]) ? fields["allow_to_evm"] : [];
          const denyToEvmRaw = Array.isArray(fields["deny_to_evm"]) ? fields["deny_to_evm"] : [];
          const allowToEvmBytes = allowToEvmRaw.map((x: any) => decodeVecU8(x));
          const denyToEvmBytes = denyToEvmRaw.map((x: any) => decodeVecU8(x));
          const expiresAtMs = BigInt(fields["expires_at_ms"] ?? 0);

          // Compute policy_root exactly like Move `compute_policy_root`:
          // keccak256( bcs::to_bytes(PolicyCanonicalV1{...}) )
          const VecU8Inner = bcs.vector(bcs.u8());
          const VecVecU8Inner = bcs.vector(VecU8Inner);
          const PolicyCanonicalV1Bcs = bcs.struct("PolicyCanonicalV1", {
            policy_id: VecU8Inner,
            policy_version: VecU8Inner,
            allow_to_evm: VecVecU8Inner,
            deny_to_evm: VecVecU8Inner,
            expires_at_ms: bcs.u64(),
          });
          const canonBytes = PolicyCanonicalV1Bcs.serialize({
            policy_id: stableIdBytes,
            policy_version: versionBytes,
            allow_to_evm: allowToEvmBytes,
            deny_to_evm: denyToEvmBytes,
            expires_at_ms: expiresAtMs,
          }).toBytes();
          return toBytes(keccak256(canonBytes));
        }

        if (t.endsWith("::policy_registry::PolicyV2")) {
          const allowToEvmRaw = Array.isArray(fields["allow_to_evm"]) ? fields["allow_to_evm"] : [];
          const denyToEvmRaw = Array.isArray(fields["deny_to_evm"]) ? fields["deny_to_evm"] : [];
          const allowToEvmBytes = allowToEvmRaw.map((x: any) => decodeVecU8(x));
          const denyToEvmBytes = denyToEvmRaw.map((x: any) => decodeVecU8(x));
          const expiresAtMs = BigInt(fields["expires_at_ms"] ?? 0);
          const allowEvmChainIdsRaw = Array.isArray(fields["allow_evm_chain_ids"])
            ? fields["allow_evm_chain_ids"]
            : [];
          const allowEvmChainIds = allowEvmChainIdsRaw.map((x: any) => BigInt(String(x ?? "0")));
          const allowSelectorsRaw = Array.isArray(fields["allow_evm_selectors"])
            ? fields["allow_evm_selectors"]
            : [];
          const denySelectorsRaw = Array.isArray(fields["deny_evm_selectors"])
            ? fields["deny_evm_selectors"]
            : [];
          const allowSelectors = allowSelectorsRaw.map((x: any) => decodeVecU8(x));
          const denySelectors = denySelectorsRaw.map((x: any) => decodeVecU8(x));
          const erc20RulesRaw = Array.isArray(fields["erc20_rules"]) ? fields["erc20_rules"] : [];
          const erc20Rules = erc20RulesRaw.map((r: any) => {
            const rf: any = (r && typeof r === "object" ? (r.fields ?? r) : {}) as any;
            return {
              token: decodeVecU8(rf["token"]),
              max_amount: decodeVecU8(rf["max_amount"]),
            };
          });

          // Compute policy_root_v2 exactly like Move `compute_policy_root_v2`:
          // keccak256( bcs::to_bytes(PolicyV2CanonicalV1{...}) )
          const VecU8Inner = bcs.vector(bcs.u8());
          const VecVecU8Inner = bcs.vector(VecU8Inner);
          const VecU64Inner = bcs.vector(bcs.u64());
          const Erc20RuleBcs = bcs.struct("Erc20Rule", {
            token: VecU8Inner,
            max_amount: VecU8Inner,
          });
          const VecErc20RuleBcs = bcs.vector(Erc20RuleBcs);
          const PolicyV2CanonicalV1Bcs = bcs.struct("PolicyV2CanonicalV1", {
            policy_id: VecU8Inner,
            policy_version: VecU8Inner,
            allow_to_evm: VecVecU8Inner,
            deny_to_evm: VecVecU8Inner,
            expires_at_ms: bcs.u64(),
            allow_evm_chain_ids: VecU64Inner,
            allow_evm_selectors: VecVecU8Inner,
            deny_evm_selectors: VecVecU8Inner,
            erc20_rules: VecErc20RuleBcs,
          });
          const canonBytes = PolicyV2CanonicalV1Bcs.serialize({
            policy_id: stableIdBytes,
            policy_version: versionBytes,
            allow_to_evm: allowToEvmBytes,
            deny_to_evm: denyToEvmBytes,
            expires_at_ms: expiresAtMs,
            allow_evm_chain_ids: allowEvmChainIds,
            allow_evm_selectors: allowSelectors,
            deny_evm_selectors: denySelectors,
            erc20_rules: erc20Rules,
          }).toBytes();
          return toBytes(keccak256(canonBytes));
        }

        throw new Error(`policyObjectId is not a supported policy type (type=${t})`);
      })();
      if (rootBytes.length !== 32) throw new Error("Computed policy_root is not 32 bytes (unexpected)");
      tx.moveCall({
        target: `${policyPkg}::policy_registry::register_policy_version`,
        arguments: [
          tx.object(registryId),
          tx.object("0x6"), // Clock
          tx.pure(VecU8.serialize(Array.from(stableIdBytes)).toBytes()),
          tx.pure(VecU8.serialize(Array.from(versionBytes)).toBytes()),
          tx.pure(VecU8.serialize(Array.from(rootBytes)).toBytes()),
          tx.pure(VecU8.serialize(Array.from(noteBytes)).toBytes()),
        ],
      });
    }


    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Policy version registration confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      throw new Error(`Policy version registration failed on-chain: ${err}`);
    }

    const suffix = "::policy_registry::PolicyVersion";
    const changes = ((txResult as any)?.objectChanges ?? []) as Array<any>;
    let policyVersionObjectId: string | null = null;
    for (const c of changes) {
      if (c?.type !== "created") continue;
      const t = String(c.objectType ?? "");
      const id = String(c.objectId ?? "");
      if (id && t.endsWith(suffix)) {
        policyVersionObjectId = id;
        break;
      }
    }
    if (!policyVersionObjectId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.endsWith(suffix)) {
            policyVersionObjectId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }
    if (!policyVersionObjectId) {
      throw new Error("Failed to find created PolicyVersion object in transaction result");
    }
    return { policyVersionObjectId, digest: result.digest };
  }

  async createPolicyBinding(params: {
    registryObjectId?: string;
    dWalletId: string;
    stableId: string;
  }): Promise<{ bindingObjectId: string; digest: string; activeVersionObjectId?: string }> {
    await this.initPromise;

    const policyPkg = this.getPolicyPkg();

    const registryId = String(
      params.registryObjectId ?? (config.kairo as any).policyRegistryId ?? ""
    ).trim();
    if (!registryId.startsWith("0x")) {
      throw new Error("Missing KAIRO_POLICY_REGISTRY_ID (required to create PolicyBinding)");
    }
    if (!String(params.dWalletId ?? "").startsWith("0x")) {
      throw new Error("Invalid dWalletId");
    }

    const dWalletObj = await this.client.getObject({
      id: params.dWalletId,
      options: { showType: true },
    });
    if (!dWalletObj.data) {
      throw new Error(
        `dWallet ${params.dWalletId} does not exist on-chain`
      );
    }

    const stableId = String(params.stableId ?? "").trim();
    if (!stableId) throw new Error("Missing stableId");

    const VecU8 = bcs.vector(bcs.u8());
    const dwalletBytes = new TextEncoder().encode(String(params.dWalletId));
    const stableBytes = new TextEncoder().encode(stableId);

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::create_and_share_policy_binding`,
      arguments: [
        tx.object(registryId),
        tx.object("0x6"), // Clock
        tx.pure(VecU8.serialize(Array.from(dwalletBytes)).toBytes()),
        tx.pure(VecU8.serialize(Array.from(stableBytes)).toBytes()),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Policy binding creation confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    const status = (txResult as any)?.effects?.status;
    if (status?.status && status.status !== "success") {
      const err = String(status.error ?? "unknown execution error");
      // Include digest so we can always inspect the tx on Sui explorers even if logs/UI truncate.
      throw new Error(`Policy binding creation failed on-chain (digest=${result.digest}): ${err}`);
    }

    const suffix = "::policy_registry::PolicyBinding";
    const changes = ((txResult as any)?.objectChanges ?? []) as Array<any>;
    let bindingObjectId: string | null = null;
    for (const c of changes) {
      if (c?.type !== "created") continue;
      const t = String(c.objectType ?? "");
      const id = String(c.objectId ?? "");
      if (id && t.endsWith(suffix)) {
        bindingObjectId = id;
        break;
      }
    }
    if (!bindingObjectId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.endsWith(suffix)) {
            bindingObjectId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }
    if (!bindingObjectId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      const changes2 = ((txResult as any)?.objectChanges ?? []) as Array<any>;
      // Fallback: if RPC doesn't provide created/objectChanges, try locating the shared object by scanning PolicyBinding objects.
      // This approach avoids brittle tx parsing across nodes.
      try {
        const wantDWallet = String(params.dWalletId);
        const wantStable = String(stableId);
        let cursor: any = null;
        for (let page = 0; page < 6; page++) {
          const res = await (this.client as any).queryObjects({
            query: { MoveStructType: `${policyPkg}::policy_registry::PolicyBinding` },
            cursor,
            limit: 50,
            options: { showContent: true, showType: true },
          });
          const items = (res as any)?.data ?? [];
          for (const o of items) {
            const objId = String((o as any)?.data?.objectId ?? "").trim();
            const t = String((o as any)?.data?.type ?? "").trim();
            if (!objId.startsWith("0x")) continue;
            if (!t.endsWith("::policy_registry::PolicyBinding")) continue;
            const fields: any = (o as any)?.data?.content?.fields ?? {};
            const dw = fields["dwallet_id"];
            const st = fields["stable_id"];
            const dwStr = (() => {
              try {
                const b = Array.isArray(dw) ? Uint8Array.from(dw) : null;
                return b ? new TextDecoder().decode(b) : "";
              } catch {
                return "";
              }
            })();
            const stStr = (() => {
              try {
                const b = Array.isArray(st) ? Uint8Array.from(st) : null;
                return b ? new TextDecoder().decode(b) : "";
              } catch {
                return "";
              }
            })();
            if (dwStr === wantDWallet && stStr === wantStable) {
              bindingObjectId = objId;
              break;
            }
          }
          if (bindingObjectId) break;
          cursor = (res as any)?.nextCursor ?? null;
          if (!(res as any)?.hasNextPage) break;
        }
      } catch {
        // ignore
      }
      if (!bindingObjectId) {
        throw new Error(
          `Failed to find created PolicyBinding object in transaction result (createdCount=${created.length}, objectChangesCount=${changes2.length})`
        );
      }
    }

    // Best-effort: fetch active version id after creation (for UI/debug).
    let activeVersionObjectId: string | undefined;
    try {
      const obj = await this.client.getObject({
        id: bindingObjectId,
        options: { showContent: true },
      });
      const fields: any = (obj as any)?.data?.content?.fields ?? {};
      const v = String(fields["active_version_id"] ?? "").trim();
      if (v.startsWith("0x")) activeVersionObjectId = v;
    } catch {
      // ignore
    }

    pushPolicyAudit({
      kind: "binding_create",
      createdAtMs: Date.now(),
      digest: result.digest,
      objectId: bindingObjectId,
      meta: { dWalletId: params.dWalletId, stableId },
    });

    return { bindingObjectId, digest: result.digest, activeVersionObjectId };
  }

  async resolvePolicyStableIdString(policyObjectId: string): Promise<string | null> {
    await this.initPromise;
    if (!String(policyObjectId ?? "").startsWith("0x")) return null;
    const obj = await this.client.getObject({
      id: policyObjectId,
      options: { showContent: true, showType: true },
    });
    const t = String((obj as any)?.data?.type ?? "");
    if (
      !t.endsWith("::policy_registry::Policy") &&
      !t.endsWith("::policy_registry::PolicyV2") &&
      !t.endsWith("::policy_registry::PolicyV3") &&
      !t.endsWith("::policy_registry::PolicyV4")
    )
      return null;
    const fields: any = (obj as any)?.data?.content?.fields ?? {};
    const raw = fields["policy_id"];
    try {
      if (typeof raw === "string") return raw.trim() || null;
      if (Array.isArray(raw)) {
        const b = Uint8Array.from(raw.map((x: any) => Number(x)));
        const s = new TextDecoder().decode(b).trim();
        return s || null;
      }
    } catch {
      // ignore
    }
    return null;
  }

  async reaffirmPolicyBinding(params: {
    registryObjectId?: string;
    bindingObjectId: string;
  }): Promise<{ digest: string; activeVersionObjectId?: string }> {
    await this.initPromise;

    const policyPkg =
      config.kairo.policyMintPackageId &&
      String(config.kairo.policyMintPackageId).startsWith("0x")
        ? String(config.kairo.policyMintPackageId)
        : "";
    if (!policyPkg) {
      throw new Error(
        "Missing KAIRO_POLICY_MINT_PACKAGE_ID (required to reaffirm PolicyBinding)"
      );
    }

    const registryId = String(
      params.registryObjectId ?? (config.kairo as any).policyRegistryId ?? ""
    ).trim();
    if (!registryId.startsWith("0x")) {
      throw new Error("Missing KAIRO_POLICY_REGISTRY_ID (required to reaffirm PolicyBinding)");
    }
    if (!String(params.bindingObjectId ?? "").startsWith("0x")) {
      throw new Error("Invalid bindingObjectId");
    }

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::reaffirm_policy_binding`,
      arguments: [tx.object(params.bindingObjectId), tx.object(registryId), tx.object("0x6")],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Policy binding reaffirmation confirmation"
    );

    // Best-effort: fetch active version id after reaffirmation.
    let activeVersionObjectId: string | undefined;
    try {
      const obj = await this.client.getObject({
        id: params.bindingObjectId,
        options: { showContent: true },
      });
      const fields: any = (obj as any)?.data?.content?.fields ?? {};
      const v = String(fields["active_version_id"] ?? "").trim();
      if (v.startsWith("0x")) activeVersionObjectId = v;
    } catch {
      // ignore
    }

    return { digest: result.digest, activeVersionObjectId };
  }

  private async appendCustodyEventWithReceipt(args: {
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
    const pkg = args.custodyPackageId;
    if (!pkg.startsWith("0x")) throw new Error("Invalid custodyPackageId");

    const decodeU8Vec = (v: any): Uint8Array | null => {
      if (!v) return null;
      if (v instanceof Uint8Array) return v;
      if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
        return Uint8Array.from(v);
      }
      if (typeof v === "string") {
        if (/^0x[0-9a-fA-F]*$/.test(v)) {
          const raw = v.slice(2);
          if (raw.length % 2 !== 0) return null;
          const out = new Uint8Array(raw.length / 2);
          for (let i = 0; i < out.length; i++) out[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);
          return out;
        }
        try {
          return Uint8Array.from(Buffer.from(v, "base64"));
        } catch {
          return null;
        }
      }
      if (typeof v === "object") {
        const inner = (v as any).bytes ?? (v as any).data ?? (v as any).value;
        if (inner !== undefined) return decodeU8Vec(inner);
      }
      return null;
    };

    // Fetch custody chain head hash for prev_hash check.
    const chainObj = await this.client.getObject({
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
    const prevHashBytes = decodeU8Vec(headHashAny);
    if (!prevHashBytes || prevHashBytes.length !== 32) {
      throw new Error("Failed to read custody chain head_hash (expected 32 bytes)");
    }

    // intent_hash is required by on-chain checks
    const intentBytes = toBytes(args.intentHashHex);
    if (intentBytes.length !== 32) throw new Error("intentHashHex must be 32 bytes");

    // src_tx_hash (optional; 32 bytes if present)
    const srcTxHashBytes = (() => {
      const h = String(args.srcTxHashHex ?? "").trim();
      if (!h) return null;
      if (!/^0x[0-9a-fA-F]{64}$/.test(h)) throw new Error("srcTxHashHex must be 32 bytes hex");
      return toBytes(h as any);
    })();

    // Determine receipt type so we can call the correct custody_ledger entrypoint.
    const receiptObj = await this.client.getObject({
      id: args.receiptObjectId,
      options: { showType: true, showContent: true },
    });
    const receiptType = String((receiptObj as any)?.data?.type ?? "");
    const isReceiptV2 = receiptType.endsWith("::policy_registry::PolicyReceiptV2");
    const isReceiptV3 = receiptType.endsWith("::policy_registry::PolicyReceiptV3");
    const isReceiptV4 = receiptType.endsWith("::policy_registry::PolicyReceiptV4");

    // V3/V4 receipts store destination on-chain; use it so custody contains a meaningful `to_addr`.
    let toAddrBytes: Uint8Array | null = null;
    if (isReceiptV4 || isReceiptV3) {
      const receiptFields = (receiptObj as any)?.data?.content?.fields ?? {};
      const destAny = receiptFields?.destination;
      const dest = decodeU8Vec(destAny);
      if (dest && dest.length > 0) {
        toAddrBytes = dest;
      }
    } else {
      const toEvmBytes = toBytes(args.toEvm as any);
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
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const chainRef = tx.sharedObjectRef({
      objectId: args.custodyChainObjectId,
      initialSharedVersion,
      mutable: true,
    });

    // Prefer v3 (PolicyReceiptV3 / PolicyReceiptV2) or v2 (PolicyReceipt) where possible so Sui computes event_hash deterministically.
    const custodyFns = await (async (): Promise<Set<string>> => {
      try {
        const mod = await this.client.getNormalizedMoveModule({
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
    })();

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
    } else if (!isReceiptV2 && custodyFns.has("append_event_with_receipt_any_v2")) {
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
      // Fallback (legacy): caller-provided event_hash.
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

    const r = await this.executeSuiTransaction(tx);

    // Best-effort: parse created CustodyEvent id so users can find it on explorers.
    let custodyEventObjectId: string | undefined;
    try {
      await withTimeout(
        this.client.waitForTransaction({
          digest: r.digest,
          options: { showEffects: true },
        }),
        TIMEOUTS.TRANSACTION_WAIT,
        "Custody append confirmation"
      );
      const txResult = await this.client.getTransactionBlock({
        digest: r.digest,
        options: { showObjectChanges: true, showEffects: true },
      });

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
      if (!custodyEventObjectId) {
        const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
        for (const c of created) {
          const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
          if (!id.startsWith("0x")) continue;
          try {
            const obj = await this.client.getObject({ id, options: { showType: true } });
            const t = String((obj as any)?.data?.type ?? "");
            if (t.endsWith("::custody_ledger::CustodyEvent")) {
              custodyEventObjectId = id;
              break;
            }
          } catch {
            // ignore
          }
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

  private async createAndShareCustodyChainForPolicy(args: {
    custodyPackageId: string;
    policyObjectId: string;
  }): Promise<{ custodyChainObjectId: string; digest: string }> {
    const pkg = String(args.custodyPackageId ?? "").trim();
    if (!pkg.startsWith("0x")) throw new Error("Invalid custodyPackageId");
    const policyId = String(args.policyObjectId ?? "").trim();
    if (!policyId.startsWith("0x")) throw new Error("Invalid policyObjectId for custody chain creation");

    // Use policy object id bytes as AssetId.id so a given policy maps to a deterministic chain identity.
    const raw = policyId.slice(2);
    if (raw.length % 2 !== 0) throw new Error("Invalid policyObjectId hex");
    const idBytes = new Uint8Array(raw.length / 2);
    for (let i = 0; i < idBytes.length; i++) idBytes[i] = parseInt(raw.slice(i * 2, i * 2 + 2), 16);

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    // create_and_share_chain_from_parts(namespace, chain_id, kind, id)
    tx.moveCall({
      target: `${pkg}::custody_ledger::create_and_share_chain_from_parts`,
      arguments: [
        tx.pure.u8(1), // namespace (kairo)
        tx.pure.u64(0n), // chain_id (generic)
        tx.pure.u8(1), // kind (policy)
        tx.pure.vector("u8", Array.from(idBytes)),
      ],
    });

    const r = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: r.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Custody chain creation confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: r.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

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
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.endsWith("::custody_ledger::CustodyChain")) {
            custodyChainObjectId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }
    if (!custodyChainObjectId) {
      throw new Error("Custody chain creation succeeded but CustodyChain objectId not found");
    }

    logger.info({ custodyChainObjectId, digest: r.digest }, "Created custody chain for policy");
    return { custodyChainObjectId, digest: r.digest };
  }

  private bytesFieldToHex(v: unknown): string | null {
    const bytes = this.bytesFieldToU8(v);
    if (!bytes) return null;
    if (bytes.length === 0) return null;
    return `0x${Buffer.from(bytes).toString("hex")}`;
  }

  private bytesFieldToUtf8(v: unknown): string {
    const bytes = this.bytesFieldToU8(v);
    if (!bytes) return "";
    return new TextDecoder().decode(bytes);
  }

  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  private evmChainIdEncodingCandidates(chainId: string | number): Uint8Array[] {
    const idBig = BigInt(typeof chainId === "number" ? chainId : Number(chainId));
    // Canonical current encoding: BCS u64 LE
    const leU64 = new Uint8Array(bcs.u64().serialize(idBig).toBytes());

    // Legacy encodings from raw-hex API input paths (big-endian bytes).
    const hex = idBig.toString(16);
    const evenHex = hex.length % 2 === 0 ? hex : `0${hex}`;
    const beMinimal = Uint8Array.from(Buffer.from(evenHex, "hex"));
    const beU32 = Uint8Array.from(Buffer.from(evenHex.padStart(8, "0"), "hex"));
    const beU64 = Uint8Array.from(Buffer.from(evenHex.padStart(16, "0"), "hex"));

    // Deduplicate by hex value.
    const uniq = new Map<string, Uint8Array>();
    for (const c of [leU64, beMinimal, beU32, beU64]) {
      uniq.set(Buffer.from(c).toString("hex"), c);
    }
    return Array.from(uniq.values());
  }

  private async getReceiptChainIdBytes(receiptId: string): Promise<Uint8Array | null> {
    const id = String(receiptId ?? "").trim();
    if (!id.startsWith("0x")) return null;
    try {
      const obj = await this.client.getObject({
        id,
        options: { showContent: true, showType: true },
      });
      if (!obj.data?.content || obj.data.content.dataType !== "moveObject") return null;
      const fields = (obj.data.content.fields ?? {}) as Record<string, unknown>;
      const bytes = this.bytesFieldToU8(fields["chain_id"]);
      return bytes ?? null;
    } catch {
      return null;
    }
  }

  private async getPolicyBindingInfo(bindingObjectId: string): Promise<{
    stableId?: string;
    activeVersionId?: string;
  }> {
    const id = String(bindingObjectId ?? "").trim();
    if (!id.startsWith("0x")) return {};

    const obj = await this.client.getObject({
      id,
      options: { showType: true, showContent: true },
    });
    const t = String((obj as any)?.data?.type ?? "");
    if (!t.endsWith("::policy_registry::PolicyBinding")) {
      throw new Error(`policyBindingObjectId is not a PolicyBinding (type=${t})`);
    }
    const fields: any = (obj as any)?.data?.content?.fields ?? {};
    const stableId = this.bytesFieldToUtf8(fields["stable_id"]);
    const activeVersionId = String(fields["active_version_id"] ?? "").trim();
    return {
      stableId: stableId || undefined,
      activeVersionId: activeVersionId.startsWith("0x") ? activeVersionId : undefined,
    };
  }

  private async getLatestPolicyVersionIdFromRegistry(params: {
    registryObjectId: string;
    stableId: string;
  }): Promise<string | null> {
    const registryObjectId = String(params.registryObjectId ?? "").trim();
    const stableId = String(params.stableId ?? "").trim();
    if (!registryObjectId.startsWith("0x") || !stableId) return null;

    const obj = await this.client.getObject({
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
      const s = (s0 && typeof s0 === "object" && (s0 as any).fields) ? (s0 as any).fields : s0;
      const sid = this.bytesFieldToUtf8((s as any)?.stable_id);
      if (!sid || sid !== stableId) continue;
      const versions: any = (s as any)?.versions;
      if (!Array.isArray(versions) || versions.length === 0) return null;
      const last = String(versions[versions.length - 1] ?? "").trim();
      return last.startsWith("0x") ? last : null;
    }
    return null;
  }

  /**
   * Sui JSON can represent `vector<u8>` in multiple shapes depending on RPC/version:
   * - number[] (most common)
   * - { bytes: number[] } / { data: number[] } / { value: number[] }
   * - base64 string (some RPCs)
   * - 0x-prefixed hex string (rare, but accept)
   */
  private bytesFieldToU8(v: unknown): Uint8Array | null {
    if (!v) return null;
    if (v instanceof Uint8Array) return v;
    if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
      return Uint8Array.from(v as number[]);
    }
    if (typeof v === "string") {
      const s = v.trim();
      if (!s) return null;
      if (/^0x[0-9a-fA-F]*$/.test(s)) {
        try {
          return toBytes(s as any);
        } catch {
          return null;
        }
      }
      // base64 fallback
      try {
        return Uint8Array.from(Buffer.from(s, "base64"));
      } catch {
        return null;
      }
    }
    if (typeof v === "object") {
      const o: any = v as any;
      // common wrappers
      if (o.bytes != null) return this.bytesFieldToU8(o.bytes);
      if (o.data != null) return this.bytesFieldToU8(o.data);
      if (o.value != null) return this.bytesFieldToU8(o.value);
      if (o.fields != null) return this.bytesFieldToU8(o.fields);
    }
    return null;
  }

  /**
   * Broadcast a signed transaction to the requested EVM chain
   */
  private async broadcastToEthereum(
    ethTx: NonNullable<SignRequestInput["ethTx"]>,
    signatureBytes: Uint8Array
  ): Promise<{ txHash: string; blockNumber: number }> {
    const chainId = Number(ethTx.chainId);
    const chainName = getEvmChainName(chainId);
    const ethClient = getEvmPublicClient(chainId);

    // Use the EXACT values from ethTx that were signed by the frontend
    // Do NOT fetch fresh nonce/gas - the signature was computed over these specific values
    logger.info(
      {
        from: ethTx.from,
        nonce: ethTx.nonce,
        maxFeePerGas: ethTx.maxFeePerGas,
        maxPriorityFeePerGas: ethTx.maxPriorityFeePerGas,
        chainId: ethTx.chainId,
      },
      "Using signed transaction values for broadcast"
    );

    // Parse signature (r, s from ECDSA signature)
    // Format: r[32-byte]-s[32-byte] (no v/recovery ID from Ika)
    const r = `0x${Buffer.from(signatureBytes.slice(0, 32)).toString(
      "hex"
    )}` as Hex;
    const s = `0x${Buffer.from(signatureBytes.slice(32, 64)).toString(
      "hex"
    )}` as Hex;

    // Create the transaction object with the EXACT values that were signed
    const unsignedTx: TransactionSerializableEIP1559 = {
      type: "eip1559",
      chainId: ethTx.chainId,
      nonce: ethTx.nonce,
      to: ethTx.to as Hex,
      value: BigInt(ethTx.value),
      maxFeePerGas: BigInt(ethTx.maxFeePerGas),
      maxPriorityFeePerGas: BigInt(ethTx.maxPriorityFeePerGas),
      gas: BigInt(ethTx.gasLimit),
    };

    // Fail fast with a clear error if the sender doesn't have enough ETH for (value + max gas spend).
    // This prevents confusing "success" states when the chain rejects the tx.
    const balanceWei = await ethClient.getBalance({ address: ethTx.from as Hex });
    const valueWei = BigInt(ethTx.value);
    const maxGasCostWei = BigInt(ethTx.gasLimit) * BigInt(ethTx.maxFeePerGas);
    const requiredWei = valueWei + maxGasCostWei;
    if (balanceWei < requiredWei) {
      throw new Error(
        `Insufficient ETH to send. Need at least ${requiredWei.toString()} wei (value + max gas), have ${balanceWei.toString()} wei. Fund ${ethTx.from} on ${chainName} and retry.`
      );
    }

    // No recovery ID (v) from Ika - try both yParity values (0 and 1)
    // and use the one that recovers to the correct address
    let signedTx: Hex | null = null;
    for (const yParity of [0, 1] as const) {
      const candidateTx = serializeTransaction(unsignedTx, { r, s, yParity });
      try {
        const recoveredAddress = await recoverTransactionAddress({
          serializedTransaction: candidateTx,
        });
        if (recoveredAddress.toLowerCase() === ethTx.from.toLowerCase()) {
          signedTx = candidateTx;
          logger.info({ yParity }, "Found correct yParity for signature");
          break;
        }
      } catch {
        // This yParity didn't work, try the other
        continue;
      }
    }

    if (!signedTx) {
      throw new Error(
        "Failed to recover correct signer address with either yParity value"
      );
    }

    logger.info(
      {
        to: ethTx.to,
        value: ethTx.value,
        chainId: ethTx.chainId,
        nonce: ethTx.nonce,
        signedTxLength: signedTx.length,
      },
      `Broadcasting signed transaction to ${chainName}`
    );

    // Send the raw transaction
    const txHash = await ethClient.sendRawTransaction({
      serializedTransaction: signedTx,
    });

    // Wait for transaction receipt (with timeout)
    const receipt = await withTimeout(
      ethClient.waitForTransactionReceipt({
        hash: txHash,
        confirmations: 1,
      }),
      TIMEOUTS.ETH_RECEIPT_WAIT,
      "Ethereum transaction receipt"
    );

    return {
      txHash,
      blockNumber: Number(receipt.blockNumber),
    };
  }

  /**
   * Pin gas payment coin and budget for admin-signed Sui transactions.
   * This avoids failures when the SDK auto-selects a small gas coin.
   */
  private async setAdminGas(
    tx: Transaction,
    adminAddress: string,
    gasBudgetMist: bigint
  ): Promise<void> {
    // Keep this simple: pick the largest SUI coin object as gas payment.
    const suiCoins = await this.client.getCoins({
      owner: adminAddress,
      coinType: "0x2::sui::SUI",
    });
    const sorted = [...(suiCoins.data ?? [])].sort(
      (a, b) => Number(BigInt(b.balance) - BigInt(a.balance))
    );
    const gasCoin = sorted[0];
    if (!gasCoin) {
      throw new Error(
        `Admin address has no SUI coins to pay gas (admin=${adminAddress}). Fund it on Sui ${config.sui.network}.`
      );
    }

    const balance = BigInt(gasCoin.balance);
    if (balance < gasBudgetMist) {
      // The budget is a MAX; gas used will be lower, but Sui requires coin balance >= budget.
      throw new Error(
        `Insufficient SUI gas coin balance for configured gas budget: ` +
          `gasCoinBalance=${balance} mist, gasBudget=${gasBudgetMist} mist. ` +
          `Top up admin=${adminAddress} or lower SUI_*_GAS_BUDGET_MIST.`
      );
    }

    tx.setGasBudget(gasBudgetMist);
    tx.setGasPayment([
      {
        objectId: gasCoin.coinObjectId,
        version: gasCoin.version,
        digest: gasCoin.digest,
      },
    ]);
  }

  /**
   * Get admin address for display
   */
  getAdminAddress(): string {
    return this.adminKeypair.toSuiAddress();
  }

  /**
   * Lightweight audit feed for UI dashboards.
   * NOTE: This is in-memory only (best-effort).
   */
  listAuditEvents(limit: number = 50): Array<{
    kind: "dkg" | "imported_verify" | "presign" | "sign" | "policy_create" | "binding_create" | "receipt_mint" | "vault_register" | "vault_sign" | "vault_denial";
    id: string;
    status: string;
    createdAtMs: number;
    digest?: string;
    dWalletId?: string;
    dWalletCapId?: string;
    ethereumAddress?: string;
    ethTxHash?: string;
    error?: string;
  }> {
    const out: Array<any> = [];

    for (const r of dkgRequests.values()) {
      out.push({
        kind: "dkg",
        id: r.id,
        status: r.status,
        createdAtMs: r.createdAt.getTime(),
        digest: r.digest,
        dWalletId: r.dWalletObjectId,
        dWalletCapId: r.dWalletCapObjectId,
        ethereumAddress: r.ethereumAddress,
        error: r.error,
      });
    }

    for (const r of importedVerifyRequests.values()) {
      out.push({
        kind: "imported_verify",
        id: r.id,
        status: r.status,
        createdAtMs: r.createdAt.getTime(),
        digest: r.digest,
        dWalletId: r.dWalletObjectId,
        dWalletCapId: r.dWalletCapObjectId,
        ethereumAddress: r.ethereumAddress,
        error: r.error,
      });
    }

    for (const r of presignRequests.values()) {
      out.push({
        kind: "presign",
        id: r.id,
        status: r.status,
        createdAtMs: r.createdAt.getTime(),
        dWalletId: r.dWalletId,
        error: r.error,
      });
    }

    for (const r of signRequests.values()) {
      out.push({
        kind: "sign",
        id: r.id,
        status: r.status,
        createdAtMs: r.createdAt.getTime(),
        digest: r.digest,
        dWalletId: r.data?.dWalletId,
        dWalletCapId: r.data?.dWalletCapId,
        ethTxHash: r.ethTxHash,
        error: r.error,
      });
    }

    for (const evt of policyAuditEvents) {
      out.push({
        kind: evt.kind,
        id: evt.objectId ?? "",
        status: evt.error ? "error" : "success",
        createdAtMs: evt.createdAtMs,
        digest: evt.digest,
        error: evt.error,
      });
    }

    out.sort((a, b) => b.createdAtMs - a.createdAtMs);
    return out.slice(0, Math.max(1, Math.min(200, Math.floor(limit))));
  }

  /**
   * Get Ethereum transaction parameters (nonce, gas prices) for an address
   * Frontend calls this before signing to get actual values
   */
  async getEthTxParams(address: string): Promise<{
    nonce: number;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
    gasLimit: string;
  }> {
    // Back-compat default (previously: Base Sepolia only)
    const chainId = 84532;
    return this.getEvmTxParams({ address, chainId });
  }

  async getEvmTxParams(args: { address: string; chainId: number }): Promise<{
    nonce: number;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
    gasLimit: string;
  }> {
    const { address, chainId } = args;
    const ethClient = getEvmPublicClient(chainId);
    const [nonce, feeData] = await Promise.all([
      ethClient.getTransactionCount({ address: address as Hex }),
      ethClient.estimateFeesPerGas(),
    ]);

    return {
      nonce,
      maxFeePerGas: (feeData.maxFeePerGas || BigInt("50000000000")).toString(),
      maxPriorityFeePerGas: (
        feeData.maxPriorityFeePerGas || BigInt("2000000000")
      ).toString(),
      gasLimit: "21000", // Standard ETH transfer
    };
  }

  // ---- Governance methods ----

  private getPolicyPkg(): string {
    const policyPkg =
      config.kairo.policyMintPackageId &&
      String(config.kairo.policyMintPackageId).startsWith("0x")
        ? String(config.kairo.policyMintPackageId)
        : "";
    if (!policyPkg) {
      throw new Error("Missing KAIRO_POLICY_MINT_PACKAGE_ID");
    }
    return policyPkg;
  }

  private getGovernancePkg(): string {
    const govPkg =
      config.kairo.governancePackageId &&
      String(config.kairo.governancePackageId).startsWith("0x")
        ? String(config.kairo.governancePackageId)
        : "";
    if (!govPkg) {
      throw new Error("Missing KAIRO_GOVERNANCE_PACKAGE_ID");
    }
    return govPkg;
  }

  // -- Binding governance management (calls kairo_policy_engine package) --

  async setBindingGovernance(params: {
    bindingObjectId: string;
    governanceId: string;
    mode?: number; // 0 = Disabled, 1 = ReceiptRequired (default 0)
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::set_binding_governance`,
      arguments: [
        tx.object(params.bindingObjectId),
        tx.pure.address(params.governanceId),
        tx.pure.u8(params.mode ?? 0),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async activateBindingGovernance(params: {
    bindingObjectId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::activate_binding_governance`,
      arguments: [tx.object(params.bindingObjectId)],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async removeBindingGovernance(params: {
    bindingObjectId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::remove_binding_governance`,
      arguments: [tx.object(params.bindingObjectId)],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async updateApprovers(params: {
    adminCapId: string;
    governanceId: string;
    newApprovers: string[];
    newThreshold: number;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const govPkg = this.getGovernancePkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const approverAddresses = params.newApprovers.map((a) => tx.pure.address(a));

    tx.moveCall({
      target: `${govPkg}::policy_governance::update_approvers`,
      arguments: [
        tx.object(params.adminCapId),
        tx.object(params.governanceId),
        tx.makeMoveVec({ type: "address", elements: approverAddresses }),
        tx.pure.u64(BigInt(params.newThreshold)),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  // ============================================================================
  // Governance V2 (in-package, calls kairo_policy_engine::policy_governance)
  // ============================================================================

  async createGovernanceV2(params: {
    stableId: string;
    approvers: string[];
    threshold: number;
    timelockDurationMs: number;
  }): Promise<{ governanceId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const stableIdBytes = Array.from(new TextEncoder().encode(params.stableId));
    const approverAddresses = params.approvers.map((a) => tx.pure.address(a));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::create_governance_v2`,
      arguments: [
        tx.pure.vector("u8", stableIdBytes),
        tx.makeMoveVec({ type: "address", elements: approverAddresses }),
        tx.pure.u64(BigInt(params.threshold)),
        tx.pure.u64(BigInt(params.timelockDurationMs)),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Governance V2 creation confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let governanceId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("PolicyGovernanceV2")
      ) {
        governanceId = String(change.objectId);
        break;
      }
    }
    if (!governanceId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("PolicyGovernanceV2")) {
            governanceId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    return { governanceId, digest: result.digest };
  }

  async setBindingGovernanceV2(params: {
    bindingObjectId: string;
    governanceId: string;
    mode?: number;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::set_binding_governance_v2`,
      arguments: [
        tx.object(params.bindingObjectId),
        tx.pure.address(params.governanceId),
        tx.pure.u8(params.mode ?? 0),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async activateBindingGovernanceV2(params: {
    bindingObjectId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::activate_binding_governance_v2`,
      arguments: [tx.object(params.bindingObjectId)],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async removeBindingGovernanceV2(params: {
    bindingObjectId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::remove_binding_governance_v2`,
      arguments: [tx.object(params.bindingObjectId)],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async proposeChangeV2(params: {
    governanceId: string;
    bindingId: string;
    targetVersionId: string;
  }): Promise<{ proposalId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::propose_change_v2`,
      arguments: [
        tx.object(params.governanceId),
        tx.pure.address(params.bindingId),
        tx.pure.address(params.targetVersionId),
        tx.object("0x6"),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Propose change V2 confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let proposalId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("PolicyChangeProposalV2")
      ) {
        proposalId = String(change.objectId);
        break;
      }
    }
    if (!proposalId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("PolicyChangeProposalV2")) {
            proposalId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    return { proposalId, digest: result.digest };
  }

  async approveProposalV2(params: {
    governanceId: string;
    proposalId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::approve_proposal_v2`,
      arguments: [
        tx.object(params.governanceId),
        tx.object(params.proposalId),
        tx.object("0x6"),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async executeProposalV2(params: {
    governanceId: string;
    proposalId: string;
  }): Promise<{ receiptId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const receipt = tx.moveCall({
      target: `${policyPkg}::policy_governance::execute_proposal_v2`,
      arguments: [
        tx.object(params.governanceId),
        tx.object(params.proposalId),
        tx.object("0x6"),
      ],
    });
    tx.transferObjects([receipt], adminAddress);

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Execute proposal V2 confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let receiptId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("GovernanceReceiptV2")
      ) {
        receiptId = String(change.objectId);
        break;
      }
    }
    if (!receiptId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("GovernanceReceiptV2")) {
            receiptId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    return { receiptId, digest: result.digest };
  }

  async governedReaffirmPolicyBindingV2(params: {
    bindingObjectId: string;
    receiptId: string;
    registryObjectId?: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const registryId = String(
      params.registryObjectId ?? (config.kairo as any).policyRegistryId ?? ""
    ).trim();
    if (!registryId.startsWith("0x")) {
      throw new Error("Missing KAIRO_POLICY_REGISTRY_ID (required for governed reaffirm)");
    }

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_registry::governed_reaffirm_policy_binding_v2`,
      arguments: [
        tx.object(params.bindingObjectId),
        tx.object(registryId),
        tx.object("0x6"),
        tx.object(params.receiptId),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async executeAndReaffirmV2(params: {
    governanceId: string;
    proposalId: string;
    bindingObjectId: string;
    registryObjectId?: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const registryId = String(
      params.registryObjectId ?? (config.kairo as any).policyRegistryId ?? ""
    ).trim();
    if (!registryId.startsWith("0x")) {
      throw new Error("Missing KAIRO_POLICY_REGISTRY_ID (required for governed reaffirm)");
    }

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const receipt = tx.moveCall({
      target: `${policyPkg}::policy_governance::execute_proposal_v2`,
      arguments: [
        tx.object(params.governanceId),
        tx.object(params.proposalId),
        tx.object("0x6"),
      ],
    });

    tx.moveCall({
      target: `${policyPkg}::policy_registry::governed_reaffirm_policy_binding_v2`,
      arguments: [
        tx.object(params.bindingObjectId),
        tx.object(registryId),
        tx.object("0x6"),
        receipt,
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async cancelProposalV2(params: {
    proposalId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::cancel_proposal_v2`,
      arguments: [tx.object(params.proposalId)],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async updateApproversV2(params: {
    adminCapId: string;
    governanceId: string;
    newApprovers: string[];
    newThreshold: number;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const approverAddresses = params.newApprovers.map((a) => tx.pure.address(a));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::update_approvers_v2`,
      arguments: [
        tx.object(params.adminCapId),
        tx.object(params.governanceId),
        tx.makeMoveVec({ type: "address", elements: approverAddresses }),
        tx.pure.u64(BigInt(params.newThreshold)),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  // ============================================================================
  // Recovery (calls kairo_policy_engine::policy_governance + vault)
  // ============================================================================

  async createRecoveryConfig(params: {
    dwalletId: string;
    stableId: string;
    guardians: string[];
    threshold: number;
    timelockDurationMs: number;
  }): Promise<{ configId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const dwalletIdBytes = Array.from(new TextEncoder().encode(params.dwalletId));
    const stableIdBytes = Array.from(new TextEncoder().encode(params.stableId));
    const guardianAddresses = params.guardians.map((a) => tx.pure.address(a));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::create_recovery_config`,
      arguments: [
        tx.pure.vector("u8", dwalletIdBytes),
        tx.pure.vector("u8", stableIdBytes),
        tx.makeMoveVec({ type: "address", elements: guardianAddresses }),
        tx.pure.u64(BigInt(params.threshold)),
        tx.pure.u64(BigInt(params.timelockDurationMs)),
        tx.object("0x6"),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Recovery config creation confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let configId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("RecoveryConfig")
      ) {
        configId = String(change.objectId);
        break;
      }
    }
    if (!configId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("RecoveryConfig")) {
            configId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    return { configId, digest: result.digest };
  }

  async proposeRecovery(params: {
    configId: string;
  }): Promise<{ proposalId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::propose_recovery`,
      arguments: [
        tx.object(params.configId),
        tx.object("0x6"),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Recovery proposal creation confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let proposalId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("RecoveryProposal")
      ) {
        proposalId = String(change.objectId);
        break;
      }
    }
    if (!proposalId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("RecoveryProposal")) {
            proposalId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    return { proposalId, digest: result.digest };
  }

  async approveRecovery(params: {
    configId: string;
    proposalId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::policy_governance::approve_recovery`,
      arguments: [
        tx.object(params.configId),
        tx.object(params.proposalId),
        tx.object("0x6"),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  async executeRecovery(params: {
    configId: string;
    proposalId: string;
  }): Promise<{ receiptId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const receipt = tx.moveCall({
      target: `${policyPkg}::policy_governance::execute_recovery`,
      arguments: [
        tx.object(params.configId),
        tx.object(params.proposalId),
        tx.object("0x6"),
      ],
    });
    tx.transferObjects([receipt], adminAddress);

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Recovery execution confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let receiptId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("RecoveryReceiptV1")
      ) {
        receiptId = String(change.objectId);
        break;
      }
    }
    if (!receiptId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("RecoveryReceiptV1")) {
            receiptId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    return { receiptId, digest: result.digest };
  }

  async completeRecovery(params: {
    vaultObjectId: string;
    receiptId: string;
    bindingObjectId: string;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    tx.moveCall({
      target: `${policyPkg}::dwallet_policy_vault::complete_recovery`,
      arguments: [
        tx.object(params.vaultObjectId),
        tx.object(params.receiptId),
        tx.object(params.bindingObjectId),
        tx.object("0x6"),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }

  // ============================================================================
  // PolicyV4 (calls kairo_policy_engine::policy_registry)
  // ============================================================================

  private static hexToBytes(hex: string): number[] {
    const clean = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
    if (clean.length > 0 && !/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error(`Invalid hex string: contains non-hex characters`);
    }
    if (clean.length % 2 !== 0) {
      throw new Error(`Invalid hex string: odd length (${clean.length})`);
    }
    return Array.from(Buffer.from(clean, "hex"));
  }

  private async checkDwalletVaultRegistration(bindingObjectId: string): Promise<void> {
    const bindingObj = await this.client.getObject({
      id: bindingObjectId,
      options: { showType: true, showContent: true },
    });
    if (!bindingObj.data) {
      throw new Error(`PolicyBinding ${bindingObjectId} does not exist on-chain`);
    }

    const fields = (bindingObj.data as any)?.content?.fields;
    const dwalletIdRaw = fields?.dwallet_id;
    if (!dwalletIdRaw) {
      throw new Error(`PolicyBinding ${bindingObjectId} has no dwallet_id field`);
    }

    let dwalletIdBytes: number[];
    if (Array.isArray(dwalletIdRaw)) {
      dwalletIdBytes = dwalletIdRaw;
    } else if (typeof dwalletIdRaw === "object" && dwalletIdRaw.fields) {
      dwalletIdBytes = Array.isArray(dwalletIdRaw.fields) ? dwalletIdRaw.fields : [];
    } else {
      dwalletIdBytes = [];
    }

    const vaultObjectId = config.kairo.policyVaultObjectId;
    const policyPkg = this.getPolicyPkg();
    if (!vaultObjectId?.startsWith("0x") || !policyPkg) return;

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.moveCall({
      target: `${policyPkg}::dwallet_policy_vault::has_dwallet`,
      arguments: [
        tx.object(vaultObjectId),
        tx.pure(bcs.vector(bcs.u8()).serialize(dwalletIdBytes).toBytes()),
      ],
    });

    const result = await this.client.devInspectTransactionBlock({
      transactionBlock: tx,
      sender: adminAddress,
    });

    let isRegistered = false;
    if (result.results && result.results[0]?.returnValues) {
      const returnVal = result.results[0].returnValues[0];
      if (returnVal && returnVal[0]) {
        const bytes = new Uint8Array(returnVal[0] as number[]);
        isRegistered = bytes[0] === 1;
      }
    }

    if (!isRegistered) {
      const dwalletIdStr = new TextDecoder().decode(Uint8Array.from(dwalletIdBytes));
      throw new Error(
        `dWallet ${dwalletIdStr} (from binding ${bindingObjectId}) is not registered in the vault. ` +
        `Register it via POST /api/vault/provision first.`
      );
    }
  }

  async createPolicyV4(params: {
    stableId: string;
    version: string;
    expiresAtMs?: number;
    allowNamespaces?: number[];
    allowChainIds?: Array<{ namespace: number; chainId: string }>;
    allowDestinations?: string[];
    denyDestinations?: string[];
    rules: Array<{ ruleType: number; namespace: number; params: string }>;
  }): Promise<{ policyObjectId: string; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const stableIdBytes = Array.from(new TextEncoder().encode(params.stableId));
    const versionBytes = Array.from(new TextEncoder().encode(params.version));
    const allowNs = params.allowNamespaces ?? [];

    const chainIdVec: any[] = [];
    for (const cid of params.allowChainIds ?? []) {
      const chainIdBytes = DKGExecutorService.hexToBytes(cid.chainId);
      chainIdVec.push(
        tx.moveCall({
          target: `${policyPkg}::policy_registry::create_chain_id_v3`,
          arguments: [
            tx.pure.u8(cid.namespace),
            tx.pure.vector("u8", chainIdBytes),
          ],
        })
      );
    }

    const ruleVec: any[] = [];
    for (const rule of params.rules) {
      const ruleParams = DKGExecutorService.hexToBytes(rule.params);
      ruleVec.push(
        tx.moveCall({
          target: `${policyPkg}::policy_registry::create_generic_rule`,
          arguments: [
            tx.pure.u8(rule.ruleType),
            tx.pure.u8(rule.namespace),
            tx.pure.vector("u8", ruleParams),
          ],
        })
      );
    }

    // Auto-populate allow_destinations from rules whose params are 20-byte addresses.
    // The Move contract checks allow_destinations for destination enforcement, not the
    // generic rules array. Without this, rules-only policies have empty allow_destinations
    // and the contract sees nothing to deny → allowed: true for everything.
    const mergedAllowDest = [...(params.allowDestinations ?? [])];
    for (const rule of params.rules) {
      const raw = rule.params.startsWith("0x") ? rule.params.slice(2) : rule.params;
      if (raw.length === 40 && !mergedAllowDest.includes(rule.params)) {
        mergedAllowDest.push(rule.params);
      }
    }

    const allowDest = mergedAllowDest.map((d) =>
      tx.pure.vector("u8", DKGExecutorService.hexToBytes(d))
    );
    const denyDest = (params.denyDestinations ?? []).map((d) =>
      tx.pure.vector("u8", DKGExecutorService.hexToBytes(d))
    );

    tx.moveCall({
      target: `${policyPkg}::policy_registry::create_and_share_policy_v4`,
      arguments: [
        tx.pure.vector("u8", stableIdBytes),
        tx.pure.vector("u8", versionBytes),
        tx.pure.u64(BigInt(params.expiresAtMs ?? 0)),
        tx.pure.vector("u8", allowNs),
        tx.makeMoveVec({
          type: `${policyPkg}::policy_registry::ChainIdV3`,
          elements: chainIdVec,
        }),
        tx.makeMoveVec({ type: "vector<u8>", elements: allowDest }),
        tx.makeMoveVec({ type: "vector<u8>", elements: denyDest }),
        tx.makeMoveVec({
          type: `${policyPkg}::policy_registry::GenericRule`,
          elements: ruleVec,
        }),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    const txResult = await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true, showObjectChanges: true },
    });

    let policyObjectId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("PolicyV4")
      ) {
        policyObjectId = String(change.objectId);
        break;
      }
    }
    if (!policyObjectId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("PolicyV4")) {
            policyObjectId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    pushPolicyAudit({
      kind: "policy_create",
      createdAtMs: Date.now(),
      digest: result.digest,
      objectId: policyObjectId,
      meta: { stableId: params.stableId, version: params.version },
    });

    return { policyObjectId, digest: result.digest };
  }

  async mintReceiptV4(params: {
    policyObjectId: string;
    bindingObjectId: string;
    namespace: number;
    chainId: string;
    intentHashHex: string;
    destinationHex: string;
    nativeValueHex: string;
    contextDataHex?: string;
    registryObjectId?: string;
  }): Promise<{ receiptId: string; allowed: boolean; digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    await this.checkDwalletVaultRegistration(params.bindingObjectId);

    const registryId = String(
      params.registryObjectId ?? (config.kairo as any).policyRegistryId ?? ""
    ).trim();
    if (!registryId.startsWith("0x")) {
      throw new Error("Missing KAIRO_POLICY_REGISTRY_ID");
    }

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const chainIdBytes = DKGExecutorService.hexToBytes(params.chainId);
    const intentBytes = DKGExecutorService.hexToBytes(params.intentHashHex);
    const destBytes = DKGExecutorService.hexToBytes(params.destinationHex);
    const valueBytes = DKGExecutorService.hexToBytes(params.nativeValueHex);
    const contextBytes = DKGExecutorService.hexToBytes(params.contextDataHex ?? "");

    const receipt = tx.moveCall({
      target: `${policyPkg}::policy_registry::mint_receipt_v4`,
      arguments: [
        tx.object(registryId),
        tx.object(params.policyObjectId),
        tx.object(params.bindingObjectId),
        tx.object("0x6"),
        tx.pure.u8(params.namespace),
        tx.pure.vector("u8", chainIdBytes),
        tx.pure.vector("u8", intentBytes),
        tx.pure.vector("u8", destBytes),
        tx.pure.vector("u8", valueBytes),
        tx.pure.vector("u8", contextBytes),
      ],
    });
    tx.transferObjects([receipt], adminAddress);

    const result = await this.executeSuiTransaction(tx);
    await withTimeout(
      this.client.waitForTransaction({
        digest: result.digest,
        options: { showEffects: true },
      }),
      TIMEOUTS.TRANSACTION_WAIT,
      "Policy receipt V4 mint confirmation"
    );
    const txResult = await this.client.getTransactionBlock({
      digest: result.digest,
      options: { showObjectChanges: true, showEffects: true },
    });

    let receiptId = "";
    for (const change of (txResult as any)?.objectChanges ?? []) {
      if (
        change.type === "created" &&
        String(change.objectType ?? "").includes("PolicyReceiptV4")
      ) {
        receiptId = String(change.objectId);
        break;
      }
    }
    if (!receiptId) {
      const created = ((txResult as any)?.effects?.created ?? []) as Array<any>;
      for (const c of created) {
        const id = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!id.startsWith("0x")) continue;
        try {
          const obj = await this.client.getObject({ id, options: { showType: true } });
          const t = String((obj as any)?.data?.type ?? "");
          if (t.includes("PolicyReceiptV4")) {
            receiptId = id;
            break;
          }
        } catch {
          // ignore
        }
      }
    }

    // Read the on-chain `allowed` field from the created receipt.
    // Retry with backoff to handle indexer lag after waitForTransaction.
    let allowed = false;
    if (receiptId) {
      const RETRY_DELAYS = [200, 500, 1000];
      for (let attempt = 0; attempt <= RETRY_DELAYS.length; attempt++) {
        try {
          const receiptObj = await this.client.getObject({
            id: receiptId,
            options: { showContent: true },
          });
          const fields = (receiptObj.data as any)?.content?.fields;
          if (fields && "allowed" in fields) {
            allowed = Boolean(fields["allowed"]);
            break;
          }
        } catch {
          // ignore and retry
        }
        if (attempt < RETRY_DELAYS.length) {
          await new Promise((r) => setTimeout(r, RETRY_DELAYS[attempt]));
        }
      }
    }

    pushPolicyAudit({
      kind: "receipt_mint",
      createdAtMs: Date.now(),
      digest: result.digest,
      objectId: receiptId,
      meta: {
        policyObjectId: params.policyObjectId,
        bindingObjectId: params.bindingObjectId,
        namespace: params.namespace,
        allowed,
      },
    });

    return { receiptId, allowed, digest: result.digest };
  }

  async policyGatedAuthorizeSignV4(params: {
    vaultObjectId: string;
    receiptId: string;
    bindingObjectId: string;
    dwalletId: string;
    intentDigestHex: string;
    namespace: number;
    chainId: string;
    destinationHex: string;
    receiptTtlMs?: number;
  }): Promise<{ digest: string }> {
    await this.initPromise;
    const policyPkg = this.getPolicyPkg();

    const tx = new Transaction();
    const adminAddress = this.adminKeypair.toSuiAddress();
    tx.setSender(adminAddress);
    await this.setAdminGas(tx, adminAddress, BigInt(config.sui.gasBudgetsMist.sign));

    const dwalletIdBytes = Array.from(new TextEncoder().encode(params.dwalletId));
    const intentBytes = DKGExecutorService.hexToBytes(params.intentDigestHex);
    const chainIdBytes = DKGExecutorService.hexToBytes(params.chainId);
    const destBytes = DKGExecutorService.hexToBytes(params.destinationHex);

    tx.moveCall({
      target: `${policyPkg}::dwallet_policy_vault::policy_gated_authorize_sign_v4`,
      arguments: [
        tx.object(params.vaultObjectId),
        tx.object(params.receiptId),
        tx.object(params.bindingObjectId),
        tx.object("0x6"),
        tx.pure.vector("u8", dwalletIdBytes),
        tx.pure.vector("u8", intentBytes),
        tx.pure.u8(params.namespace),
        tx.pure.vector("u8", chainIdBytes),
        tx.pure.vector("u8", destBytes),
        tx.pure.u64(BigInt(params.receiptTtlMs ?? 0)),
      ],
    });

    const result = await this.executeSuiTransaction(tx);
    await this.client.waitForTransaction({
      digest: result.digest,
      options: { showEffects: true },
    });

    return { digest: result.digest };
  }
}

// Export singleton instance
export const dkgExecutor = new DKGExecutorService();
