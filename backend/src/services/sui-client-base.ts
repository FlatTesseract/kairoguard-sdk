/**
 * SuiClientBase - Shared infrastructure for all Sui/Ika services
 *
 * Provides common dependencies and utilities that all domain services need:
 * - SuiClient for chain interaction
 * - IkaClient for dWallet operations
 * - Admin keypair for signing transactions
 * - Transaction execution helpers
 */

import { SuiClient } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { getNetworkConfig, IkaClient, type IkaConfig } from "@ika.xyz/sdk";
import { config } from "../config.js";
import { logger } from "../logger.js";

/**
 * Get the network-specific RPC URL for Sui
 */
export function getSuiRpcUrl(network: "mainnet" | "testnet"): string {
  if (config.sui.rpcUrl) return config.sui.rpcUrl;
  return network === "mainnet"
    ? "https://ikafn-on-sui-2-mainnet.ika-network.net/"
    : "https://rpc.testnet.sui.io";
}

/**
 * Initialize the IkaConfig with testnet overrides if needed
 */
export function initIkaConfig(network: "mainnet" | "testnet"): IkaConfig {
  return getNetworkConfig(network);
}

/**
 * Create admin keypair from config with helpful error message
 */
export function createAdminKeypair(): Ed25519Keypair {
  try {
    return Ed25519Keypair.fromSecretKey(config.sui.adminSecretKey);
  } catch (err) {
    const msg = String((err as any)?.message ?? err ?? "unknown error");
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
}

/**
 * SuiClientBase provides shared Sui/Ika infrastructure for all services.
 *
 * Services receive this base class via constructor injection for:
 * - Testability (mock the base for unit tests)
 * - Single source of truth for client initialization
 * - Shared transaction execution logic
 */
export class SuiClientBase {
  readonly client: SuiClient;
  readonly ikaConfig: IkaConfig;
  readonly ikaClient: IkaClient;
  readonly adminKeypair: Ed25519Keypair;
  readonly network: "mainnet" | "testnet";

  /**
   * Promise that resolves when async initialization is complete.
   * Services should await this before performing operations.
   */
  readonly initPromise: Promise<void>;

  constructor() {
    this.network = config.sui.network;
    const rpcUrl = getSuiRpcUrl(this.network);

    this.client = new SuiClient({ url: rpcUrl });
    this.ikaConfig = initIkaConfig(this.network);
    this.ikaClient = new IkaClient({
      suiClient: this.client,
      config: this.ikaConfig,
    });
    this.adminKeypair = createAdminKeypair();

    // Kick off async config validation
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
        network: this.network,
      },
      "SuiClientBase initialized"
    );
  }

  /**
   * Get the admin's Sui address
   */
  getAdminAddress(): string {
    return this.adminKeypair.toSuiAddress();
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
  async executeSuiTransaction(tx: Transaction): Promise<{ digest: string }> {
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
   * Pin gas payment coin and budget for admin-signed Sui transactions.
   * This avoids failures when the SDK auto-selects a small gas coin.
   */
  async setAdminGas(
    tx: Transaction,
    adminAddress: string,
    gasBudgetMist: bigint
  ): Promise<void> {
    // Keep this simple: pick the largest SUI coin object as gas payment
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
        `Admin address has no SUI coins to pay gas (admin=${adminAddress}). Fund it on Sui ${this.network}.`
      );
    }

    const balance = BigInt(gasCoin.balance);
    if (balance < gasBudgetMist) {
      // The budget is a MAX; gas used will be lower, but Sui requires coin balance >= budget
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
   * Detect the IKA coin type for the current network.
   * This is cached after first call.
   */
  private ikaCoinTypeCache: string | null = null;

  async detectIkaCoinType(): Promise<string> {
    if (this.ikaCoinTypeCache) {
      return this.ikaCoinTypeCache;
    }
    // Try to get from treasury cap first
    const treasuryCapId = (this.ikaConfig.objects as any).ikaTreasuryCap?.objectID;
    if (treasuryCapId) {
      const obj = await this.client.getObject({
        id: treasuryCapId,
        options: { showType: true },
      });
      const typeStr = (obj?.data as any)?.type as string | undefined;
      if (typeStr) {
        // Treasury cap type is like "0x2::coin::TreasuryCap<0x...::ika::IKA>"
        const match = typeStr.match(/<([^>]+)>/);
        if (match?.[1]) {
          this.ikaCoinTypeCache = match[1];
          return this.ikaCoinTypeCache;
        }
      }
    }
    // Fallback: detect from balances
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

  /**
   * Select an IKA payment coin for protocol fees.
   * Returns the object ID of the largest IKA coin.
   *
   * @param args.owner - The address to check for IKA coins
   * @param args.requiredIka - Optional minimum required balance
   * @param args.context - Description of the operation (for error messages)
   * @returns The coin object ID
   * @throws Error if no suitable coin is found
   */
  async selectIkaPaymentCoinOrThrow(args: {
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

  /**
   * Validate configuration at startup.
   * Ensures the admin has IKA coins and required packages exist.
   */
  private async validateConfigOrThrow(): Promise<void> {
    try {
      // Validate that the admin has an IKA coin type available
      const ikaCoinType = await this.detectIkaCoinType();
      const ikaCoins = await this.client.getCoins({
        owner: this.adminKeypair.toSuiAddress(),
        coinType: ikaCoinType,
      });
      if (!(ikaCoins.data ?? []).length) {
        throw new Error(
          `No IKA coin objects found for admin=${this.adminKeypair.toSuiAddress()} on Sui ${this.network} (coinType=${ikaCoinType}).\n` +
            `Fund the admin address with IKA on this network.`
        );
      }

      // Validate Ika package ids
      const pkgIds = [
        this.ikaConfig.packages.ikaPackage,
        this.ikaConfig.packages.ikaCommonPackage,
        this.ikaConfig.packages.ikaSystemPackage,
        this.ikaConfig.packages.ikaDwallet2pcMpcPackage,
      ];
      for (const pid of pkgIds) {
        const p = await this.client.getObject({
          id: pid,
          options: { showType: true },
        });
        const errCode = (p as any)?.error?.code as string | undefined;
        if (errCode === "notExists") {
          throw new Error(
            `Ika package id does not exist on Sui ${this.network}: ${pid}\n` +
              `This usually means the SDK's network config is stale or the backend is pointing at the wrong network RPC.`
          );
        }
        const t = (p as any)?.data?.type as string | undefined;
        if (t !== "package") {
          throw new Error(
            `Ika package id is not a package object on Sui ${this.network}: ${pid} (type=${t ?? "unknown"})`
          );
        }
      }
    } catch (err) {
      const msg = String((err as any)?.message ?? err ?? "unknown error");
      throw new Error(`Backend config validation failed: ${msg}`);
    }
  }
}

/**
 * Singleton instance of SuiClientBase for use across services.
 * Services should use this unless they need a custom instance for testing.
 */
let _sharedInstance: SuiClientBase | null = null;

export function getSharedSuiClientBase(): SuiClientBase {
  if (!_sharedInstance) {
    _sharedInstance = new SuiClientBase();
  }
  return _sharedInstance;
}

/**
 * Reset the shared instance (for testing)
 */
export function resetSharedSuiClientBase(): void {
  _sharedInstance = null;
}
