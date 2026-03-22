/**
 * KairoClient -- the main entry point for agents.
 *
 * Usage:
 *   const kairo = new KairoClient({
 *     apiKey: "ka_abc123...",
 *   });
 *   const wallet = await kairo.createWallet();
 *   // { walletId: "0xabc...", address: "0x742d...", curve: "secp256k1" }
 */

import {
  BackendClient,
  type CreatePolicyV4Params,
  type GovernanceProposalInfo,
} from "./backend.js";
import { KeyStore, type WalletRecord } from "./keystore.js";
import {
  Curve,
  fetchProtocolParams,
  deriveEncryptionKeys,
  generateSeed,
  generateSessionIdentifier,
  runDKG,
  computeUserOutputSignature,
  fetchDWallet,
  waitForDWalletState,
  type SupportedCurve,
} from "./ika-protocol.js";
import { Hash, SignatureAlgorithm, createUserSignMessageWithPublicOutput } from "@ika.xyz/sdk";
import { computeEvmIntentFromUnsignedTxBytes } from "./evmIntent.js";
import type { Hex } from "./types.js";
import {
  keccak256,
  recoverTransactionAddress,
  serializeTransaction,
  type TransactionSerializableEIP1559,
} from "viem";

export interface KairoClientOpts {
  apiKey: string;
  /** Kairo backend URL. Defaults to production if omitted. */
  backendUrl?: string;
  /** Local directory for secret share storage. Defaults to ~/.kairo/keys */
  storePath?: string;
  /** Sui RPC URL for fetching Ika protocol params. Defaults to backend's proxy, then SUI_RPC_URL env, then public testnet. */
  suiRpcUrl?: string;
  /** Sui network. Defaults to "testnet". */
  network?: "testnet" | "mainnet";
  /** Optional chainId -> EVM RPC URL mapping used by signEvm/broadcast/getBalance. */
  evmRpcUrls?: Record<number, string>;
}

export interface CreateWalletOpts {
  /** Key curve. Defaults to "secp256k1" (Ethereum). */
  curve?: SupportedCurve;
  /** Policy object ID to bind during provisioning. */
  policyObjectId?: string;
  /** Human-readable label for the binding (derived from policy if omitted). */
  stableId?: string;
}

export interface WalletInfo {
  walletId: string;
  address: string;
  curve: string;
  bindingObjectId?: string;
  createdAt: number;
}

export interface PresignResult {
  requestId: string;
  presignId: string;
  presignBytes: Uint8Array;
}

export interface SignResult {
  requestId: string;
  signId?: string;
  presignId: string;
  signatureHex: Hex;
}

export interface SignEvmParams {
  walletId: string;
  to: Hex;
  value: bigint | number | string;
  chainId: number;
  data?: Hex;
  rpcUrl?: string;
}

export interface ProposePolicyUpdateParams {
  walletId: string;
  governanceId: string;
  stableId: string;
  version: string;
  expiresAtMs?: number;
  allowNamespaces?: number[];
  allowChainIds?: Array<{ namespace: number; chainId: string }>;
  allowDestinations?: string[];
  denyDestinations?: string[];
  rules: Array<{ ruleType: number; namespace?: number; params: string }>;
  registryObjectId?: string;
  note?: string;
}

export interface PolicyUpdateProposalResult {
  walletId: string;
  governanceId: string;
  bindingObjectId: string;
  policyObjectId: string;
  policyVersionObjectId: string;
  proposalId: string;
  policyDigest: string;
  registerDigest: string;
  proposalDigest: string;
}

export interface ApprovePolicyUpdateParams {
  governanceId: string;
  proposalId: string;
}

export interface ExecutePolicyUpdateParams {
  walletId: string;
  governanceId: string;
  proposalId: string;
}

export interface PolicyUpdateStatus {
  proposal: GovernanceProposalInfo;
  threshold?: number;
  timelockDurationMs?: number;
  approvalsCollected: number;
  approvalsNeeded?: number;
  state: "awaiting_approvals" | "awaiting_timelock" | "ready_to_execute" | "executed" | "cancelled";
}

interface SignPolicyContext {
  namespace: number;
  chainId: number;
  intentHashHex: Hex;
  destinationHex: Hex;
  nativeValue: bigint;
  contextDataHex?: Hex;
}

interface SignOpts {
  presignId?: string;
  presignBytes?: Uint8Array;
  policyContext?: SignPolicyContext;
  ethTx?: {
    to: string;
    value: string;
    nonce: number;
    gasLimit: string;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
    chainId: number;
    from: string;
  };
  policyVersion?: string;
}

const FALLBACK_SUI_RPC = "https://fullnode.testnet.sui.io:443";

async function testRpcEndpoint(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "suix_getLatestSuiSystemState", params: [] }),
    });
    if (!res.ok) return false;
    const json = await res.json() as Record<string, unknown>;
    return json.jsonrpc === "2.0" && "result" in json;
  } catch {
    return false;
  }
}

function isRateLimitError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.includes("429") || message.includes("Too Many Requests");
}

async function withRetry<T>(
  fn: () => Promise<T>,
  opts?: {
    maxRetries?: number;
    baseDelayMs?: number;
    label?: string;
  },
): Promise<T> {
  const maxRetries = opts?.maxRetries ?? 3;
  const baseDelayMs = opts?.baseDelayMs ?? 2000;
  const label = opts?.label ?? "operation";

  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const lastAttempt = attempt >= maxRetries;
      if (lastAttempt || !isRateLimitError(err)) {
        throw err;
      }

      const delayMs = baseDelayMs * 2 ** attempt;
      console.warn(
        `[KairoSDK] ${label} rate-limited (attempt ${attempt + 1}/${maxRetries + 1}); retrying in ${
          delayMs / 1000
        }s...`,
      );
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}
const DEFAULT_EVM_RPC_URLS: Record<number, string> = {
  1: "https://rpc.ankr.com/eth",
  11155111: "https://rpc.ankr.com/eth_sepolia",
};
const DKG_POLL_INTERVAL_MS = 2_000;
const DKG_POLL_TIMEOUT_MS = 120_000;
const PRESIGN_POLL_INTERVAL_MS = 2_000;
const PRESIGN_POLL_TIMEOUT_MS = 120_000;
const SIGN_POLL_INTERVAL_MS = 2_000;
const SIGN_POLL_TIMEOUT_MS = 180_000;
const ACTIVATION_POLL_INTERVAL_MS = 3_000;
const ACTIVATION_POLL_TIMEOUT_MS = 90_000;

function curveToNumber(curve: SupportedCurve): number {
  return curve === "ed25519" ? 2 : 0;
}

export class KairoClient {
  private backend: BackendClient;
  private store: KeyStore;
  private suiRpcUrl: string;
  private network: "testnet" | "mainnet";
  private evmRpcUrls: Record<number, string>;

  constructor(opts: KairoClientOpts) {
    this.backend = new BackendClient({ backendUrl: opts.backendUrl, apiKey: opts.apiKey });
    this.store = new KeyStore(opts.storePath);
    this.network = opts.network ?? "testnet";
    this.evmRpcUrls = { ...DEFAULT_EVM_RPC_URLS, ...(opts.evmRpcUrls ?? {}) };

    // Sui RPC priority: explicit option > env var > will resolve lazily (proxy or fallback)
    this.suiRpcUrl =
      opts.suiRpcUrl ??
      process.env.SUI_RPC_URL?.trim() ??
      ""; // Empty means we'll resolve lazily
  }

  /**
   * Resolve Sui RPC URL, testing backend proxy first and falling back to public RPC.
   */
  private async resolveSuiRpcUrl(): Promise<string> {
    if (this.suiRpcUrl) return this.suiRpcUrl;

    // Try backend proxy first (uses Shinami)
    const backendProxy = `${this.backend.getBaseUrl()}/api/sui-rpc`;
    if (await testRpcEndpoint(backendProxy)) {
      this.suiRpcUrl = backendProxy;
      return this.suiRpcUrl;
    }

    // Fall back to public RPC
    console.warn("[KairoSDK] Backend RPC proxy not available, falling back to public Sui RPC");
    this.suiRpcUrl = FALLBACK_SUI_RPC;
    return this.suiRpcUrl;
  }

  /**
   * Create a new dWallet. Runs DKG on the agent's machine, submits to backend,
   * and optionally provisions the wallet in the vault.
   *
   * The agent's secret share is stored locally and never sent to the server.
   */
  async createWallet(opts?: CreateWalletOpts): Promise<WalletInfo> {
    const curve: SupportedCurve = opts?.curve ?? "secp256k1";

    // 1. Generate encryption seed and derive keys
    const seed = generateSeed();
    const encryptionKeys = await deriveEncryptionKeys(seed, curve);

    // 2. Fetch protocol params from Ika network (runs locally, avoids backend memory limit)
    const rpcUrl = await this.resolveSuiRpcUrl();
    const protocolParams = await withRetry(
      () => fetchProtocolParams(curve, rpcUrl, this.network),
      { label: "fetchProtocolParams" },
    );

    // 3. Generate session identifier
    const sessionIdentifier = generateSessionIdentifier();

    // 4. Get backend admin address (DKG must target the admin signer)
    const health = await this.backend.getHealth();
    const adminAddress = health.adminAddress;

    // 5. Run client-side DKG
    const dkgOutputs = await runDKG({
      protocolPublicParameters: protocolParams,
      curve,
      encryptionKey: encryptionKeys.encryptionKey,
      sessionIdentifier,
      adminAddress,
    });

    // 6. Submit DKG to backend
    const encKeySignature = await encryptionKeys.getEncryptionKeySignature();
    const submitResult = await this.backend.submitDKG({
      userPublicOutput: dkgOutputs.userPublicOutput,
      userDkgMessage: dkgOutputs.userDKGMessage,
      encryptedUserShareAndProof: dkgOutputs.encryptedUserShareAndProof,
      sessionIdentifier: Array.from(sessionIdentifier),
      signerPublicKey: Array.from(encryptionKeys.getPublicKey().toRawBytes()),
      encryptionKeyAddress: encryptionKeys.getSuiAddress(),
      encryptionKey: Array.from(encryptionKeys.encryptionKey),
      encryptionKeySignature: Array.from(encKeySignature),
      curve: curveToNumber(curve),
    });

    if (!submitResult.success) {
      throw new Error(`DKG submit failed: ${submitResult.requestId}`);
    }

    // 7. Poll for DKG completion
    const dkgResult = await this.pollDKGStatus(submitResult.requestId);

    const walletId = dkgResult.dWalletObjectId!;
    const address = (curve === "ed25519" ? dkgResult.solanaAddress : dkgResult.ethereumAddress) ?? "";
    const encryptedShareId = dkgResult.encryptedUserSecretKeyShareId ?? "";

    // 8. Save secret share locally BEFORE activation so it is never lost
    const record: WalletRecord = {
      walletId,
      dWalletCapId: dkgResult.dWalletCapObjectId,
      address,
      curve,
      seed: Array.from(seed),
      userSecretKeyShare: dkgOutputs.userSecretKeyShare,
      userPublicOutput: dkgOutputs.userPublicOutput,
      encryptedUserSecretKeyShareId: encryptedShareId,
      bindingObjectId: undefined,
      policyObjectId: opts?.policyObjectId,
      createdAt: Date.now(),
    };
    this.store.save(record);

    // 9. Activate the dWallet (sign to accept encrypted key share)
    if (encryptedShareId) {
      await this.activateWallet(walletId, encryptedShareId, encryptionKeys, dkgOutputs.userPublicOutput);
    }

    // 10. Provision into vault (binding + registration) if policy is provided
    let bindingObjectId: string | undefined;
    if (opts?.policyObjectId) {
      const provisionResult = await this.provision(walletId, opts.policyObjectId, opts.stableId);
      bindingObjectId = provisionResult.bindingObjectId;
    }

    return {
      walletId,
      address,
      curve,
      bindingObjectId,
      createdAt: record.createdAt,
    };
  }

  /** List all wallets in local key store. */
  listWallets(): WalletInfo[] {
    return this.store.list().map((r) => ({
      walletId: r.walletId,
      address: r.address,
      curve: r.curve,
      bindingObjectId: r.bindingObjectId,
      createdAt: r.createdAt,
    }));
  }

  /** Get a wallet from local key store by ID. */
  getWallet(walletId: string): WalletInfo | null {
    const r = this.store.load(walletId);
    if (!r) return null;
    return {
      walletId: r.walletId,
      address: r.address,
      curve: r.curve,
      bindingObjectId: r.bindingObjectId,
      createdAt: r.createdAt,
    };
  }

  /**
   * Provision an existing local wallet into the policy vault.
   * Persists binding/policy metadata to local keystore.
   */
  async provision(
    walletId: string,
    policyObjectId: string,
    stableId?: string,
  ): Promise<{ bindingObjectId: string; digest: string }> {
    const wallet = this.requireWalletRecord(walletId);
    if (!policyObjectId?.startsWith("0x")) {
      throw new Error("policyObjectId must be a valid 0x object id");
    }
    const result = await this.backend.provision({
      dwalletObjectId: walletId,
      policyObjectId,
      stableId: stableId ?? `agent-wallet-${walletId.slice(0, 8)}`,
    });
    const bindingObjectId = String(result.bindingObjectId ?? "");
    if (!bindingObjectId.startsWith("0x")) {
      throw new Error("Provision succeeded but no bindingObjectId was returned");
    }
    this.store.save({
      ...wallet,
      bindingObjectId,
      policyObjectId,
    });
    return { bindingObjectId, digest: result.digest };
  }

  async reaffirmBinding(walletId: string): Promise<{ digest: string; activeVersionObjectId?: string }> {
    const wallet = this.requireWalletRecord(walletId);
    if (!wallet.bindingObjectId?.startsWith("0x")) {
      throw new Error("Wallet is missing bindingObjectId. Provision the wallet before reaffirming.");
    }
    try {
      const result = await this.backend.reaffirmPolicyBinding({
        bindingObjectId: wallet.bindingObjectId,
      });
      return {
        digest: result.digest,
        activeVersionObjectId: result.activeVersionObjectId,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const governedGuardTriggered =
        /binding is governed/i.test(message) ||
        /requires governance receipt flow/i.test(message) ||
        /execute-and-reaffirm/i.test(message);
      if (governedGuardTriggered) {
        throw new Error(
          "Binding is governed and cannot be directly reaffirmed. Complete governance execute-and-reaffirm first, then retry signing.",
        );
      }
      throw error;
    }
  }

  /**
   * Governance-first policy update: creates a new policy + version, then proposes
   * a change for approvers. This method does NOT execute/reaffirm directly.
   */
  async updatePolicy(params: ProposePolicyUpdateParams): Promise<PolicyUpdateProposalResult> {
    return this.proposePolicyUpdate(params);
  }

  /**
   * Create and register a new policy version, then create governance proposal.
   * This is the safe default for agents so policy changes require approvers.
   */
  async proposePolicyUpdate(
    params: ProposePolicyUpdateParams
  ): Promise<PolicyUpdateProposalResult> {
    const wallet = this.requireWalletRecord(params.walletId);
    if (!wallet.bindingObjectId) {
      throw new Error(
        "Wallet is missing bindingObjectId. Provision the wallet before proposing policy updates."
      );
    }

    const createBody: CreatePolicyV4Params = {
      stableId: params.stableId,
      version: params.version,
      expiresAtMs: params.expiresAtMs,
      allowNamespaces: params.allowNamespaces,
      allowChainIds: params.allowChainIds,
      allowDestinations: params.allowDestinations,
      denyDestinations: params.denyDestinations,
      rules: params.rules,
    };
    const created = await this.backend.createPolicyV4(createBody);
    if (!created.success || !created.policyObjectId?.startsWith("0x")) {
      throw new Error(created.error ?? "Failed to create policy");
    }

    const registered = await this.backend.registerPolicyVersionFromPolicy({
      policyObjectId: created.policyObjectId,
      note: params.note ?? `sdk policy update ${params.version}`,
      registryObjectId: params.registryObjectId,
    });
    if (!registered.success || !registered.policyVersionObjectId?.startsWith("0x")) {
      throw new Error(registered.error ?? "Failed to register policy version");
    }

    const proposed = await this.backend.proposeGovernancePolicyChange({
      governanceId: params.governanceId,
      bindingId: wallet.bindingObjectId,
      targetVersionId: registered.policyVersionObjectId,
    });
    if (!proposed.success || !proposed.proposalId?.startsWith("0x")) {
      throw new Error(proposed.error ?? "Failed to propose governance policy change");
    }

    // Track latest policy target locally; governance execution still required.
    this.store.save({
      ...wallet,
      policyObjectId: created.policyObjectId,
    });

    return {
      walletId: params.walletId,
      governanceId: params.governanceId,
      bindingObjectId: wallet.bindingObjectId,
      policyObjectId: created.policyObjectId,
      policyVersionObjectId: registered.policyVersionObjectId,
      proposalId: proposed.proposalId,
      policyDigest: created.digest,
      registerDigest: registered.digest,
      proposalDigest: proposed.digest,
    };
  }

  async approvePolicyUpdate(params: ApprovePolicyUpdateParams): Promise<{ digest: string }> {
    const r = await this.backend.approveGovernancePolicyChange(params);
    if (!r.success) {
      throw new Error(r.error ?? "Failed to approve policy update proposal");
    }
    return { digest: r.digest };
  }

  async executePolicyUpdate(params: ExecutePolicyUpdateParams): Promise<{ digest: string }> {
    const wallet = this.requireWalletRecord(params.walletId);
    if (!wallet.bindingObjectId) {
      throw new Error(
        "Wallet is missing bindingObjectId. Provision the wallet before executing policy updates."
      );
    }
    const r = await this.backend.executeAndReaffirmGovernancePolicyChange({
      governanceId: params.governanceId,
      proposalId: params.proposalId,
      bindingObjectId: wallet.bindingObjectId,
    });
    if (!r.success) {
      throw new Error(r.error ?? "Failed to execute and reaffirm policy update");
    }
    return { digest: r.digest };
  }

  async getPolicyUpdateStatus(proposalId: string): Promise<PolicyUpdateStatus> {
    const proposalResp = await this.backend.getGovernanceProposal(proposalId);
    if (!proposalResp.success || !proposalResp.proposal) {
      throw new Error(proposalResp.error ?? "Failed to fetch governance proposal");
    }
    const proposal = proposalResp.proposal;

    let threshold: number | undefined;
    let timelockDurationMs: number | undefined;
    if (proposal.governanceId?.startsWith("0x")) {
      const govResp = await this.backend.getGovernance(proposal.governanceId);
      if (govResp.success && govResp.governance) {
        threshold = Number(govResp.governance.threshold);
        timelockDurationMs = Number(govResp.governance.timelockDurationMs);
      }
    }

    const approvalsCollected = proposal.approvals?.length ?? 0;
    const approvalsNeeded = threshold !== undefined ? Math.max(0, threshold - approvalsCollected) : undefined;

    let state: PolicyUpdateStatus["state"] = "awaiting_approvals";
    if (proposal.cancelled) {
      state = "cancelled";
    } else if (proposal.executed) {
      state = "executed";
    } else if (threshold !== undefined && approvalsCollected < threshold) {
      state = "awaiting_approvals";
    } else if (
      proposal.thresholdMetAtMs > 0 &&
      timelockDurationMs !== undefined &&
      timelockDurationMs > 0 &&
      Date.now() < proposal.thresholdMetAtMs + timelockDurationMs
    ) {
      state = "awaiting_timelock";
    } else {
      state = "ready_to_execute";
    }

    return {
      proposal,
      threshold,
      timelockDurationMs,
      approvalsCollected,
      approvalsNeeded,
      state,
    };
  }

  async getPolicy(walletId: string): Promise<Record<string, unknown>> {
    const wallet = this.requireWalletRecord(walletId);
    if (!wallet.policyObjectId) {
      throw new Error("Wallet has no policyObjectId recorded");
    }
    const response = await this.backend.getPolicy(wallet.policyObjectId);
    if (!response.success || !response.policy) {
      throw new Error(response.error ?? "Failed to fetch policy");
    }
    return response.policy;
  }

  async createPresign(walletId: string): Promise<PresignResult> {
    const wallet = this.requireWalletRecord(walletId);

    const req = await this.backend.requestPresign({
      dWalletId: wallet.walletId,
    });
    if (!req.success) {
      throw new Error(`Failed to request presign for wallet ${walletId}`);
    }

    const status = await this.pollPresignStatus(req.requestId);
    return {
      requestId: req.requestId,
      presignId: status.presignId!,
      presignBytes: new Uint8Array(status.presignBytes!),
    };
  }

  async sign(walletId: string, messageHex: string, opts?: SignOpts): Promise<SignResult> {
    const wallet = this.requireWalletRecord(walletId);

    if (wallet.curve !== "secp256k1") {
      throw new Error(`sign() currently supports secp256k1 wallets only (wallet curve: ${wallet.curve})`);
    }

    const messageHexNoPrefix = stripHexPrefix(messageHex);
    if (!messageHexNoPrefix || messageHexNoPrefix.length % 2 !== 0) {
      throw new Error("messageHex must be a non-empty even-length hex string");
    }

    let presignId = opts?.presignId;
    let presignBytes = opts?.presignBytes;

    if (!presignId || !presignBytes) {
      if (presignId || presignBytes) {
        throw new Error("When overriding presign, both presignId and presignBytes are required");
      }
      const presign = await this.createPresign(walletId);
      presignId = presign.presignId;
      presignBytes = presign.presignBytes;
    }

    const rpcUrlForSign = await this.resolveSuiRpcUrl();
    const protocolParams = await withRetry(
      () => fetchProtocolParams("secp256k1", rpcUrlForSign, this.network),
      { label: "fetchProtocolParams(sign)" },
    );
    const messageBytes = new Uint8Array(Buffer.from(messageHexNoPrefix, "hex"));
    const userSignMessage = await this.computeUserSignMessageWithExtensionFallback(
      wallet,
      protocolParams,
      presignBytes,
      messageBytes,
    );

    const policyContext: SignPolicyContext = opts?.policyContext ?? {
      namespace: 1,
      chainId: 1,
      intentHashHex: keccak256(ensureHexPrefix(messageHexNoPrefix)) as Hex,
      destinationHex: "0x0000000000000000000000000000000000000000",
      nativeValue: 0n,
    };

    const initialPolicyReceiptId = await this.mintPolicyReceipt(wallet, policyContext);
    const dWalletCapId = wallet.dWalletCapId;
    if (!dWalletCapId) {
      throw new Error(
        "Wallet record is missing dWalletCapId. Recreate/provision this wallet before signing.",
      );
    }

    if (!presignId) {
      throw new Error("Missing presignId after presign creation.");
    }

    const resolvedPolicyVersion = await this.resolvePolicyVersion(wallet, opts?.policyVersion);
    const submitAndPoll = async (policyReceiptId: string): Promise<SignResult> => {
      const req = await this.backend.requestSign({
        dWalletId: wallet.walletId,
        dWalletCapId,
        encryptedUserSecretKeyShareId: wallet.encryptedUserSecretKeyShareId ?? "",
        userOutputSignature: [],
        presignId,
        messageHex: messageHexNoPrefix,
        userSignMessage: Array.from(userSignMessage),
        policyReceiptId,
        policyBindingObjectId: wallet.bindingObjectId,
        policyObjectId: wallet.policyObjectId,
        policyVersion: resolvedPolicyVersion,
        ethTx: opts?.ethTx,
      });
      if (!req.success) {
        throw new Error(`Failed to request sign for wallet ${walletId}`);
      }
      const signStatus = await this.pollSignStatus(req.requestId);
      return {
        requestId: req.requestId,
        signId: signStatus.signId,
        presignId,
        signatureHex: ensureHexPrefix(signStatus.signatureHex!) as Hex,
      };
    };

    try {
      return await submitAndPoll(initialPolicyReceiptId);
    } catch (error) {
      if (!this.isReaffirmRequiredError(error)) throw error;
      await this.reaffirmBinding(wallet.walletId);
      // Reaffirm changes active binding version; mint a fresh receipt bound to the new version.
      const retriedPolicyReceiptId = await this.mintPolicyReceipt(wallet, policyContext);
      return submitAndPoll(retriedPolicyReceiptId);
    }
  }

  async signEvm(params: SignEvmParams): Promise<Hex> {
    const wallet = this.requireWalletRecord(params.walletId);
    const rpcUrl = this.resolveEvmRpcUrl(params.chainId, params.rpcUrl);
    const value = toBigInt(params.value);

    const nonceHex = await this.evmRpcCall<string>(rpcUrl, "eth_getTransactionCount", [
      wallet.address,
      "pending",
    ]);
    const nonce = Number(BigInt(nonceHex));

    const data = params.data ?? "0x";
    const gasHex = await this.evmRpcCall<string>(rpcUrl, "eth_estimateGas", [
      {
        from: wallet.address,
        to: params.to,
        value: ensureHexPrefix(value.toString(16)),
        data,
      },
    ]);
    const gas = BigInt(gasHex);

    const gasPriceHex = await this.evmRpcCall<string>(rpcUrl, "eth_gasPrice", []);
    const gasPrice = BigInt(gasPriceHex);
    const maxPriorityFeePerGas = gasPrice;
    const maxFeePerGas = gasPrice * 2n;

    const unsignedTx: TransactionSerializableEIP1559 = {
      type: "eip1559",
      chainId: params.chainId,
      nonce,
      to: params.to,
      value,
      data,
      gas,
      maxFeePerGas,
      maxPriorityFeePerGas,
    };

    const serializedUnsigned = serializeTransaction(unsignedTx);
    const evmIntent = computeEvmIntentFromUnsignedTxBytes({
      chainId: params.chainId,
      unsignedTxBytesHex: serializedUnsigned as Hex,
    });

    const signResult = await this.sign(params.walletId, serializedUnsigned, {
      policyContext: {
        namespace: 1,
        chainId: params.chainId,
        intentHashHex: evmIntent.intentHash,
        destinationHex: params.to,
        nativeValue: value,
      },
      ethTx: {
        to: params.to,
        value: value.toString(),
        nonce,
        gasLimit: gas.toString(),
        maxFeePerGas: maxFeePerGas.toString(),
        maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
        chainId: params.chainId,
        from: wallet.address,
      },
    });

    const sigNoPrefix = stripHexPrefix(signResult.signatureHex);
    let signedTx: Hex | null = null;

    // Ika/backend may return either:
    // - 64-byte compact ECDSA (r||s) without recovery id
    // - 65-byte recoverable (r||s||v/yParity)
    if (sigNoPrefix.length === 128) {
      const r = ensureHexPrefix(sigNoPrefix.slice(0, 64)) as Hex;
      const s = ensureHexPrefix(sigNoPrefix.slice(64, 128)) as Hex;

      for (const yParity of [0, 1] as const) {
        const candidate = serializeTransaction(unsignedTx, { r, s, yParity }) as Hex;
        try {
          const recovered = await recoverTransactionAddress({
            serializedTransaction: candidate as any,
          });
          if (recovered.toLowerCase() === wallet.address.toLowerCase()) {
            signedTx = candidate;
            break;
          }
        } catch {
          // Try the other parity.
        }
      }

      if (!signedTx) {
        throw new Error("Failed to recover correct signer address from 64-byte signature");
      }
    } else if (sigNoPrefix.length === 130) {
      const r = ensureHexPrefix(sigNoPrefix.slice(0, 64)) as Hex;
      const s = ensureHexPrefix(sigNoPrefix.slice(64, 128)) as Hex;
      const vByte = Number.parseInt(sigNoPrefix.slice(128, 130), 16);
      const yParity = (vByte === 27 || vByte === 28 ? vByte - 27 : vByte) as 0 | 1;
      if (yParity !== 0 && yParity !== 1) {
        throw new Error(`Unsupported signature v/yParity byte: ${vByte}`);
      }
      signedTx = serializeTransaction(unsignedTx, { r, s, yParity }) as Hex;
    } else {
      throw new Error(
        `Unexpected signature length from sign endpoint: ${sigNoPrefix.length / 2} bytes`,
      );
    }

    return signedTx;
  }

  async broadcastEvm(signedTx: Hex, rpcUrl: string): Promise<Hex> {
    const txHash = await this.evmRpcCall<string>(rpcUrl, "eth_sendRawTransaction", [signedTx]);
    return ensureHexPrefix(txHash) as Hex;
  }

  async getBalance(address: Hex, rpcUrl: string): Promise<bigint> {
    const balanceHex = await this.evmRpcCall<string>(rpcUrl, "eth_getBalance", [address, "latest"]);
    return BigInt(balanceHex);
  }

  private async activateWallet(
    walletId: string,
    encryptedShareId: string,
    encryptionKeys: Awaited<ReturnType<typeof deriveEncryptionKeys>>,
    userPublicOutput: number[],
  ): Promise<void> {
    const rpcUrl = await this.resolveSuiRpcUrl();

    // After DKG the on-chain dWallet goes through AwaitingNetworkDKGVerification
    // (30-60s+ on testnet). Use the Ika SDK's native polling to wait for the
    // correct state before attempting activation.
    let dWallet: unknown;
    try {
      dWallet = await waitForDWalletState(
        rpcUrl, this.network, walletId, "AwaitingKeyHolderSignature",
        { timeout: ACTIVATION_POLL_TIMEOUT_MS, interval: ACTIVATION_POLL_INTERVAL_MS },
      );
    } catch {
      // May already be Active (idempotent retry after earlier partial success)
      const current = await withRetry(
        () => fetchDWallet(rpcUrl, this.network, walletId),
        { label: "fetchDWallet(activate-fallback)" },
      );
      const kind = String((current as any)?.state?.$kind ?? "");
      if (kind === "Active") return;
      throw new Error(
        `dWallet activation timed out after ${ACTIVATION_POLL_TIMEOUT_MS / 1000}s ` +
          `(state=${kind || "Unknown"}). The wallet record is saved locally — retry later.`,
      );
    }

    const signature = await computeUserOutputSignature({
      encryptionKeys,
      dWallet: dWallet as any,
      userPublicOutput: new Uint8Array(userPublicOutput),
    });

    await this.backend.activateDWallet({
      dWalletId: walletId,
      encryptedUserSecretKeyShareId: encryptedShareId,
      userOutputSignature: Array.from(signature),
    });
  }

  private async pollDKGStatus(requestId: string) {
    const deadline = Date.now() + DKG_POLL_TIMEOUT_MS;

    while (Date.now() < deadline) {
      const status = await this.backend.getDKGStatus(requestId);

      if (status.status === "completed") {
        if (!status.dWalletObjectId) {
          throw new Error("DKG completed but no dWalletObjectId returned");
        }
        return status;
      }

      if (status.status === "failed") {
        throw new Error(`DKG failed: ${status.error ?? "unknown error"}`);
      }

      await new Promise((r) => setTimeout(r, DKG_POLL_INTERVAL_MS));
    }

    throw new Error(`DKG timed out after ${DKG_POLL_TIMEOUT_MS / 1000}s (requestId: ${requestId})`);
  }

  private requireWalletRecord(walletId: string): WalletRecord {
    const wallet = this.store.load(walletId);
    if (!wallet) {
      throw new Error(`Wallet not found in local key store: ${walletId}`);
    }
    return wallet;
  }

  private async pollPresignStatus(requestId: string) {
    const deadline = Date.now() + PRESIGN_POLL_TIMEOUT_MS;

    while (Date.now() < deadline) {
      const status = await this.backend.getPresignStatus(requestId);

      if (status.status === "completed") {
        if (!status.presignId || !status.presignBytes) {
          throw new Error("Presign completed but missing presignId/presignBytes");
        }
        return status;
      }

      if (status.status === "failed") {
        throw new Error(`Presign failed: ${status.error ?? "unknown error"}`);
      }

      await sleep(PRESIGN_POLL_INTERVAL_MS);
    }

    throw new Error(`Presign timed out after ${PRESIGN_POLL_TIMEOUT_MS / 1000}s (requestId: ${requestId})`);
  }

  private async pollSignStatus(requestId: string) {
    const deadline = Date.now() + SIGN_POLL_TIMEOUT_MS;

    while (Date.now() < deadline) {
      const status = await this.backend.getSignStatus(requestId);

      if (status.status === "completed") {
        if (!status.signatureHex) {
          throw new Error("Sign completed but no signatureHex returned");
        }
        return status;
      }

      if (status.status === "failed") {
        throw new Error(`Sign failed: ${status.error ?? "unknown error"}`);
      }

      await sleep(SIGN_POLL_INTERVAL_MS);
    }

    throw new Error(`Sign timed out after ${SIGN_POLL_TIMEOUT_MS / 1000}s (requestId: ${requestId})`);
  }

  private async mintPolicyReceipt(wallet: WalletRecord, ctx: SignPolicyContext): Promise<string> {
    if (!wallet.policyObjectId || !wallet.bindingObjectId) {
      throw new Error(
        "Wallet is missing policy binding metadata. Ensure it is provisioned with policyObjectId and bindingObjectId.",
      );
    }

    const mintOnce = () =>
      this.backend.mintReceipt({
        policyObjectId: wallet.policyObjectId,
        bindingObjectId: wallet.bindingObjectId,
        namespace: ctx.namespace,
        // chainId is encoded as u64 bytes (16 hex chars)
        chainId: ctx.chainId.toString(16).padStart(16, "0"),
        intentHashHex: stripHexPrefix(ctx.intentHashHex),
        destinationHex: stripHexPrefix(ctx.destinationHex),
        nativeValueHex: ctx.nativeValue.toString(16).padStart(64, "0"),
        contextDataHex: ctx.contextDataHex ? stripHexPrefix(ctx.contextDataHex) : undefined,
      });

    let response = await mintOnce();
    const initialError = String((response as any)?.error ?? "");
    if (response.success === false && this.isReaffirmRequiredError(initialError)) {
      await this.reaffirmBinding(wallet.walletId);
      response = await mintOnce();
    }

    if (response.success === false) {
      throw new Error(String(response.error ?? "Failed to mint policy receipt"));
    }

    if (response.allowed === false) {
      throw new Error("Policy denied this signing intent");
    }

    const receiptId = String(response.receiptId ?? response.receiptObjectId ?? "");
    if (!receiptId.startsWith("0x")) {
      throw new Error("Policy receipt mint succeeded but no receipt id was returned");
    }

    return receiptId;
  }

  private async resolvePolicyVersion(wallet: WalletRecord, override?: string): Promise<string> {
    const explicit = String(override ?? "").trim();
    if (explicit) return explicit;
    if (!wallet.policyObjectId?.startsWith("0x")) {
      throw new Error("Wallet is missing policyObjectId. Provision the wallet before signing.");
    }
    const response = await this.backend.getPolicy(wallet.policyObjectId);
    if (!response.success || !response.policy) {
      throw new Error(response.error ?? "Failed to resolve policy details for signing");
    }
    const version = decodeMoveString((response.policy as Record<string, unknown>).version).trim();
    if (!version) {
      throw new Error("Policy version is missing on-chain. Pass policyVersion explicitly.");
    }
    return version;
  }

  private isReaffirmRequiredError(err: unknown): boolean {
    const message = err instanceof Error ? err.message : String(err);
    return /requires confirmation/i.test(message) || /reaffirm/i.test(message);
  }

  private async computeUserSignMessageWithExtensionFallback(
    wallet: WalletRecord,
    protocolParams: Uint8Array,
    presignBytes: Uint8Array,
    messageBytes: Uint8Array,
  ): Promise<Uint8Array> {
    try {
      return await createUserSignMessageWithPublicOutput(
        protocolParams,
        new Uint8Array(wallet.userPublicOutput),
        new Uint8Array(wallet.userSecretKeyShare),
        presignBytes,
        messageBytes,
        Hash.KECCAK256,
        SignatureAlgorithm.ECDSASecp256k1,
        Curve.SECP256K1,
      );
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      const likelyPresignDecodeIssue =
        msg.includes("unexpected end of input") ||
        msg.includes("create_sign_centralized_party_message");
      if (!likelyPresignDecodeIssue) {
        throw error;
      }

      const fallback = await this.rebuildSigningMaterialFromChain(wallet, protocolParams);
      return createUserSignMessageWithPublicOutput(
        protocolParams,
        fallback.verifiedPublicOutput,
        fallback.secretShare,
        presignBytes,
        messageBytes,
        Hash.KECCAK256,
        SignatureAlgorithm.ECDSASecp256k1,
        Curve.SECP256K1,
      );
    }
  }

  private async rebuildSigningMaterialFromChain(
    wallet: WalletRecord,
    protocolParams: Uint8Array,
  ): Promise<{ secretShare: Uint8Array; verifiedPublicOutput: Uint8Array }> {
    if (!wallet.seed?.length) {
      throw new Error("Wallet is missing seed; cannot rebuild signing material from chain");
    }
    if (!wallet.encryptedUserSecretKeyShareId?.startsWith("0x")) {
      throw new Error(
        "Wallet is missing encryptedUserSecretKeyShareId; cannot rebuild signing material from chain",
      );
    }

    const encryptionKeys = await deriveEncryptionKeys(new Uint8Array(wallet.seed), "secp256k1");
    const dWalletResp = await this.backend.getDWalletFull(wallet.walletId);
    if (!dWalletResp.success || !dWalletResp.dWallet) {
      throw new Error(dWalletResp.error ?? "Failed to fetch dWallet for fallback signing");
    }

    const encObj = await this.backend.getSuiObject(wallet.encryptedUserSecretKeyShareId);
    if (!encObj.success) {
      throw new Error(encObj.error ?? "Failed to fetch encrypted share object for fallback signing");
    }
    const fields = (encObj.object?.data?.content?.fields ?? {}) as Record<string, unknown>;
    const normalized = buildNormalizedEncryptedShare(fields);

    const { secretShare, verifiedPublicOutput } = await encryptionKeys.decryptUserShare(
      dWalletResp.dWallet as any,
      normalized as any,
      protocolParams,
    );

    return { secretShare, verifiedPublicOutput };
  }

  private resolveEvmRpcUrl(chainId: number, explicitRpcUrl?: string): string {
    const url = explicitRpcUrl ?? this.evmRpcUrls[chainId];
    if (!url) {
      throw new Error(`No EVM RPC URL configured for chainId ${chainId}`);
    }
    return url;
  }

  private async evmRpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: Date.now(),
        method,
        params,
      }),
    });

    const json = await res.json() as {
      result?: T;
      error?: { message?: string };
    };

    if (!res.ok) {
      throw new Error(`EVM RPC request failed (${method}): HTTP ${res.status}`);
    }
    if (json.error) {
      throw new Error(`EVM RPC error (${method}): ${json.error.message ?? "unknown error"}`);
    }
    if (json.result === undefined) {
      throw new Error(`EVM RPC response missing result (${method})`);
    }
    return json.result;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function stripHexPrefix(value: string): string {
  return value.startsWith("0x") ? value.slice(2) : value;
}

function ensureHexPrefix(value: string): `0x${string}` {
  return (value.startsWith("0x") ? value : `0x${value}`) as `0x${string}`;
}

function toBigInt(value: bigint | number | string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") return BigInt(value);
  return value.startsWith("0x") ? BigInt(value) : BigInt(value);
}

function decodeMoveString(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
    try {
      return new TextDecoder().decode(Uint8Array.from(value as number[]));
    } catch {
      return "";
    }
  }
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return (
      decodeMoveString(obj.bytes) ||
      decodeMoveString(obj.data) ||
      decodeMoveString(obj.value) ||
      decodeMoveString(obj.fields)
    );
  }
  return "";
}

function buildNormalizedEncryptedShare(fields: Record<string, unknown>): Record<string, unknown> {
  const { state } = normalizeMoveEnumState(fields.state);
  const candidate: Record<string, unknown> = {
    state,
    encryption_key_address: String(
      (fields.encryption_key_address as string) ?? (fields.encryptionKeyAddress as string) ?? "",
    ),
    encrypted_centralized_secret_share_and_proof:
      fields.encrypted_centralized_secret_share_and_proof ??
      fields.encryptedCentralizedSecretShareAndProof ??
      fields.encrypted_user_share_and_proof ??
      [],
  };

  const rawSig =
    (candidate?.state as any)?.KeyHolderSigned?.user_output_signature ??
    (candidate?.state as any)?.KeyHolderSigned?.fields?.user_output_signature ??
    (candidate?.state as any)?.user_output_signature ??
    findNestedUserOutputSignature(fields.state) ??
    null;
  const sig = normalizeBytesLike(rawSig);
  if (sig && sig.length > 0) {
    candidate.state = {
      KeyHolderSigned: {
        ...(((candidate.state as any)?.KeyHolderSigned ?? {}) as Record<string, unknown>),
        user_output_signature: sig,
      },
    };
  }

  return candidate;
}

function normalizeBytesLike(v: unknown): number[] | null {
  if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
    return v as number[];
  }
  if (typeof v === "string" && v.length > 0) {
    try {
      return Array.from(Buffer.from(v, "base64"));
    } catch {
      return null;
    }
  }
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (Array.isArray(o.bytes)) return normalizeBytesLike(o.bytes);
    if (Array.isArray(o.data)) return normalizeBytesLike(o.data);
    if (Array.isArray(o.value)) return normalizeBytesLike(o.value);
    if (o.fields) return normalizeBytesLike(o.fields);
  }
  return null;
}

function normalizeMoveEnumState(stateRaw: unknown): { kind: string; state: Record<string, unknown> } {
  if (!stateRaw || typeof stateRaw !== "object") return { kind: "Unknown", state: {} };
  const stateObj = stateRaw as Record<string, unknown>;

  if (stateObj.fields && typeof stateObj.fields === "object") {
    return normalizeMoveEnumState(stateObj.fields);
  }

  if (typeof stateObj.$kind === "string") {
    const kind = String(stateObj.$kind);
    const copy: Record<string, unknown> = { ...stateObj };
    delete copy.$kind;
    const flat =
      copy.fields && typeof copy.fields === "object"
        ? ({ ...copy.fields } as Record<string, unknown>)
        : copy;
    return { kind, state: { [kind]: flat } };
  }

  const keys = Object.keys(stateObj);
  if (!keys.length) return { kind: "Unknown", state: {} };
  const kind = String(keys[0]);
  const inner = stateObj[kind];
  const flat =
    inner &&
    typeof inner === "object" &&
    (inner as Record<string, unknown>).fields &&
    typeof (inner as Record<string, unknown>).fields === "object"
      ? ({ ...((inner as Record<string, unknown>).fields as Record<string, unknown>) } as Record<
          string,
          unknown
        >)
      : ((inner as Record<string, unknown>) ?? {});
  return { kind, state: { [kind]: flat } };
}

function findNestedUserOutputSignature(v: unknown, depth = 0): unknown {
  if (depth > 6 || v == null || typeof v !== "object") return null;
  if (Array.isArray(v)) {
    for (const it of v) {
      const r = findNestedUserOutputSignature(it, depth + 1);
      if (r != null) return r;
    }
    return null;
  }
  const obj = v as Record<string, unknown>;
  if (obj.user_output_signature != null) return obj.user_output_signature;
  if (obj.fields != null) {
    const r = findNestedUserOutputSignature(obj.fields, depth + 1);
    if (r != null) return r;
  }
  if (obj.KeyHolderSigned != null) {
    const r = findNestedUserOutputSignature(obj.KeyHolderSigned, depth + 1);
    if (r != null) return r;
  }
  for (const k of Object.keys(obj)) {
    const r = findNestedUserOutputSignature(obj[k], depth + 1);
    if (r != null) return r;
  }
  return null;
}
