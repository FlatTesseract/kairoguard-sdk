/**
 * HTTP client for the Kairo backend API.
 *
 * Handles authentication, request formatting, and response parsing.
 * All methods automatically attach the X-Kairo-Api-Key header.
 */

export const DEFAULT_BACKEND_URL = "https://backend.0xlegacy.link";

export interface BackendClientOpts {
  backendUrl?: string;
  apiKey?: string;
}

export interface HealthResponse {
  status: string;
  adminAddress: string;
  suiNetwork: string;
  timestamp: string;
}

export interface DKGSubmitRequest {
  userPublicOutput: number[];
  userDkgMessage: number[];
  encryptedUserShareAndProof: number[];
  sessionIdentifier: number[];
  signerPublicKey: number[];
  encryptionKeyAddress: string;
  encryptionKey: number[];
  encryptionKeySignature: number[];
  curve?: number;
}

export interface DKGSubmitResponse {
  success: boolean;
  requestId: string;
  status: string;
}

export interface DKGStatusResponse {
  success: boolean;
  requestId: string;
  status: "pending" | "processing" | "completed" | "failed";
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  encryptedUserSecretKeyShareId?: string;
  ethereumAddress?: string;
  solanaAddress?: string;
  error?: string;
}

export interface ProvisionRequest {
  dwalletObjectId: string;
  policyObjectId: string;
  stableId: string;
  isImportedKey?: boolean;
}

export interface ProvisionResponse {
  success: boolean;
  digest: string;
  bindingObjectId: string | null;
  vaultObjectId: string;
  dwalletObjectId: string;
  walletState: string;
}

export interface RegisterKeyRequest {
  label: string;
  email?: string;
}

export interface RegisterKeyResponse {
  success: boolean;
  apiKey: string;
  label: string;
  tier: string;
  createdAt: number;
}

export type RequestStatus = "pending" | "processing" | "completed" | "failed";

export interface PresignRequestParams {
  dWalletId: string;
  dWalletCapId?: string;
  curve?: number;
  signatureAlgorithm?: number;
  encryptedUserSecretKeyShareId?: string;
  userOutputSignature?: number[];
}

export interface PresignRequestResponse {
  success: boolean;
  requestId: string;
  status: RequestStatus;
}

export interface PresignStatusResponse {
  success: boolean;
  requestId: string;
  status: RequestStatus;
  presignId?: string;
  presignBytes?: number[];
  error?: string;
}

export interface EthTxParams {
  to: string;
  value: string;
  nonce: number;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  chainId: number;
  from: string;
}

export interface SignRequestParams {
  dWalletId: string;
  dWalletCapId: string;
  encryptedUserSecretKeyShareId: string;
  userOutputSignature: number[];
  presignId: string;
  messageHex: string;
  userSignMessage: number[];
  policyReceiptId: string;
  policyBindingObjectId?: string;
  policyObjectId?: string;
  policyVersion?: string;
  custodyChainObjectId?: string;
  custodyPackageId?: string;
  ethTx?: EthTxParams;
}

export interface SignRequestResponse {
  success: boolean;
  requestId: string;
  status: RequestStatus;
}

export interface SignStatusResponse {
  success: boolean;
  requestId: string;
  status: RequestStatus;
  digest?: string;
  signatureHex?: string;
  signId?: string;
  ethTxHash?: string;
  ethBlockNumber?: number;
  error?: string;
}

export interface CreatePolicyV4Rule {
  ruleType: number;
  namespace?: number;
  params: string;
}

export interface CreatePolicyV4Params {
  stableId: string;
  version: string;
  expiresAtMs?: number;
  allowNamespaces?: number[];
  allowChainIds?: Array<{ namespace: number; chainId: string }>;
  allowDestinations?: string[];
  denyDestinations?: string[];
  rules: CreatePolicyV4Rule[];
}

export interface CreatePolicyV4Response {
  success: boolean;
  policyObjectId: string;
  digest: string;
  error?: string;
}

export interface RegisterFromPolicyParams {
  policyObjectId: string;
  note?: string;
  registryObjectId?: string;
}

export interface RegisterFromPolicyResponse {
  success: boolean;
  policyVersionObjectId: string;
  digest: string;
  error?: string;
}

export interface GovernanceProposeParams {
  governanceId: string;
  bindingId: string;
  targetVersionId: string;
}

export interface GovernanceProposeResponse {
  success: boolean;
  proposalId: string;
  digest: string;
  error?: string;
}

export interface GovernanceApproveParams {
  governanceId: string;
  proposalId: string;
}

export interface GovernanceApproveResponse {
  success: boolean;
  digest: string;
  error?: string;
}

export interface GovernanceExecuteAndReaffirmParams {
  governanceId: string;
  proposalId: string;
  bindingObjectId: string;
}

export interface GovernanceExecuteAndReaffirmResponse {
  success: boolean;
  digest: string;
  error?: string;
}

export interface GovernanceInfo {
  id: string;
  stableId: string;
  approvers: string[];
  threshold: number;
  timelockDurationMs: number;
  proposalCount: number;
  admin: string;
}

export interface GovernanceGetResponse {
  success: boolean;
  governance?: GovernanceInfo;
  error?: string;
}

export interface GovernanceProposalInfo {
  id: string;
  governanceId: string;
  bindingId: string;
  targetVersionId: string;
  proposer: string;
  approvals: string[];
  createdAtMs: number;
  thresholdMetAtMs: number;
  executed: boolean;
  cancelled: boolean;
}

export interface GovernanceProposalGetResponse {
  success: boolean;
  proposal?: GovernanceProposalInfo;
  error?: string;
}

export interface PolicyDetailsResponse {
  success: boolean;
  policy?: Record<string, unknown>;
  error?: string;
}

export interface ReaffirmPolicyBindingParams {
  bindingObjectId: string;
  registryObjectId?: string;
}

export interface ReaffirmPolicyBindingResponse {
  success: boolean;
  digest: string;
  activeVersionObjectId?: string;
  error?: string;
}

export interface DWalletFullResponse {
  success: boolean;
  dWallet?: unknown;
  error?: string;
}

export interface SuiObjectResponse {
  success: boolean;
  object?: {
    data?: {
      content?: {
        fields?: Record<string, unknown>;
      };
    };
  };
  error?: string;
}

export class BackendClient {
  private baseUrl: string;
  private apiKey: string | undefined;

  constructor(opts: BackendClientOpts) {
    this.baseUrl = (opts.backendUrl ?? DEFAULT_BACKEND_URL).replace(/\/+$/, "");
    this.apiKey = opts.apiKey;
  }

  setApiKey(key: string): void {
    this.apiKey = key;
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.apiKey) {
      headers["X-Kairo-Api-Key"] = this.apiKey;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    const json = await res.json() as Record<string, unknown>;

    if (!res.ok) {
      const msg = (json.error as string) || (json.message as string) || `HTTP ${res.status}`;
      throw new Error(`Kairo API error (${path}): ${msg}`);
    }

    return json as T;
  }

  async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>("GET", "/health");
  }

  async register(label: string, email?: string): Promise<RegisterKeyResponse> {
    return this.request<RegisterKeyResponse>("POST", "/api/keys/register", { label, email });
  }

  async submitDKG(data: DKGSubmitRequest): Promise<DKGSubmitResponse> {
    return this.request<DKGSubmitResponse>("POST", "/api/dkg/submit", data);
  }

  async getDKGStatus(requestId: string): Promise<DKGStatusResponse> {
    return this.request<DKGStatusResponse>("GET", `/api/dkg/status/${requestId}`);
  }

  async provision(params: ProvisionRequest): Promise<ProvisionResponse> {
    return this.request<ProvisionResponse>("POST", "/api/vault/provision", params);
  }

  async mintReceipt(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/api/policy/receipt/mint", params);
  }

  async requestPresign(params: PresignRequestParams): Promise<PresignRequestResponse> {
    return this.request<PresignRequestResponse>("POST", "/api/presign/request", params);
  }

  async getPresignStatus(requestId: string): Promise<PresignStatusResponse> {
    return this.request<PresignStatusResponse>("GET", `/api/presign/status/${requestId}`);
  }

  async requestSign(params: SignRequestParams): Promise<SignRequestResponse> {
    return this.request<SignRequestResponse>("POST", "/api/sign/request", params);
  }

  async getSignStatus(requestId: string): Promise<SignStatusResponse> {
    return this.request<SignStatusResponse>("GET", `/api/sign/status/${requestId}`);
  }

  async createPolicyV4(params: CreatePolicyV4Params): Promise<CreatePolicyV4Response> {
    return this.request<CreatePolicyV4Response>("POST", "/api/policy/create", params);
  }

  async registerPolicyVersionFromPolicy(
    params: RegisterFromPolicyParams
  ): Promise<RegisterFromPolicyResponse> {
    return this.request<RegisterFromPolicyResponse>(
      "POST",
      "/api/policy/registry/register-from-policy",
      params
    );
  }

  async proposeGovernancePolicyChange(
    params: GovernanceProposeParams
  ): Promise<GovernanceProposeResponse> {
    return this.request<GovernanceProposeResponse>("POST", "/api/policy/governance/propose", params);
  }

  async approveGovernancePolicyChange(
    params: GovernanceApproveParams
  ): Promise<GovernanceApproveResponse> {
    return this.request<GovernanceApproveResponse>("POST", "/api/policy/governance/approve", params);
  }

  async executeAndReaffirmGovernancePolicyChange(
    params: GovernanceExecuteAndReaffirmParams
  ): Promise<GovernanceExecuteAndReaffirmResponse> {
    return this.request<GovernanceExecuteAndReaffirmResponse>(
      "POST",
      "/api/policy/governance/execute-and-reaffirm",
      params
    );
  }

  async getGovernance(governanceId: string): Promise<GovernanceGetResponse> {
    return this.request<GovernanceGetResponse>("GET", `/api/policy/governance/${governanceId}`);
  }

  async getGovernanceProposal(proposalId: string): Promise<GovernanceProposalGetResponse> {
    return this.request<GovernanceProposalGetResponse>(
      "GET",
      `/api/policy/governance/proposal/${proposalId}`
    );
  }

  async getPolicy(policyObjectId: string): Promise<PolicyDetailsResponse> {
    return this.request<PolicyDetailsResponse>("GET", `/api/policies/${policyObjectId}`);
  }

  async reaffirmPolicyBinding(
    params: ReaffirmPolicyBindingParams
  ): Promise<ReaffirmPolicyBindingResponse> {
    return this.request<ReaffirmPolicyBindingResponse>("POST", "/api/policy/binding/reaffirm", params);
  }

  async getDWalletFull(dWalletId: string): Promise<DWalletFullResponse> {
    return this.request<DWalletFullResponse>("GET", `/api/dwallet/full/${dWalletId}`);
  }

  async getSuiObject(objectId: string): Promise<SuiObjectResponse> {
    return this.request<SuiObjectResponse>("GET", `/api/sui/object/${objectId}`);
  }

  async policySign(params: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("POST", "/api/policy/sign", params);
  }

  async activateDWallet(params: {
    dWalletId: string;
    encryptedUserSecretKeyShareId: string;
    userOutputSignature: number[];
  }): Promise<{ success: boolean; digest: string }> {
    return this.request<{ success: boolean; digest: string }>("POST", "/api/dwallet/activate", params);
  }

  async getVaultStatus(dWalletId: string): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", `/api/vault/status/${dWalletId}`);
  }

  async getAuditEvents(limit = 10): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>("GET", `/api/audit/events?limit=${limit}`);
  }
}
