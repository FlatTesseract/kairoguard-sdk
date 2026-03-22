import type { CustodyMode, CustodyStatus } from "./custody-mode.js";

/**
 * DKG submission data from frontend
 * Matches the IKA SDK CreateDWalletParams structure
 */
export interface DKGSubmitInput {
  // Public output from local DKG computation
  userPublicOutput: number[];
  // DKG message for the network
  userDkgMessage: number[];
  // Encrypted user secret key share and proof
  encryptedUserShareAndProof: number[];
  // Session identifier (random bytes)
  sessionIdentifier: number[];
  // Signer public key for encryption key registration
  signerPublicKey: number[];
  // Address where encryption key is registered
  encryptionKeyAddress: string;
  // Encryption key bytes
  encryptionKey: number[];
  // Signature over encryption key
  encryptionKeySignature: number[];
  // Curve type (0 = SECP256K1 for Ethereum, 2 = ED25519 for Sui)
  curve?: number;
}

/**
 * In-memory store for pending DKG requests
 */
export interface DKGRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  data: DKGSubmitInput;
  createdAt: Date;
  // Results after processing
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  encryptedUserSecretKeyShareId?: string | null;
  ethereumAddress?: string;
  solanaAddress?: string;
  digest?: string;
  error?: string;
}

/**
 * DKG submit response
 */
export interface DKGSubmitResponse {
  success: boolean;
  requestId: string;
  status: DKGRequest["status"];
}

/**
 * DKG status response
 */
export interface DKGStatusResponse {
  requestId: string;
  status: DKGRequest["status"];
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  ethereumAddress?: string;
  solanaAddress?: string;
  error?: string;
}

/**
 * Sign request input - NON-CUSTODIAL
 * The user computes userSignMessage client-side using createUserSignMessageWithPublicOutput
 * The secret share NEVER leaves the client
 * Based on https://docs.ika.xyz/sdk/ika-transaction/zero-trust-dwallet#signing-a-message
 */
export interface SignRequestInput {
  // The dWallet ID to sign with
  dWalletId: string;
  // The dWallet Cap ID for message approval
  dWalletCapId: string;
  // Encrypted user secret key share id
  encryptedUserSecretKeyShareId: string;
  // User output signature
  userOutputSignature: number[];
  // Presign ID (must be completed)
  presignId: string;
  // Message to sign (hex-encoded, e.g., Ethereum transaction hash)
  messageHex: string;
  // User sign message computed client-side via createUserSignMessageWithPublicOutput
  // This is the user's partial signature - NOT the secret share
  userSignMessage: number[];
  // Kairo hard gate: Sui PolicyReceipt object id that must be valid for this intent
  policyReceiptId: string;
  // Optional: if provided, backend enforces explicit policy reaffirmation checkpoints.
  // For PolicyReceiptV2 this should match the active PolicyVersion in the PolicyBinding.
  policyBindingObjectId?: string;
  // Optional overrides: policy object id/version the receipt must match (defaults to backend env).
  policyObjectId?: string;
  policyVersion?: string;
  // Optional: custody chain identifiers (enable post-broadcast custody append).
  custodyChainObjectId?: string;
  custodyPackageId?: string;
  // Optional: override custody enforcement mode for this operation.
  // REQUIRED (default): fail if custody append fails
  // BEST_EFFORT: log and continue
  // DISABLED: skip custody entirely
  custodyMode?: CustodyMode;
  // Optional: Ethereum transaction details for broadcasting
  ethTx?: {
    to: string; // Recipient address
    value: string; // Value in wei (hex)
    nonce: number;
    gasLimit: string; // Hex
    maxFeePerGas: string; // Hex
    maxPriorityFeePerGas: string; // Hex
    chainId: number;
    from: string; // dWallet's Ethereum address
  };
}

/**
 * Sign request stored in memory
 */
export interface SignRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  data: SignRequestInput;
  createdAt: Date;
  // encrypted user secret key share id
  encryptedUserSecretKeyShareId?: string | null;
  userOutputSignature?: string;
  // Results
  signatureHex?: string;
  signId?: string;
  digest?: string;
  // Ethereum broadcast results
  ethTxHash?: string;
  ethBlockNumber?: number;
  error?: string;
}

/**
 * Presign request
 */
export interface PresignRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  dWalletId: string;
  /** Optional: curve override (0=secp256k1, 2=ed25519) */
  curve?: number;
  /** Optional: signature algorithm override (e.g. 0=ECDSA, 1=Taproot, 2=ED25519) */
  signatureAlgorithm?: number;
  encryptedUserSecretKeyShareId: string;
  userOutputSignature: number[];
  createdAt: Date;
  // Results
  presignId?: string;
  // Completed presign output bytes (safe to share with client)
  presignBytes?: number[];
  error?: string;
}

/**
 * Imported-key dWallet: verification request input (prepared offline; no private key is sent to backend).
 * Mirrors Ika SDK `ImportDWalletVerificationRequestInput`.
 */
export interface ImportedKeyVerificationInput {
  // Prepared public output for the imported key verification protocol
  userPublicOutput: number[];
  // Outgoing message for the verification protocol
  userMessage: number[];
  // Encrypted user share + proof for the imported key
  encryptedUserShareAndProof: number[];
}

/**
 * Submit an imported-key verification request.
 * This is a separate flow (not policy-gated).
 */
export interface ImportedKeyVerifySubmitInput {
  curve: number; // 0 = SECP256K1
  sessionIdentifier: number[]; // 32 bytes
  signerPublicKey: number[]; // UserShareEncryptionKeys signing pubkey bytes
  encryptionKeyAddress: string; // derived from signerPublicKey (ed25519 address)
  encryptionKey: number[]; // class-groups encryption key bytes
  encryptionKeySignature: number[]; // signature over encryptionKey
  importInput: ImportedKeyVerificationInput;
  // Optional: for UI/debug
  expectedEvmAddress?: string;
}

export interface ImportedKeyVerifyRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  data: ImportedKeyVerifySubmitInput;
  createdAt: Date;
  // Results after processing
  dWalletCapObjectId?: string;
  dWalletObjectId?: string;
  encryptedUserSecretKeyShareId?: string | null;
  ethereumAddress?: string;
  solanaAddress?: string;
  digest?: string;
  error?: string;
}

/**
 * Imported-key activation (accept encrypted share).
 * The client computes userOutputSignature locally via UserShareEncryptionKeys.getUserOutputSignature(...)
 */
export interface ImportedKeyActivateInput {
  dWalletId: string;
  encryptedUserSecretKeyShareId: string;
  userOutputSignature: number[]; // bytes
}

/**
 * Imported-key signing request.
 * The client computes userSignMessage locally using decrypted share + presign bytes.
 */
export interface ImportedKeySignRequestInput {
  dWalletId: string;
  dWalletCapId: string;
  presignId: string;
  messageHex: string;
  userSignMessage: number[];
  // Kairo hard gate: Sui PolicyReceipt object id that must be valid for this intent
  policyReceiptId: string;
  // Optional: if provided, backend enforces explicit policy reaffirmation checkpoints.
  policyBindingObjectId?: string;
  // Optional overrides: policy object id/version the receipt must match (defaults to backend env).
  policyObjectId?: string;
  policyVersion?: string;
  // Optional: custody chain identifiers (enable post-broadcast custody append).
  custodyChainObjectId?: string;
  custodyPackageId?: string;
  // Optional: override custody enforcement mode for this operation.
  custodyMode?: CustodyMode;
  // Required for policy gating + optional broadcast
  ethTx: NonNullable<SignRequestInput["ethTx"]>;
}

export interface ImportedKeySignRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  data: ImportedKeySignRequestInput;
  createdAt: Date;
  signatureHex?: string;
  signId?: string;
  digest?: string;
  ethTxHash?: string;
  ethBlockNumber?: number;
  error?: string;
}
