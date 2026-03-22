import { z } from "zod";
import { CustodyMode } from "./custody-mode";

// Default on-chain policy engine package ids (used when env vars are not set).
// NOTE: On Sui upgrades, package ids change. These defaults are for local dev.
const DEFAULT_TESTNET_POLICY_MINT_PACKAGE_ID =
  "0x1cb801eed07b7389924ec6474a3ab622e563f043f61c2e63e2d0c25a2574de92";
// On testnet, custody_ledger currently lives in the latest policy engine package.
const DEFAULT_TESTNET_CUSTODY_PACKAGE_ID =
  "0x1cb801eed07b7389924ec6474a3ab622e563f043f61c2e63e2d0c25a2574de92";

/**
 * Environment variable schema definition
 */
const envSchema = z.object({
  PORT: z.coerce.number().positive().default(3001),
  HOST: z.string().default("0.0.0.0"),

  // Sui Admin Keypair (base64 encoded secret key)
  SUI_ADMIN_SECRET_KEY: z.string().min(1, "SUI_ADMIN_SECRET_KEY is required"),

  // Sui Network
  SUI_NETWORK: z.enum(["testnet", "mainnet"]).default("testnet"),

  // Optional: override Sui RPC URL (useful if a particular environment has egress/DNS issues).
  // If set, this is used for BOTH mainnet and testnet (ensure it matches SUI_NETWORK).
  SUI_RPC_URL: z.string().url().optional(),

  // Sui gas budgets (in mist). These are MAX limits; actual gas used is typically much lower.
  // Must be <= selected gas coin balance, otherwise Sui rejects the transaction before execution.
  SUI_DKG_GAS_BUDGET_MIST: z.coerce.number().int().positive().default(500_000_000), // 0.5 SUI
  SUI_SIGN_GAS_BUDGET_MIST: z.coerce.number().int().positive().default(200_000_000), // 0.2 SUI

  // Kairo policy gating (hard gate via Sui PolicyReceipt)
  // Policy object id on Sui (shared object) and expected semantic version string
  //
  // NOTE: These are optional now to support per-user policies created dynamically
  // (the extension can pass policyObjectId/policyVersion in requests).
  KAIRO_POLICY_ID: z.string().optional(),
  KAIRO_POLICY_VERSION: z.string().optional(),

  // Optional: override Move package id used for minting PolicyReceipts.
  // Why: Policies created under an older package id keep that type forever, but newer upgrades
  // may publish a wrapper package (new package id) that exposes mint functions like
  // `mint_receipt_evm_to_sender` for those older policy types.
  KAIRO_POLICY_MINT_PACKAGE_ID: z.string().optional(),

  // Optional: Policy registry shared object id (required for PolicyBinding endpoints)
  KAIRO_POLICY_REGISTRY_ID: z.string().optional(),

  // Custody enforcement mode for chain-of-custody append.
  // REQUIRED (default for mainnet): Fail if custody append fails - ensures audit completeness.
  // BEST_EFFORT (default for testnet): Log and continue if custody fails - for dev/test only.
  // DISABLED: Skip custody entirely - for non-custody operations.
  KAIRO_CUSTODY_MODE: z.enum(["REQUIRED", "BEST_EFFORT", "DISABLED"]).optional(),

  // Custody chain configuration (optional - will auto-create if not set)
  KAIRO_CUSTODY_CHAIN_OBJECT_ID: z.string().optional(),
  KAIRO_CUSTODY_PACKAGE_ID: z.string().optional(),

  // PolicyVault configuration (Option A: Hard-gated dWallet signing)
  // REQUIRED: All signing goes through the vault's policy_gated_authorize_sign_v4
  // This is the sole signing gateway - no legacy/ungated path exists
  KAIRO_POLICY_VAULT_OBJECT_ID: z.string().min(1, "KAIRO_POLICY_VAULT_OBJECT_ID is required for vault-gated signing"),

  // Governance package id (kairo_governance) for proposal/receipt flow.
  // Optional: only needed when governance hard-gate is enabled on bindings.
  KAIRO_GOVERNANCE_PACKAGE_ID: z.string().optional(),

  // zkLogin deterministic salt master seed (32-byte hex string).
  // Used for HKDF derivation: salt = HKDF(ikm = seed, salt = iss||aud, info = sub).
  // CRITICAL: Changing this value invalidates all previously derived addresses.
  // Generate once with: openssl rand -hex 32
  ZKLOGIN_MASTER_SEED: z.string().optional(),

  // Bootstrap admin API key. When set, enables auth and can manage other keys.
  // When not set, auth is disabled entirely (open mode for local dev).
  // Generate with: openssl rand -hex 32
  KAIRO_ADMIN_KEY: z.string().optional(),

  // Optional Supabase persistence for API keys + wallet ownership mappings.
  // If both are set, registry state is loaded from and written to Supabase.
  SUPABASE_URL: z.string().url().optional(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().optional(),
  KAIRO_API_KEYS_TABLE: z.string().optional(),
});

export type Env = z.infer<typeof envSchema>;

function validateEnv(): Env {
  try {
    return envSchema.parse(process.env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.issues
        .map((err: z.ZodIssue) => `${err.path.join(".")}: ${err.message}`)
        .join("\n");

      console.error("❌ Environment validation failed:");
      console.error(errorMessages);
      process.exit(1);
    }
    throw error;
  }
}

export const env = validateEnv();

export const config = {
  server: {
    port: env.PORT,
    host: env.HOST,
  },
  sui: {
    network: env.SUI_NETWORK,
    rpcUrl: env.SUI_RPC_URL ? String(env.SUI_RPC_URL) : undefined,
    adminSecretKey: env.SUI_ADMIN_SECRET_KEY,
    gasBudgetsMist: {
      dkg: env.SUI_DKG_GAS_BUDGET_MIST,
      sign: env.SUI_SIGN_GAS_BUDGET_MIST,
    },
  },
  kairo: {
    policyId: String(env.KAIRO_POLICY_ID ?? ""),
    policyVersion: String(env.KAIRO_POLICY_VERSION ?? ""),
    policyMintPackageId:
      (env.KAIRO_POLICY_MINT_PACKAGE_ID &&
      String(env.KAIRO_POLICY_MINT_PACKAGE_ID).startsWith("0x"))
        ? String(env.KAIRO_POLICY_MINT_PACKAGE_ID)
        : env.SUI_NETWORK === "testnet"
          ? DEFAULT_TESTNET_POLICY_MINT_PACKAGE_ID
          : "",
    policyRegistryId:
      env.KAIRO_POLICY_REGISTRY_ID &&
      String(env.KAIRO_POLICY_REGISTRY_ID).startsWith("0x")
        ? String(env.KAIRO_POLICY_REGISTRY_ID)
        : "",
    custodyChainObjectId: env.KAIRO_CUSTODY_CHAIN_OBJECT_ID,
    custodyPackageId:
      (env.KAIRO_CUSTODY_PACKAGE_ID &&
      String(env.KAIRO_CUSTODY_PACKAGE_ID).startsWith("0x"))
        ? String(env.KAIRO_CUSTODY_PACKAGE_ID)
        : env.SUI_NETWORK === "testnet"
          ? DEFAULT_TESTNET_CUSTODY_PACKAGE_ID
          : "",
    // Custody is REQUIRED for all signing operations on all networks.
    // Override via KAIRO_CUSTODY_MODE env var only for non-signing operations.
    custodyMode: ((): CustodyMode => {
      if (env.KAIRO_CUSTODY_MODE) {
        return env.KAIRO_CUSTODY_MODE as CustodyMode;
      }
      return CustodyMode.REQUIRED;
    })(),
    // PolicyVault configuration for hard-gated signing (Option A)
    // This is mandatory - all signing must go through the vault
    policyVaultObjectId: String(env.KAIRO_POLICY_VAULT_OBJECT_ID),
    // Governance package id (kairo_governance) for proposal/receipt flow
    governancePackageId:
      (env.KAIRO_GOVERNANCE_PACKAGE_ID &&
      String(env.KAIRO_GOVERNANCE_PACKAGE_ID).startsWith("0x"))
        ? String(env.KAIRO_GOVERNANCE_PACKAGE_ID)
        : "",
  },
  zklogin: {
    masterSeed: String(env.ZKLOGIN_MASTER_SEED ?? ""),
  },
  auth: {
    adminKey: env.KAIRO_ADMIN_KEY ?? "",
    supabaseUrl: env.SUPABASE_URL ?? "",
    supabaseServiceRoleKey: env.SUPABASE_SERVICE_ROLE_KEY ?? "",
    apiKeysTable: env.KAIRO_API_KEYS_TABLE ?? "api_keys",
  },
} as const;
