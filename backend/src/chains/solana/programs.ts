/**
 * Solana Known Program IDs
 *
 * Common program IDs for policy evaluation.
 */

/**
 * System Program - native SOL transfers.
 */
export const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";

/**
 * Token Program (SPL Token) - SPL token operations.
 */
export const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/**
 * Token 2022 Program - new token standard.
 */
export const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/**
 * Associated Token Account Program.
 */
export const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/**
 * Memo Program.
 */
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/**
 * Compute Budget Program.
 */
export const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111";

/**
 * Address Lookup Table Program.
 */
export const ADDRESS_LOOKUP_TABLE_PROGRAM_ID = "AddressLookupTab1e1111111111111111111111111";

/**
 * Common Solana program IDs (aggregated object for convenience).
 */
export const PROGRAM_IDS = {
  SYSTEM: SYSTEM_PROGRAM_ID,
  TOKEN: TOKEN_PROGRAM_ID,
  TOKEN_2022: TOKEN_2022_PROGRAM_ID,
  ASSOCIATED_TOKEN: ASSOCIATED_TOKEN_PROGRAM_ID,
  MEMO: MEMO_PROGRAM_ID,
  COMPUTE_BUDGET: COMPUTE_BUDGET_PROGRAM_ID,
} as const;

/**
 * Known safe programs that don't require special approval.
 */
export const KNOWN_SAFE_PROGRAMS = new Set([
  SYSTEM_PROGRAM_ID,
  MEMO_PROGRAM_ID,
  COMPUTE_BUDGET_PROGRAM_ID,
]);

/**
 * Token-related programs.
 */
export const TOKEN_PROGRAMS = new Set([
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
]);

/**
 * Check if a program is a known token program.
 */
export function isTokenProgram(programId: string): boolean {
  return TOKEN_PROGRAMS.has(programId);
}

/**
 * Check if a program is considered safe (doesn't need approval).
 */
export function isSafeProgram(programId: string): boolean {
  return KNOWN_SAFE_PROGRAMS.has(programId);
}

/**
 * System instruction types (first 4 bytes of instruction data).
 */
export enum SystemInstructionType {
  CreateAccount = 0,
  Assign = 1,
  Transfer = 2,
  CreateAccountWithSeed = 3,
  AdvanceNonceAccount = 4,
  WithdrawNonceAccount = 5,
  InitializeNonceAccount = 6,
  AuthorizeNonceAccount = 7,
  Allocate = 8,
  AllocateWithSeed = 9,
  AssignWithSeed = 10,
  TransferWithSeed = 11,
  UpgradeNonceAccount = 12,
}

/**
 * Token instruction types (first byte of instruction data).
 */
export enum TokenInstructionType {
  InitializeMint = 0,
  InitializeAccount = 1,
  InitializeMultisig = 2,
  Transfer = 3,
  Approve = 4,
  Revoke = 5,
  SetAuthority = 6,
  MintTo = 7,
  Burn = 8,
  CloseAccount = 9,
  FreezeAccount = 10,
  ThawAccount = 11,
  TransferChecked = 12,
  ApproveChecked = 13,
  MintToChecked = 14,
  BurnChecked = 15,
  InitializeAccount2 = 16,
  SyncNative = 17,
  InitializeAccount3 = 18,
  InitializeMultisig2 = 19,
  InitializeMint2 = 20,
}

/**
 * Get human-readable name for a program.
 */
export function getProgramName(programId: string): string {
  switch (programId) {
    case SYSTEM_PROGRAM_ID:
      return "System Program";
    case TOKEN_PROGRAM_ID:
      return "Token Program";
    case TOKEN_2022_PROGRAM_ID:
      return "Token 2022 Program";
    case ASSOCIATED_TOKEN_PROGRAM_ID:
      return "Associated Token Program";
    case MEMO_PROGRAM_ID:
      return "Memo Program";
    case COMPUTE_BUDGET_PROGRAM_ID:
      return "Compute Budget Program";
    case ADDRESS_LOOKUP_TABLE_PROGRAM_ID:
      return "Address Lookup Table Program";
    default:
      return `Unknown (${programId.slice(0, 8)}...)`;
  }
}
