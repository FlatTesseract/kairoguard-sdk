import { createHash, randomBytes } from "node:crypto";
import { logger } from "./logger.js";
import {
  deleteApiKeyByHash,
  isSupabasePersistenceEnabled,
  loadApiKeyByHash,
  loadApiKeysByUser,
  loadAllApiKeys,
  upsertApiKey,
  type PersistedApiKeyRow,
} from "./key-store-supabase.js";

export interface GovernanceEntry {
  governanceId: string;
  mode: number;
}

export interface ApiKeyRecord {
  keyHash: string;
  keyPreview: string;
  label: string;
  email?: string;
  userId?: string;
  createdAt: number;
  isAdmin: boolean;
  tier: "default" | "premium";
  wallets: Set<string>;
  bindings: Set<string>;
  governanceMap: Map<string, GovernanceEntry>;
  proposals: Set<string>;
}

const registry = new Map<string, ApiKeyRecord>(); // key: sha256(rawKey)

function hashKey(rawKey: string): string {
  return createHash("sha256").update(rawKey).digest("hex");
}

function normalizeWalletId(id: string): string {
  return String(id || "").trim().toLowerCase();
}

function normalizeBindingId(id: string): string {
  return String(id || "").trim().toLowerCase();
}

function deserializeGovernanceMap(
  raw: Record<string, unknown> | null | undefined
): Map<string, GovernanceEntry> {
  const map = new Map<string, GovernanceEntry>();
  if (!raw || typeof raw !== "object") return map;
  for (const [k, v] of Object.entries(raw)) {
    if (!v || typeof v !== "object") continue;
    const entry = v as Record<string, unknown>;
    const governanceId = String(entry.governanceId ?? "");
    if (!governanceId) continue;
    map.set(k.toLowerCase(), { governanceId, mode: Number(entry.mode ?? 0) });
  }
  return map;
}

async function persistRecord(record: ApiKeyRecord): Promise<void> {
  if (!isSupabasePersistenceEnabled()) return;
  const row: PersistedApiKeyRow = {
    key_hash: record.keyHash,
    label: record.label,
    email: record.email ?? null,
    user_id: record.userId ?? null,
    created_at: record.createdAt,
    is_admin: record.isAdmin,
    tier: record.tier,
    wallet_ids: Array.from(record.wallets),
    binding_ids: Array.from(record.bindings),
    governance_map: Object.fromEntries(record.governanceMap),
    proposal_ids: Array.from(record.proposals),
  };
  await upsertApiKey(row);
}

export async function initRegistry(adminKey?: string): Promise<void> {
  registry.clear();

  if (isSupabasePersistenceEnabled()) {
    try {
      const rows = (await loadAllApiKeys()) ?? [];
      for (const row of rows) {
        registry.set(row.key_hash, {
          keyHash: row.key_hash,
          keyPreview: `${row.key_hash.slice(0, 6)}...${row.key_hash.slice(-4)}`,
          label: row.label,
          email: row.email ?? undefined,
          userId: row.user_id ?? undefined,
          createdAt: Number(row.created_at) || Date.now(),
          isAdmin: Boolean(row.is_admin),
          tier: row.tier === "premium" ? "premium" : "default",
          wallets: new Set((row.wallet_ids ?? []).map(normalizeWalletId).filter(Boolean)),
          bindings: new Set((row.binding_ids ?? []).map(normalizeBindingId).filter(Boolean)),
          governanceMap: deserializeGovernanceMap(row.governance_map),
          proposals: new Set((row.proposal_ids ?? []).map((id: string) => String(id || "").trim().toLowerCase()).filter(Boolean)),
        });
      }
      logger.info({ count: rows.length }, "Loaded API keys from Supabase");
    } catch (error) {
      logger.error({ err: error }, "Failed to load API keys from Supabase; continuing with in-memory registry");
    }
  }

  if (adminKey) {
    const adminHash = hashKey(adminKey);
    const existing = registry.get(adminHash);
    if (existing) {
      existing.isAdmin = true;
      existing.tier = "premium";
      existing.label = existing.label || "admin";
      try {
        await persistRecord(existing);
      } catch (error) {
        logger.error({ err: error }, "Failed to persist existing admin API key record");
      }
    } else {
      const adminRecord: ApiKeyRecord = {
        keyHash: adminHash,
        keyPreview: maskRawKey(adminKey),
        label: "admin",
        createdAt: Date.now(),
        isAdmin: true,
        tier: "premium",
        wallets: new Set(),
        bindings: new Set(),
        governanceMap: new Map(),
        proposals: new Set(),
      };
      registry.set(adminHash, adminRecord);
      try {
        await persistRecord(adminRecord);
      } catch (error) {
        logger.error({ err: error }, "Failed to persist admin API key record");
      }
    }
    logger.info("Admin API key loaded from environment");
  }
}

export function getKeyRecord(rawKey: string): ApiKeyRecord | null {
  if (!rawKey) return null;
  const keyHash = hashKey(rawKey);
  return registry.get(keyHash) ?? null;
}

export function isAuthEnabled(): boolean {
  return registry.size > 0;
}

export async function createKey(opts: {
  label: string;
  tier?: "default" | "premium";
  email?: string;
  userId?: string;
}): Promise<ApiKeyRecord & { key: string }> {
  const key = randomBytes(32).toString("hex");
  const keyHash = hashKey(key);
  const record: ApiKeyRecord = {
    keyHash,
    keyPreview: maskRawKey(key),
    label: opts.label,
    email: opts.email,
    userId: opts.userId,
    createdAt: Date.now(),
    isAdmin: false,
    tier: opts.tier ?? "default",
    wallets: new Set(),
    bindings: new Set(),
    governanceMap: new Map(),
    proposals: new Set(),
  };
  registry.set(keyHash, record);
  await persistRecord(record);
  logger.info({ label: opts.label, tier: record.tier }, "API key created");
  return { ...record, key };
}

export function listKeys(): Array<{
  key: string;
  keyHash: string;
  label: string;
  email?: string;
  createdAt: number;
  isAdmin: boolean;
  tier: string;
  walletCount: number;
}> {
  return Array.from(registry.values()).map((r) => ({
    key: r.keyPreview,
    keyHash: r.keyHash,
    label: r.label,
    email: r.email ? maskEmail(r.email) : undefined,
    createdAt: r.createdAt,
    isAdmin: r.isAdmin,
    tier: r.tier,
    walletCount: r.wallets.size,
  }));
}

export async function revokeKey(keyOrHash: string): Promise<boolean> {
  const keyHash = keyOrHash.length === 64 ? keyOrHash.toLowerCase() : hashKey(keyOrHash);
  const record = registry.get(keyHash);
  if (!record) return false;
  if (record.isAdmin) return false;
  registry.delete(keyHash);
  try {
    await deleteApiKeyByHash(keyHash);
  } catch (error) {
    logger.error({ err: error, keyHash }, "Failed to delete API key from Supabase");
  }
  logger.info({ label: record.label }, "API key revoked");
  return true;
}

export async function bindWallet(rawKey: string, dwalletId: string): Promise<void> {
  const record = getKeyRecord(rawKey);
  if (!record) return;
  const normalized = normalizeWalletId(dwalletId);
  if (!normalized) return;
  record.wallets.add(normalized);
  try {
    await persistRecord(record);
  } catch (error) {
    logger.error({ err: error, label: record.label, dwalletId: normalized }, "Failed to persist wallet binding");
  }
  logger.info({ label: record.label, dwalletId: normalized }, "Wallet bound to API key");
}

export async function bindBinding(rawKey: string, bindingId: string): Promise<void> {
  const record = getKeyRecord(rawKey);
  if (!record) return;
  const normalized = normalizeBindingId(bindingId);
  if (!normalized) return;
  record.bindings.add(normalized);
  try {
    await persistRecord(record);
  } catch (error) {
    logger.error({ err: error, label: record.label, bindingId: normalized }, "Failed to persist policy binding ID");
  }
  logger.info({ label: record.label, bindingId: normalized }, "Policy binding ID bound to API key");
}

export async function refreshWalletsFromSupabase(rawKey: string): Promise<number> {
  const record = getKeyRecord(rawKey);
  if (!record) return 0;
  if (!isSupabasePersistenceEnabled()) return record.wallets.size;

  try {
    const row = await loadApiKeyByHash(record.keyHash);
    if (!row) {
      logger.warn({ keyHash: record.keyHash }, "No Supabase row found while refreshing API key wallets");
      return record.wallets.size;
    }

    const fromSupabase = (row.wallet_ids ?? []).map(normalizeWalletId).filter(Boolean);
    if (fromSupabase.length === 0) return record.wallets.size;

    for (const walletId of fromSupabase) {
      record.wallets.add(walletId);
    }

    logger.info(
      { label: record.label, keyHash: record.keyHash, walletCount: record.wallets.size },
      "Refreshed API key wallets from Supabase"
    );
    return record.wallets.size;
  } catch (error) {
    logger.error(
      { err: error, label: record.label, keyHash: record.keyHash },
      "Failed to refresh API key wallets from Supabase"
    );
    return record.wallets.size;
  }
}

export async function recoverWalletsFromSiblingKeys(rawKey: string): Promise<number> {
  const record = getKeyRecord(rawKey);
  if (!record) return 0;
  if (!isSupabasePersistenceEnabled()) return record.wallets.size;

  const userId = record.userId ?? null;
  const email = record.email ?? null;
  if (!userId && !email) {
    logger.warn({ keyHash: record.keyHash }, "Cannot recover sibling wallets: key has no user identity");
    return record.wallets.size;
  }

  try {
    const siblingRows = await loadApiKeysByUser(userId, email);
    if (siblingRows.length === 0) {
      logger.warn({ keyHash: record.keyHash, userId, email }, "No sibling API keys found for wallet recovery");
      return record.wallets.size;
    }

    const aggregatedWallets = siblingRows.flatMap((row) =>
      (row.wallet_ids ?? []).map(normalizeWalletId).filter(Boolean)
    );
    if (aggregatedWallets.length === 0) {
      return record.wallets.size;
    }

    for (const walletId of aggregatedWallets) {
      record.wallets.add(walletId);
    }

    await persistRecord(record);
    logger.info(
      {
        keyHash: record.keyHash,
        userId,
        email,
        siblingKeyCount: siblingRows.length,
        walletCount: record.wallets.size,
      },
      "Recovered API key wallets from sibling keys"
    );
    return record.wallets.size;
  } catch (error) {
    logger.error(
      { err: error, keyHash: record.keyHash, userId, email },
      "Failed recovering API key wallets from sibling keys"
    );
    return record.wallets.size;
  }
}

export async function bindGovernance(
  rawKey: string,
  bindingId: string,
  governanceId: string,
  mode: number
): Promise<void> {
  const record = getKeyRecord(rawKey);
  if (!record) return;
  const normalized = normalizeBindingId(bindingId);
  if (!normalized) return;
  record.governanceMap.set(normalized, { governanceId, mode });
  try {
    await persistRecord(record);
  } catch (error) {
    logger.error(
      { err: error, label: record.label, bindingId: normalized, governanceId },
      "Failed to persist governance mapping"
    );
  }
  logger.info({ label: record.label, bindingId: normalized, governanceId, mode }, "Governance mapping stored");
}

export async function bindGovernanceByBinding(
  bindingId: string,
  governanceId: string,
  mode: number
): Promise<void> {
  const normalized = normalizeBindingId(bindingId);
  if (!normalized) return;
  for (const record of registry.values()) {
    if (record.bindings.has(normalized)) {
      record.governanceMap.set(normalized, { governanceId, mode });
      try {
        await persistRecord(record);
      } catch (error) {
        logger.error(
          { err: error, keyHash: record.keyHash, bindingId: normalized, governanceId },
          "Failed to persist governance mapping (by binding)"
        );
      }
    }
  }
}

export async function bindProposal(rawKey: string, proposalId: string): Promise<void> {
  const record = getKeyRecord(rawKey);
  if (!record) return;
  const normalized = String(proposalId || "").trim().toLowerCase();
  if (!normalized) return;
  record.proposals.add(normalized);
  try {
    await persistRecord(record);
  } catch (error) {
    logger.error(
      { err: error, label: record.label, proposalId: normalized },
      "Failed to persist proposal ID"
    );
  }
  logger.info({ label: record.label, proposalId: normalized }, "Proposal ID stored on API key");
}

export async function activateGovernanceMapping(bindingId: string): Promise<void> {
  const normalized = normalizeBindingId(bindingId);
  if (!normalized) return;
  for (const record of registry.values()) {
    const existing = record.governanceMap.get(normalized);
    if (existing) {
      record.governanceMap.set(normalized, { ...existing, mode: 1 });
      try {
        await persistRecord(record);
      } catch (error) {
        logger.error(
          { err: error, keyHash: record.keyHash, bindingId: normalized },
          "Failed to persist governance activation"
        );
      }
    }
  }
}

export function keyOwnsWallet(rawKey: string, dwalletId: string): boolean {
  const record = getKeyRecord(rawKey);
  if (!record) return false;
  if (record.isAdmin) return true;
  return record.wallets.has(normalizeWalletId(dwalletId));
}

function maskRawKey(key: string): string {
  if (key.length <= 12) return "****";
  return key.slice(0, 6) + "..." + key.slice(-4);
}

function maskEmail(email: string): string {
  const at = email.indexOf("@");
  if (at <= 1) return "***@" + email.slice(at + 1);
  return email[0] + "***" + email.slice(at);
}
