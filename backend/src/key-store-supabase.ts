import { logger } from "./logger.js";
import { config } from "./config.js";

export interface PersistedApiKeyRow {
  key_hash: string;
  label: string;
  email: string | null;
  user_id: string | null;
  created_at: number;
  is_admin: boolean;
  tier: "default" | "premium";
  wallet_ids: string[];
  binding_ids: string[];
  governance_map: Record<string, { governanceId: string; mode: number }>;
  proposal_ids: string[];
}

const url = config.auth.supabaseUrl || process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const serviceKey = config.auth.supabaseServiceRoleKey || "";
const table = config.auth.apiKeysTable || "api_keys";

function enabled(): boolean {
  return Boolean(url && serviceKey);
}

function headers() {
  return {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    "Content-Type": "application/json",
    Prefer: "return=representation",
  } as Record<string, string>;
}

function endpoint(query = ""): string {
  const q = query ? `?${query}` : "";
  return `${url.replace(/\/$/, "")}/rest/v1/${table}${q}`;
}

export async function loadAllApiKeys(): Promise<PersistedApiKeyRow[] | null> {
  if (!enabled()) return null;
  const res = await fetch(
    endpoint("select=key_hash,label,email,user_id,created_at,is_admin,tier,wallet_ids,binding_ids,governance_map,proposal_ids"),
    {
    method: "GET",
    headers: headers(),
    }
  );
  if (!res.ok) {
    const body = await res.text();
    logger.error({ status: res.status, body }, "Failed loading API keys from Supabase");
    throw new Error(`Supabase load failed (${res.status})`);
  }
  return (await res.json()) as PersistedApiKeyRow[];
}

export async function loadApiKeyByHash(keyHash: string): Promise<PersistedApiKeyRow | null> {
  if (!enabled()) return null;
  const select = "select=key_hash,label,email,user_id,created_at,is_admin,tier,wallet_ids,binding_ids,governance_map,proposal_ids";
  const filter = `key_hash=eq.${encodeURIComponent(keyHash)}&limit=1`;
  const res = await fetch(endpoint(`${select}&${filter}`), {
    method: "GET",
    headers: headers(),
  });
  if (!res.ok) {
    const body = await res.text();
    logger.error({ status: res.status, body, keyHash }, "Failed loading API key by hash from Supabase");
    throw new Error(`Supabase load by hash failed (${res.status})`);
  }
  const rows = (await res.json()) as PersistedApiKeyRow[];
  return rows[0] ?? null;
}

export async function loadApiKeysByUser(
  userId: string | null,
  email: string | null
): Promise<PersistedApiKeyRow[]> {
  if (!enabled()) return [];
  const filters: string[] = [];
  if (userId) filters.push(`user_id.eq.${encodeURIComponent(userId)}`);
  if (email) filters.push(`email.eq.${encodeURIComponent(email)}`);
  if (filters.length === 0) return [];

  const select = "select=key_hash,label,email,user_id,created_at,is_admin,tier,wallet_ids,binding_ids,governance_map,proposal_ids";
  const res = await fetch(endpoint(`${select}&or=(${filters.join(",")})`), {
    method: "GET",
    headers: headers(),
  });
  if (!res.ok) {
    const body = await res.text();
    logger.error({ status: res.status, body, userId, email }, "Failed loading API keys by user from Supabase");
    throw new Error(`Supabase load by user failed (${res.status})`);
  }
  return (await res.json()) as PersistedApiKeyRow[];
}

export async function upsertApiKey(row: PersistedApiKeyRow): Promise<void> {
  if (!enabled()) return;
  const res = await fetch(endpoint("on_conflict=key_hash"), {
    method: "POST",
    headers: { ...headers(), Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(row),
  });
  if (!res.ok) {
    const body = await res.text();
    logger.error({ status: res.status, body, keyHash: row.key_hash }, "Failed upserting API key in Supabase");
    const reason = body ? body.slice(0, 240) : "unknown";
    throw new Error(`Supabase upsert failed (${res.status}): ${reason}`);
  }
}

export async function deleteApiKeyByHash(keyHash: string): Promise<void> {
  if (!enabled()) return;
  const res = await fetch(endpoint(`key_hash=eq.${encodeURIComponent(keyHash)}`), {
    method: "DELETE",
    headers: { ...headers(), Prefer: "return=minimal" },
  });
  if (!res.ok) {
    const body = await res.text();
    logger.error({ status: res.status, body, keyHash }, "Failed deleting API key in Supabase");
    throw new Error(`Supabase delete failed (${res.status})`);
  }
}

export function isSupabasePersistenceEnabled(): boolean {
  return enabled();
}
