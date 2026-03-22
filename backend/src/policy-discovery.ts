import { SuiClient } from "@mysten/sui/client";
import { config } from "./config.js";

export type DiscoveredPolicySummary = {
  objectId: string;
  policyType?: string;
  stableId?: string;
  version?: string;
  expiresAtMs?: string;
  allowToEvmCount?: number;
  denyToEvmCount?: number;
  allowDestinationsCount?: number;
  denyDestinationsCount?: number;
  rulesCount?: number;
  createdTxDigest?: string;
  createdAtMs?: number;
};

export type GenericRuleDetail = {
  ruleType: number;
  namespace: number;
  params: string;
};

export type PolicyDetails = {
  objectId: string;
  policyType?: string;
  stableId?: string;
  version?: string;
  expiresAtMs?: string;
  allowNamespaces?: number[];
  allowToEvm?: string[];
  denyToEvm?: string[];
  allowDestinations?: string[];
  denyDestinations?: string[];
  rules?: GenericRuleDetail[];
};

function isHexString(s: string): boolean {
  return /^0x[0-9a-fA-F]*$/.test(s);
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "0x";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function decodeU8VectorLikeToBytes(v: any): Uint8Array | null {
  if (!v) return null;

  // common: number[]
  if (Array.isArray(v) && v.every((x) => typeof x === "number")) {
    return new Uint8Array(v);
  }

  // newer JSON: base64 string or 0x hex string
  if (typeof v === "string") {
    if (isHexString(v)) {
      const hex = v.slice(2);
      if (hex.length % 2 !== 0) return null;
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      return out;
    }
    try {
      return new Uint8Array(Buffer.from(v, "base64"));
    } catch {
      return null;
    }
  }

  // wrappers: { bytes: "..." } / { data: "..." } / { value: "..." }
  if (typeof v === "object") {
    const inner = (v as any).bytes ?? (v as any).data ?? (v as any).value;
    if (inner !== undefined) return decodeU8VectorLikeToBytes(inner);
  }

  return null;
}

function decodeUtf8(bytes: Uint8Array | null): string | undefined {
  if (!bytes || bytes.length === 0) return undefined;
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return undefined;
  }
}

function decodeAddress20(addrBytesLike: any): string | undefined {
  const bytes = decodeU8VectorLikeToBytes(addrBytesLike);
  if (!bytes || bytes.length !== 20) return undefined;
  return bytesToHex(bytes);
}

function isPolicyType(typeStr: string): boolean {
  return /::policy_registry::Policy(V[0-9]+)?$/.test(typeStr);
}

function isPolicyVersionType(typeStr: string): boolean {
  return /::policy_registry::PolicyVersion$/.test(typeStr);
}

const RPC_BATCH_LIMIT = 50;

export function getSuiRpcUrlForNetwork(network: "testnet" | "mainnet"): string {
  if (config.sui.rpcUrl) return config.sui.rpcUrl;
  return network === "mainnet"
    ? "https://ikafn-on-sui-2-mainnet.ika-network.net/"
    : "https://rpc.testnet.sui.io";
}

async function multiGetTransactionBlocksChunked(
  client: SuiClient,
  digests: string[]
): Promise<any[]> {
  const out: any[] = [];
  for (let i = 0; i < digests.length; i += RPC_BATCH_LIMIT) {
    const chunk = digests.slice(i, i + RPC_BATCH_LIMIT);
    if (chunk.length === 0) continue;
    const batch = await client.multiGetTransactionBlocks({
      digests: chunk,
      options: { showObjectChanges: true, showEffects: true },
    });
    out.push(...batch);
  }
  return out;
}

async function multiGetObjectsChunked(
  client: SuiClient,
  ids: string[]
): Promise<any[]> {
  const out: any[] = [];
  for (let i = 0; i < ids.length; i += RPC_BATCH_LIMIT) {
    const chunk = ids.slice(i, i + RPC_BATCH_LIMIT);
    if (chunk.length === 0) continue;
    const batch = await client.multiGetObjects({
      ids: chunk,
      options: { showType: true, showContent: true },
    });
    out.push(...batch);
  }
  return out;
}

function decodeBytesArray(arr: any[]): string[] {
  return arr
    .map((x: any) => {
      const raw = x && typeof x === "object" && x.fields ? x : x;
      const bytes = decodeU8VectorLikeToBytes(raw);
      if (!bytes || bytes.length === 0) return undefined;
      return bytesToHex(bytes);
    })
    .filter(Boolean) as string[];
}

function decodeGenericRules(arr: any[]): GenericRuleDetail[] {
  return arr.map((item: any) => {
    const f = item && typeof item === "object" && item.fields ? item.fields : item;
    const params = decodeU8VectorLikeToBytes(f?.params);
    return {
      ruleType: Number(f?.rule_type ?? 0),
      namespace: Number(f?.namespace ?? 0),
      params: params ? bytesToHex(params) : "0x",
    };
  });
}

function decodePolicyDetailsFromFields(
  objectId: string,
  typeStr: string,
  fields: any
): PolicyDetails {
  if (!fields) return { objectId };

  const stableId = decodeUtf8(decodeU8VectorLikeToBytes(fields.policy_id));
  const version = decodeUtf8(decodeU8VectorLikeToBytes(fields.policy_version));

  const expiresAtMsRaw = fields.expires_at_ms;
  const expiresAtMs =
    typeof expiresAtMsRaw === "string" || typeof expiresAtMsRaw === "number"
      ? String(expiresAtMsRaw)
      : undefined;

  const isV4 = typeStr.endsWith("PolicyV4");
  const isV3 = typeStr.endsWith("PolicyV3");

  const allowNamespaces: number[] | undefined =
    isV4 && Array.isArray(fields.allow_namespaces)
      ? fields.allow_namespaces
          .map((x: any) => Number(x))
          .filter((x: number) => Number.isFinite(x))
      : undefined;

  const allowToEvm: string[] | undefined =
    !isV3 && !isV4 && Array.isArray(fields.allow_to_evm)
      ? (fields.allow_to_evm.map((x: any) => decodeAddress20(x)).filter(Boolean) as string[])
      : undefined;

  const denyToEvm: string[] | undefined =
    !isV3 && !isV4 && Array.isArray(fields.deny_to_evm)
      ? (fields.deny_to_evm.map((x: any) => decodeAddress20(x)).filter(Boolean) as string[])
      : undefined;

  const allowDestinations: string[] | undefined =
    (isV3 || isV4) && Array.isArray(fields.allow_destinations)
      ? decodeBytesArray(fields.allow_destinations)
      : undefined;

  const denyDestinations: string[] | undefined =
    (isV3 || isV4) && Array.isArray(fields.deny_destinations)
      ? decodeBytesArray(fields.deny_destinations)
      : undefined;

  const rules: GenericRuleDetail[] | undefined =
    isV4 && Array.isArray(fields.rules)
      ? decodeGenericRules(fields.rules)
      : undefined;

  return {
    objectId,
    policyType: isV4 ? "V4" : isV3 ? "V3" : "legacy",
    stableId,
    version,
    expiresAtMs,
    allowNamespaces,
    allowToEvm,
    denyToEvm,
    allowDestinations,
    denyDestinations,
    rules,
  };
}

export async function getPolicyDetails(
  client: SuiClient,
  objectId: string,
  createdByAddress?: string
): Promise<PolicyDetails | null> {
  const obj = await client.getObject({
    id: objectId,
    options: { showType: true, showContent: true },
  });

  const typeStr = (obj as any)?.data?.type as string | undefined;
  const fields = (obj as any)?.data?.content?.fields as any;
  if (!typeStr) return null;
  if (isPolicyType(typeStr)) {
    return decodePolicyDetailsFromFields(objectId, typeStr, fields);
  }

  if (!isPolicyVersionType(typeStr) || !fields || !createdByAddress?.startsWith("0x")) {
    return null;
  }

  const versionStableId = decodeUtf8(decodeU8VectorLikeToBytes(fields.stable_id));
  const versionLabel = decodeUtf8(decodeU8VectorLikeToBytes(fields.version));
  if (!versionStableId || !versionLabel) return null;

  const { policies } = await listPoliciesCreatedByAddress({
    client,
    address: createdByAddress,
<<<<<<< HEAD
    limit: 200,
=======
    limit: 50,
>>>>>>> 2e98de8 (fix(rpc): chunk batch calls to respect 50-item limit and add abort-14 retry)
  });
  const match = policies.find(
    (p) => p.stableId === versionStableId && p.version === versionLabel
  );
  if (!match?.objectId?.startsWith("0x")) return null;

  const resolved = await client.getObject({
    id: match.objectId,
    options: { showType: true, showContent: true },
  });
  const resolvedType = (resolved as any)?.data?.type as string | undefined;
  const resolvedFields = (resolved as any)?.data?.content?.fields as any;
  if (!resolvedType || !isPolicyType(resolvedType)) return null;

  return decodePolicyDetailsFromFields(match.objectId, resolvedType, resolvedFields);
}

export async function listPoliciesCreatedByAddress(args: {
  client: SuiClient;
  address: string;
  limit: number;
  cursor?: string | null;
}): Promise<{ policies: DiscoveredPolicySummary[]; nextCursor: string | null }> {
  const { client, address, limit, cursor } = args;

  const txPage = await client.queryTransactionBlocks({
    filter: { FromAddress: address },
    cursor: cursor ?? null,
    limit,
    order: "descending",
    options: {},
  });

  const created: Array<{
    objectId: string;
    createdTxDigest: string;
    createdAtMs?: number;
  }> = [];

  const digests = (txPage.data ?? [])
    .map((tx: any) => String(tx?.digest ?? ""))
    .filter((digest) => digest.length > 0);
  const createdAtByDigest = new Map<string, number | undefined>();
  for (const tx of txPage.data ?? []) {
    const digest = String((tx as any)?.digest ?? "");
    if (!digest) continue;
    const ts = (tx as any)?.timestampMs;
    const createdAtMs = typeof ts === "string" || typeof ts === "number" ? Number(ts) : undefined;
    createdAtByDigest.set(digest, createdAtMs);
  }

  if (digests.length > 0) {
    const txResults = await multiGetTransactionBlocksChunked(client, digests);
    for (const txResult of txResults) {
      const digest = String((txResult as any)?.digest ?? "");
      const createdAtMs = createdAtByDigest.get(digest);
      for (const c of (((txResult as any)?.objectChanges ?? []) as any[])) {
        if (c?.type !== "created") continue;
        const objectType = String(c?.objectType ?? "");
        const objectId = String(c?.objectId ?? "").trim();
        if (!objectId.startsWith("0x")) continue;
        if (!isPolicyType(objectType)) continue;
        created.push({ objectId, createdTxDigest: digest, createdAtMs });
      }
      for (const c of (((txResult as any)?.effects?.created ?? []) as any[])) {
        const objectId = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
        if (!objectId.startsWith("0x")) continue;
        created.push({ objectId, createdTxDigest: digest, createdAtMs });
      }
    }
  }

  const uniqueIds = Array.from(
    new Set(created.map((x) => x.objectId.toLowerCase()))
  );
  const originalsByLower = new Map<string, string>();
  for (const x of created) originalsByLower.set(x.objectId.toLowerCase(), x.objectId);

  const originals = uniqueIds
    .map((l) => originalsByLower.get(l))
    .filter(Boolean) as string[];

  const summaries: DiscoveredPolicySummary[] = [];

  if (originals.length === 0) {
    return { policies: [], nextCursor: txPage.nextCursor ?? null };
  }

  const objs = await multiGetObjectsChunked(client, originals);

  const createdMetaByLower = new Map(
    created.map((x) => [
      x.objectId.toLowerCase(),
      { createdTxDigest: x.createdTxDigest, createdAtMs: x.createdAtMs },
    ])
  );

  for (const o of objs) {
    const objectId = (o as any)?.data?.objectId as string | undefined;
    const typeStr = (o as any)?.data?.type as string | undefined;
    if (!objectId || !typeStr || !isPolicyType(typeStr)) continue;

    const fields = (o as any)?.data?.content?.fields as any;
    const stableId = decodeUtf8(decodeU8VectorLikeToBytes(fields?.policy_id));
    const version = decodeUtf8(decodeU8VectorLikeToBytes(fields?.policy_version));
    const expiresAtMsRaw = fields?.expires_at_ms;
    const expiresAtMs =
      typeof expiresAtMsRaw === "string" || typeof expiresAtMsRaw === "number"
        ? String(expiresAtMsRaw)
        : undefined;

    const isV4 = typeStr.endsWith("PolicyV4");
    const isV3 = typeStr.endsWith("PolicyV3");

    const allowToEvmCount = !isV3 && !isV4 && Array.isArray(fields?.allow_to_evm)
      ? fields.allow_to_evm.length
      : undefined;
    const denyToEvmCount = !isV3 && !isV4 && Array.isArray(fields?.deny_to_evm)
      ? fields.deny_to_evm.length
      : undefined;
    const allowDestinationsCount = (isV3 || isV4) && Array.isArray(fields?.allow_destinations)
      ? fields.allow_destinations.length
      : undefined;
    const denyDestinationsCount = (isV3 || isV4) && Array.isArray(fields?.deny_destinations)
      ? fields.deny_destinations.length
      : undefined;
    const rulesCount = isV4 && Array.isArray(fields?.rules)
      ? fields.rules.length
      : undefined;

    const meta = createdMetaByLower.get(objectId.toLowerCase());

    summaries.push({
      objectId,
      policyType: isV4 ? "V4" : isV3 ? "V3" : "legacy",
      stableId,
      version,
      expiresAtMs,
      allowToEvmCount,
      denyToEvmCount,
      allowDestinationsCount,
      denyDestinationsCount,
      rulesCount,
      createdTxDigest: meta?.createdTxDigest || undefined,
      createdAtMs: meta?.createdAtMs,
    });
  }

  return { policies: summaries, nextCursor: txPage.nextCursor ?? null };
}

