/**
 * Policy Routes - Policy management and receipts
 *
 * Handles:
 * - Policy creation
 * - Policy registry and version management
 * - Policy binding
 * - Receipt minting
 * - Policy discovery
 * - Debug utilities
 */

import { Elysia, t } from "elysia";
import { SuiClient } from "@mysten/sui/client";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { dkgExecutor } from "../dkg-executor.js";
import {
  getPolicyDetails,
  getSuiRpcUrlForNetwork,
  listPoliciesCreatedByAddress,
} from "../policy-discovery.js";
import {
  keyOwnsWallet,
  isAuthEnabled,
  getKeyRecord,
  refreshWalletsFromSupabase,
  recoverWalletsFromSiblingKeys,
  bindBinding,
} from "../key-registry.js";

const HEX_RE = /^(0x)?[0-9a-fA-F]*$/;
function assertValidHex(value: string, label: string): void {
  if (!HEX_RE.test(value)) {
    throw new Error(`${label}: invalid hex characters`);
  }
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  if (raw.length % 2 !== 0) {
    throw new Error(`${label}: odd-length hex (${raw.length} chars)`);
  }
}

// Separate Sui client for read-only discovery calls
const suiDiscoveryClient = new SuiClient({
  url: getSuiRpcUrlForNetwork(config.sui.network),
});

async function resolveDwalletIdFromBinding(bindingObjectId: string): Promise<string | null> {
  try {
    const obj = await suiDiscoveryClient.getObject({
      id: bindingObjectId,
      options: { showContent: true },
    });
    const fields = (obj.data as any)?.content?.fields;
    const raw = fields?.dwallet_id;
    if (!raw) return null;
    const bytes: number[] = Array.isArray(raw)
      ? raw
      : raw?.fields
        ? (Array.isArray(raw.fields) ? raw.fields : [])
        : [];
    if (bytes.length === 0) return null;
    return "0x" + Buffer.from(bytes).toString("hex");
  } catch {
    return null;
  }
}

function bytesLikeToUtf8(value: unknown): string {
  if (typeof value === "string") {
    const str = value as string;
    if (str.startsWith("0x")) {
      try {
        const hex = str.slice(2);
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        }
        return new TextDecoder().decode(bytes);
      } catch {
        return str;
      }
    }
    try {
      return new TextDecoder().decode(Uint8Array.from(Buffer.from(str, "base64")));
    } catch {
      return str;
    }
  }
  if (Array.isArray(value)) {
    try {
      return new TextDecoder().decode(Uint8Array.from(value as number[]));
    } catch {
      return "";
    }
  }
  if (value && typeof value === "object") {
    const inner = (value as any).bytes ?? (value as any).data ?? (value as any).value ?? (value as any).fields;
    if (inner !== undefined) return bytesLikeToUtf8(inner);
  }
  return "";
}

function extractRawBytes(value: unknown): number[] {
  if (Array.isArray(value)) {
    return value.filter((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255) as number[];
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith("0x")) {
      try {
        const hex = trimmed.slice(2);
        if (hex.length === 0 || hex.length % 2 !== 0) return [];
        return Array.from(Buffer.from(hex, "hex"));
      } catch {
        return [];
      }
    }
    return [];
  }
  if (value && typeof value === "object") {
    const inner = (value as any).bytes ?? (value as any).data ?? (value as any).value ?? (value as any).fields;
    if (inner !== undefined) return extractRawBytes(inner);
  }
  return [];
}

function packageIdFromType(type: string): string | null {
  const normalized = String(type ?? "").trim();
  if (!normalized.includes("::")) return null;
  const pkg = normalized.split("::")[0] ?? "";
  return pkg.startsWith("0x") ? pkg : null;
}

async function resolvePolicyBindingPackageIds(configuredPolicyPkg: string): Promise<string[]> {
  const ids: string[] = [];
  const seen = new Set<string>();
  const add = (id: string | null | undefined) => {
    const normalized = String(id ?? "").trim();
    if (!normalized.startsWith("0x")) return;
    const key = normalized.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    ids.push(normalized);
  };

  add(configuredPolicyPkg);

  const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();
  if (registryId.startsWith("0x")) {
    try {
      const registryObj = await suiDiscoveryClient.getObject({
        id: registryId,
        options: { showType: true },
      });
      add(packageIdFromType(String((registryObj as any)?.data?.type ?? "")));
    } catch {
      // ignore; fall back to configured package id only
    }
  }

  return ids;
}

async function queryMoveStructObjects(params: {
  moveStructType: string;
  cursor: string | null;
  limit: number;
}): Promise<{ data: any[]; nextCursor: string | null; hasNextPage: boolean }> {
  const request = {
    query: { MoveStructType: params.moveStructType },
    cursor: params.cursor,
    limit: params.limit,
    options: { showContent: true, showType: true },
  };

  const client = suiDiscoveryClient as any;
  if (typeof client.queryObjects === "function") {
    const res = await client.queryObjects(request);
    return {
      data: Array.isArray(res?.data) ? res.data : [],
      nextCursor: (res?.nextCursor as string | null) ?? null,
      hasNextPage: Boolean(res?.hasNextPage),
    };
  }

  if (typeof client.call === "function") {
    const res = await client.call("suix_queryObjects", [request]);
    return {
      data: Array.isArray(res?.data) ? res.data : [],
      nextCursor: (res?.nextCursor as string | null) ?? null,
      hasNextPage: Boolean(res?.hasNextPage),
    };
  }

  if (typeof client.transport?.request === "function") {
    const res = await client.transport.request({
      method: "suix_queryObjects",
      params: [request],
    });
    return {
      data: Array.isArray(res?.data) ? res.data : [],
      nextCursor: (res?.nextCursor as string | null) ?? null,
      hasNextPage: Boolean(res?.hasNextPage),
    };
  }

  throw new Error("Sui client does not support queryObjects or suix_queryObjects");
}

async function scanPolicyBindingsFromAdminTxs(): Promise<any[]> {
  const adminAddress = dkgExecutor.getAdminAddress();
  if (!adminAddress.startsWith("0x")) return [];

  const digests: string[] = [];
  let cursor: string | null = null;

  for (let page = 0; page < 20; page++) {
    const txPage = await suiDiscoveryClient.queryTransactionBlocks({
      filter: { FromAddress: adminAddress },
      cursor,
      limit: 50,
      order: "descending",
      options: {},
    });

    for (const tx of txPage.data ?? []) {
      if (tx.digest) digests.push(tx.digest);
    }

    cursor = (txPage as any)?.nextCursor ?? null;
    if (!(txPage as any)?.hasNextPage || !cursor) break;
  }

  if (digests.length === 0) return [];

  const ids: string[] = [];
  const seen = new Set<string>();
  const BATCH = 50;

  for (let i = 0; i < digests.length; i += BATCH) {
    const batch = digests.slice(i, i + BATCH);
    const txResults = await suiDiscoveryClient.multiGetTransactionBlocks({
      digests: batch,
      options: { showObjectChanges: true, showEffects: true },
    });
    for (const txResult of txResults) {
      for (const change of ((txResult as any)?.objectChanges ?? []) as any[]) {
        if (change?.type !== "created") continue;
        const objectType = String(change?.objectType ?? "");
        const objectId = String(change?.objectId ?? "").trim();
        if (!objectId.startsWith("0x")) continue;
        if (!objectType.endsWith("::policy_registry::PolicyBinding")) continue;
        const key = objectId.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        ids.push(objectId);
      }
      if (ids.length === 0) {
        for (const c of ((txResult as any)?.effects?.created ?? []) as any[]) {
          const objectId = String(c?.reference?.objectId ?? c?.objectId ?? "").trim();
          if (!objectId.startsWith("0x") || seen.has(objectId.toLowerCase())) continue;
          seen.add(objectId.toLowerCase());
          ids.push(objectId);
        }
      }
    }
  }

  if (ids.length === 0) return [];
  const objects = await suiDiscoveryClient.multiGetObjects({
    ids,
    options: { showContent: true, showType: true },
  });
  return Array.isArray(objects) ? objects : [];
}

async function getBindingGovernance(
  bindingId: string,
  fallbackMap?: Map<string, { governanceId: string; mode: number }>
): Promise<{ governanceId: string | null; mode: number | null }> {
  try {
    const dynamicFields = await suiDiscoveryClient.getDynamicFields({ parentId: bindingId });
    const governanceField = (dynamicFields.data ?? []).find((f: any) =>
      String(f?.name?.type ?? "").includes("GovernanceMarker")
    );
    if (!governanceField) {
      const stored = fallbackMap?.get(bindingId.toLowerCase());
      if (stored) {
        logger.info({ bindingId, source: "stored" }, "Governance resolved from stored map (no on-chain marker)");
        return { governanceId: stored.governanceId, mode: stored.mode };
      }
      return { governanceId: null, mode: null };
    }

    const df = await suiDiscoveryClient.getDynamicFieldObject({
      parentId: bindingId,
      name: governanceField.name,
    });
    const infoFields: any = (df as any)?.data?.content?.fields?.value?.fields
      ?? (df as any)?.data?.content?.fields?.value
      ?? {};
    const rawGovernanceId = infoFields?.governance_id;
    const governanceId =
      typeof rawGovernanceId === "string"
        ? rawGovernanceId
        : String(rawGovernanceId?.id ?? rawGovernanceId?.bytes ?? rawGovernanceId?.value ?? "");
    const mode = Number(infoFields?.mode ?? 0);
    return { governanceId: governanceId || null, mode };
  } catch (error) {
    logger.warn(
      { err: error instanceof Error ? error.message : String(error), bindingId },
      "getBindingGovernance on-chain lookup failed"
    );
    const stored = fallbackMap?.get(bindingId.toLowerCase());
    if (stored) {
      logger.info({ bindingId, source: "stored" }, "Governance resolved from stored map (on-chain lookup failed)");
      return { governanceId: stored.governanceId, mode: stored.mode };
    }
    return { governanceId: null, mode: null };
  }
}

export const policyRoutes = new Elysia({ prefix: "/api" })
  // --- Policy Registry ---
  .post(
    "/policy/registry/create",
    async ({ set }) => {
      try {
        const r = await dkgExecutor.createAndSharePolicyRegistry();
        return {
          success: true,
          registryObjectId: r.registryObjectId,
          digest: r.digest,
        };
      } catch (error) {
        set.status = 500;
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
    {
      detail: {
        summary: "Create and share PolicyRegistry",
        description:
          "Creates a shared PolicyRegistry object on Sui (used for policy version commitments and PolicyBinding).",
      },
    }
  )

  .post(
    "/policy/registry/register-from-policy",
    async ({ body, set }) => {
      try {
        const policyObjectId = String((body as any)?.policyObjectId ?? "").trim();
        const note = String((body as any)?.note ?? "policy publish").trim();
        const registryObjectId = (body as any)?.registryObjectId
          ? String((body as any).registryObjectId).trim()
          : undefined;
        if (!policyObjectId.startsWith("0x"))
          throw new Error("Invalid policyObjectId");

        const r = await dkgExecutor.registerPolicyVersionFromPolicy({
          registryObjectId,
          policyObjectId,
          note,
        });
        return {
          success: true,
          policyVersionObjectId: r.policyVersionObjectId,
          digest: r.digest,
        };
      } catch (error) {
        set.status = 500;
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
    {
      body: t.Object({
        policyObjectId: t.String(),
        note: t.Optional(t.String()),
        registryObjectId: t.Optional(t.String()),
      }),
      detail: {
        summary: "Register PolicyVersion (from Policy)",
        description:
          "Computes policy_root on-chain from the Policy object and registers a PolicyVersion in the PolicyRegistry.",
      },
    }
  )

  // --- Policy Binding ---
  .post(
    "/policy/binding/create",
    async ({ body, set, request }) => {
      try {
        const dWalletId = String((body as any)?.dWalletId ?? "").trim();

        // Wallet ownership check
        if (isAuthEnabled()) {
          const callerKey = request.headers.get("x-kairo-api-key") ?? "";
          if (!keyOwnsWallet(callerKey, dWalletId)) {
            set.status = 403;
            return { success: false, error: "Forbidden: API key does not own this wallet" };
          }
        }

        const stableIdRaw = String((body as any)?.stableId ?? "").trim();
        const policyObjectId = String((body as any)?.policyObjectId ?? "").trim();
        const registryObjectId = (body as any)?.registryObjectId
          ? String((body as any).registryObjectId).trim()
          : undefined;

        // Derive stableId from on-chain policy if available
        let stableId = stableIdRaw;
        if (policyObjectId.startsWith("0x")) {
          try {
            const fromPolicy =
              await dkgExecutor.resolvePolicyStableIdString(policyObjectId);
            if (fromPolicy) stableId = fromPolicy;
          } catch {
            // ignore
          }
        }

        // Best-effort: ensure a PolicyVersion exists before binding
        if (policyObjectId.startsWith("0x")) {
          try {
            await dkgExecutor.registerPolicyVersionFromPolicy({
              registryObjectId,
              policyObjectId,
              note: `auto-register before binding (${stableId})`,
            });
          } catch {
            // ignore
          }
        }

        let r: Awaited<ReturnType<typeof dkgExecutor.createPolicyBinding>>;
        try {
          r = await dkgExecutor.createPolicyBinding({
            registryObjectId,
            dWalletId,
            stableId,
          });
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          const m =
            msg.match(/abort_code:\s*(\d+)/) ??
            msg.match(/MoveAbort\([\s\S]*?,\s*(\d+)\)\s+in\s+command/i);
          const abortCode = m ? Number(m[1]) : NaN;
          // E_NO_VERSIONS = 102
          if (abortCode === 102 && policyObjectId.startsWith("0x")) {
            await dkgExecutor.registerPolicyVersionFromPolicy({
              registryObjectId,
              policyObjectId,
              note: `auto-register after E_NO_VERSIONS (${stableId})`,
            });
            r = await dkgExecutor.createPolicyBinding({
              registryObjectId,
              dWalletId,
              stableId,
            });
          } else {
            throw e;
          }
        }

        const callerKey = request.headers.get("x-kairo-api-key") ?? "";
        if (callerKey && r.bindingObjectId) {
          await bindBinding(callerKey, r.bindingObjectId);
        }

        return {
          success: true,
          bindingObjectId: r.bindingObjectId,
          digest: r.digest,
          activeVersionObjectId: r.activeVersionObjectId,
        };
      } catch (error) {
        logger.error(
          {
            err: error,
            dWalletId: (body as any)?.dWalletId,
            stableId: (body as any)?.stableId,
            policyObjectId: (body as any)?.policyObjectId,
            registryObjectId: (body as any)?.registryObjectId,
          },
          "Policy binding create failed"
        );
        set.status = 500;
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
          ...(error instanceof Error && error.stack ? { stack: error.stack } : {}),
        };
      }
    },
    {
      body: t.Object({
        dWalletId: t.String(),
        stableId: t.String(),
        policyObjectId: t.Optional(t.String()),
        registryObjectId: t.Optional(t.String()),
      }),
      detail: {
        summary: "Create PolicyBinding",
        description:
          "Creates and shares a PolicyBinding linking a dWallet to a stable policy id.",
      },
    }
  )

  .post(
    "/policy/binding/reaffirm",
    async ({ body, set, request }) => {
      try {
        const bindingObjectId = String(
          (body as any)?.bindingObjectId ?? ""
        ).trim();
        const registryObjectId = (body as any)?.registryObjectId
          ? String((body as any).registryObjectId).trim()
          : undefined;
        if (!bindingObjectId.startsWith("0x"))
          throw new Error("Invalid bindingObjectId");

        const reaffirmCallerKey = request.headers.get("x-kairo-api-key") ?? "";
        const reaffirmRecord = reaffirmCallerKey ? getKeyRecord(reaffirmCallerKey) : null;
        const governance = await getBindingGovernance(bindingObjectId, reaffirmRecord?.governanceMap);
        if (governance.governanceId && Number(governance.mode ?? 0) !== 0) {
          set.status = 409;
          return {
            success: false,
            error:
              "Binding is governed and requires governance receipt flow. Use /api/policy/governance/execute-and-reaffirm.",
            governanceId: governance.governanceId,
            governanceMode: governance.mode,
          };
        }

        const r = await dkgExecutor.reaffirmPolicyBinding({
          registryObjectId,
          bindingObjectId,
        });
        return {
          success: true,
          digest: r.digest,
          activeVersionObjectId: r.activeVersionObjectId,
        };
      } catch (error) {
        set.status = 500;
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
    {
      body: t.Object({
        bindingObjectId: t.String(),
        registryObjectId: t.Optional(t.String()),
      }),
      detail: {
        summary: "Reaffirm PolicyBinding",
        description:
          "Updates a PolicyBinding to the latest PolicyVersion for its stable id.",
      },
    }
  )

  // --- Debug utilities ---
  .get(
    "/policy/debug/resolve/:policyId",
    async ({ params, set }) => {
      const policyId = String(params.policyId || "").trim();
      if (!policyId.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "Invalid policyId" };
      }

      const obj = await suiDiscoveryClient.getObject({
        id: policyId,
        options: { showType: true, showOwner: true },
      });

      const policyType = String((obj as any)?.data?.type ?? "");
      const policyPkg = policyType.split("::")[0] ?? "";
      const sharedVersionRaw = (obj as any)?.data?.owner?.Shared
        ?.initial_shared_version;
      const initialSharedVersion = Number(sharedVersionRaw ?? 0);

      return {
        success: true,
        policyId,
        policyType: policyType || undefined,
        policyPkg: policyPkg || undefined,
        initialSharedVersion: Number.isFinite(initialSharedVersion)
          ? initialSharedVersion
          : undefined,
      };
    },
    {
      params: t.Object({ policyId: t.String() }),
      detail: {
        summary: "Debug: resolve policy package id",
        description:
          "Fetches the Policy object's type/owner and returns the inferred package id + shared initial version.",
      },
    }
  )

  .get(
    "/policy/debug/functions/:packageId",
    async ({ params, set }) => {
      const packageId = String(params.packageId || "").trim();
      if (!packageId.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "Invalid packageId" };
      }

      try {
        const mod = await suiDiscoveryClient.getNormalizedMoveModule({
          package: packageId,
          module: "policy_registry",
        });
        const exposedFunctions = Object.keys(
          (mod as any)?.exposedFunctions ?? (mod as any)?.functions ?? {}
        ).sort();

        return {
          success: true,
          packageId,
          module: "policy_registry",
          exposedFunctions,
        };
      } catch (error) {
        set.status = 500;
        return {
          success: false,
          error:
            error instanceof Error
              ? error.message
              : "Failed to fetch normalized module",
        };
      }
    },
    {
      params: t.Object({ packageId: t.String() }),
      detail: {
        summary: "Debug: list policy_registry functions",
        description:
          "Returns the exposed function names for `policy_registry` in the given Move package id.",
      },
    }
  )

  // --- Policy Registry: Latest Version Lookup ---
  .get(
    "/policy/registry/latest",
    async ({ query, set }) => {
      try {
        const stableId = String((query as any)?.stableId ?? "").trim();
        if (!stableId) {
          set.status = 400;
          return { success: false, error: "Missing stableId query parameter" };
        }

        const registryId = String((config.kairo as any).policyRegistryId ?? "").trim();
        if (!registryId.startsWith("0x")) {
          set.status = 500;
          return {
            success: false,
            error: "PolicyRegistry not configured (KAIRO_POLICY_REGISTRY_ID)",
          };
        }

        // Fetch the registry object
        const registryObj = await suiDiscoveryClient.getObject({
          id: registryId,
          options: { showType: true, showContent: true },
        });
        const registryType = String((registryObj as any)?.data?.type ?? "");
        if (!registryType.endsWith("::policy_registry::PolicyRegistry")) {
          set.status = 500;
          return {
            success: false,
            error: `KAIRO_POLICY_REGISTRY_ID is not a PolicyRegistry (type=${registryType})`,
          };
        }

        const registryFields: any = (registryObj as any)?.data?.content?.fields ?? {};
        const series: any[] = Array.isArray(registryFields["series"])
          ? (registryFields["series"] as any[])
          : [];

        // Helper to parse bytes to UTF-8 string
        const bytesFieldToUtf8 = (v: unknown): string => {
          if (!v) return "";
          let arr: number[] | null = null;
          if (Array.isArray(v) && v.every((x) => Number.isInteger(x) && x >= 0 && x <= 255)) {
            arr = v as number[];
          } else if (typeof v === "object") {
            const o: any = v;
            if (o.bytes != null) return bytesFieldToUtf8(o.bytes);
            if (o.data != null) return bytesFieldToUtf8(o.data);
            if (o.value != null) return bytesFieldToUtf8(o.value);
            if (o.fields != null) return bytesFieldToUtf8(o.fields);
          }
          if (!arr) return "";
          return new TextDecoder().decode(Uint8Array.from(arr));
        };

        // Find the series matching the stableId
        let latestPolicyVersionId: string | null = null;
        for (const s0 of series) {
          const s = s0 && typeof s0 === "object" && (s0 as any).fields ? (s0 as any).fields : s0;
          const sid = bytesFieldToUtf8((s as any)?.stable_id);
          if (!sid || sid !== stableId) continue;
          const versions: any = (s as any)?.versions;
          if (!Array.isArray(versions) || versions.length === 0) {
            return {
              success: true,
              stableId,
              latestVersion: null,
              latestPolicyVersionId: null,
              message: "Series exists but has no versions yet",
            };
          }
          const last = String(versions[versions.length - 1] ?? "").trim();
          if (last.startsWith("0x")) {
            latestPolicyVersionId = last;
          }
          break;
        }

        if (!latestPolicyVersionId) {
          return {
            success: true,
            stableId,
            latestVersion: null,
            latestPolicyVersionId: null,
            message: "No series found for this stableId",
          };
        }

        // Fetch the PolicyVersion object to get the semantic version string
        const versionObj = await suiDiscoveryClient.getObject({
          id: latestPolicyVersionId,
          options: { showType: true, showContent: true },
        });
        const versionType = String((versionObj as any)?.data?.type ?? "");
        if (!versionType.endsWith("::policy_registry::PolicyVersion")) {
          return {
            success: true,
            stableId,
            latestVersion: null,
            latestPolicyVersionId,
            message: `PolicyVersion object type mismatch (type=${versionType})`,
          };
        }

        const versionFields: any = (versionObj as any)?.data?.content?.fields ?? {};
        const versionBytes = versionFields["version"];
        const latestVersion = bytesFieldToUtf8(versionBytes);

        return {
          success: true,
          stableId,
          latestVersion: latestVersion || null,
          latestPolicyVersionId,
        };
      } catch (error) {
        logger.error({ err: error }, "Failed to fetch latest policy version");
        set.status = 500;
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
    {
      query: t.Object({
        stableId: t.String(),
      }),
      detail: {
        summary: "Get latest policy version for a stableId",
        description:
          "Fetches the PolicyRegistry, finds the series for the given stableId, and returns the latest semantic version string and PolicyVersion object ID.",
      },
    }
  )

  // --- Policy Discovery ---
  .get(
    "/policies/user",
    async ({ request, set }) => {
      try {
        const callerKey = request.headers.get("x-kairo-api-key") ?? "";
        const record = getKeyRecord(callerKey);
        if (!record) {
          set.status = 401;
          return { success: false, error: "Unauthorized: invalid API key" };
        }

        const policyPkg = String((config.kairo as any).policyMintPackageId ?? "").trim();
        if (!policyPkg.startsWith("0x")) {
          set.status = 500;
          return { success: false, error: "Policy package id is not configured" };
        }

        const packageIdsToQuery = await resolvePolicyBindingPackageIds(policyPkg);
        if (packageIdsToQuery.length === 0) {
          set.status = 500;
          return { success: false, error: "No valid policy package id resolved" };
        }

        let walletIds = record.isAdmin ? null : new Set(Array.from(record.wallets));
        if (!record.isAdmin && (!walletIds || walletIds.size === 0)) {
          const refreshedWalletCount = await refreshWalletsFromSupabase(callerKey);
          if (refreshedWalletCount > 0) {
            walletIds = new Set(Array.from(record.wallets));
          }
        }
        if (!record.isAdmin && (!walletIds || walletIds.size === 0)) {
          const recoveredWalletCount = await recoverWalletsFromSiblingKeys(callerKey);
          if (recoveredWalletCount > 0) {
            walletIds = new Set(Array.from(record.wallets));
          }
        }
        if (!record.isAdmin && (!walletIds || walletIds.size === 0)) {
          return {
            success: true,
            policies: [],
            _debug: {
              isAdmin: record.isAdmin,
              walletCount: record.wallets.size,
              packageId: policyPkg,
              packageIdsQueried: packageIdsToQuery,
              reason: "no_wallets_bound",
            },
          };
        }

        const out: Array<{
          bindingId: string;
          dWalletId: string;
          stableId: string;
          activeVersionId: string | null;
          governanceId: string | null;
          governanceMode: number | null;
          isGoverned: boolean;
        }> = [];
        const seenBindingIds = new Set<string>();
        const packageMatchCounts: Record<string, number> = {};
        const walletIdsForFilter = !record.isAdmin && walletIds ? Array.from(walletIds) : null;
        const sampleDwalletIds: string[] = [];
        let totalItemsScanned = 0;
        let skippedNoObjectId = 0;
        let skippedWrongType = 0;
        let skippedDuplicate = 0;
        let skippedEmptyDwalletId = 0;
        let skippedWalletMismatch = 0;
        let usedDirectLookup = false;
        let usedTxScanFallback = false;
        const processItems = async (items: any[], sourceLabel: string) => {
          for (const o of items) {
            totalItemsScanned += 1;
            const objectId = String((o as any)?.data?.objectId ?? "").trim();
            const type = String((o as any)?.data?.type ?? "").trim();
            if (!objectId.startsWith("0x")) {
              skippedNoObjectId += 1;
              continue;
            }
            if (!type.endsWith("::policy_registry::PolicyBinding")) {
              skippedWrongType += 1;
              continue;
            }
            if (seenBindingIds.has(objectId)) {
              skippedDuplicate += 1;
              continue;
            }

            const fields: any = (o as any)?.data?.content?.fields ?? {};
            let dWalletId = bytesLikeToUtf8(fields?.dwallet_id).trim();
            if (!dWalletId || !dWalletId.startsWith("0x")) {
              // Backward-compatibility for bindings created with raw hex bytes.
              const rawBytes = extractRawBytes(fields?.dwallet_id);
              if (rawBytes.length > 0) {
                dWalletId = `0x${Buffer.from(rawBytes).toString("hex")}`;
              }
            }
            if (!dWalletId) {
              skippedEmptyDwalletId += 1;
              continue;
            }
            if (sampleDwalletIds.length < 5) {
              sampleDwalletIds.push(dWalletId);
            }
            if (!record.isAdmin && walletIds && !walletIds.has(dWalletId.toLowerCase())) {
              skippedWalletMismatch += 1;
              continue;
            }

            const stableId = bytesLikeToUtf8(fields?.stable_id).trim();
            const activeVersionRaw = String(fields?.active_version_id ?? "").trim();
            const activeVersionId = activeVersionRaw.startsWith("0x") ? activeVersionRaw : null;
            const governance = await getBindingGovernance(objectId, record.governanceMap);

            out.push({
              bindingId: objectId,
              dWalletId,
              stableId,
              activeVersionId,
              governanceId: governance.governanceId,
              governanceMode: governance.mode,
              isGoverned: !!governance.governanceId,
            });
            seenBindingIds.add(objectId);
            packageMatchCounts[sourceLabel] = (packageMatchCounts[sourceLabel] ?? 0) + 1;
          }
        };

        const storedBindingIds = Array.from(record.bindings ?? [])
          .map((id) => String(id ?? "").trim().toLowerCase())
          .filter((id) => id.startsWith("0x"));
        if (storedBindingIds.length > 0) {
          try {
            const objs = await suiDiscoveryClient.multiGetObjects({
              ids: storedBindingIds,
              options: { showContent: true, showType: true },
            });
            await processItems(Array.isArray(objs) ? objs : [], "stored_bindings");
            usedDirectLookup = true;
          } catch (error) {
            logger.warn({ err: error }, "Direct PolicyBinding lookup from stored IDs failed");
          }
        }

        for (const packageId of packageIdsToQuery) {

          try {
            let cursor: string | null = null;
            for (let page = 0; page < 10; page++) {
              const res = await queryMoveStructObjects({
                moveStructType: `${packageId}::policy_registry::PolicyBinding`,
                cursor,
                limit: 50,
              });
              const items = (res as any)?.data ?? [];
              await processItems(items, packageId);

              cursor = ((res as any)?.nextCursor as string | null) ?? null;
              if (!(res as any)?.hasNextPage || !cursor) break;
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            const isMethodNotFound = /method not found/i.test(message);
            if (!isMethodNotFound) throw error;

            logger.warn(
              { packageId, err: message },
              "Policy discovery queryObjects unavailable; falling back to tx scan"
            );
            const fallbackItems = await scanPolicyBindingsFromAdminTxs();
            await processItems(fallbackItems, packageId);
            usedTxScanFallback = true;
          }
        }

        if (out.length === 0) {
          logger.warn(
            {
              isAdmin: record.isAdmin,
              walletCount: record.wallets.size,
              packageId: policyPkg,
              packageIdsQueried: packageIdsToQuery,
            },
            "No visible policy bindings for caller"
          );
        }

        return {
          success: true,
          policies: out,
          _debug: {
            isAdmin: record.isAdmin,
            walletCount: record.wallets.size,
            packageId: policyPkg,
            packageIdsQueried: packageIdsToQuery,
            packageMatchCounts,
            totalItemsScanned,
            skippedNoObjectId,
            skippedWrongType,
            skippedDuplicate,
            skippedEmptyDwalletId,
            skippedWalletMismatch,
            sampleDwalletIds,
            walletIdsForFilter,
            storedBindingIds,
            queryMethod: usedDirectLookup
              ? "direct_lookup"
              : (usedTxScanFallback ? "tx_scan_fallback" : "query_objects"),
            reason: out.length === 0 ? "no_visible_policies" : undefined,
          },
        };
      } catch (error) {
        logger.error({ err: error }, "Failed to list user policies");
        set.status = 500;
        return {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
    {
      detail: {
        summary: "List policy bindings for current API key",
        description:
          "Returns PolicyBinding objects for wallets owned by the caller API key, including governance info when present.",
      },
    }
  )

  .get(
    "/policies/created/:address",
    async ({ params, query, set }) => {
      const address = String(params.address || "").trim();
      if (!address.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "Invalid Sui address" };
      }

      const limitRaw = Number((query as any)?.limit ?? 20);
      const limit = Number.isFinite(limitRaw)
        ? Math.max(1, Math.min(50, Math.floor(limitRaw)))
        : 20;
      const cursor = (query as any)?.cursor
        ? String((query as any).cursor)
        : null;

      const { policies, nextCursor } = await listPoliciesCreatedByAddress({
        client: suiDiscoveryClient,
        address,
        limit,
        cursor,
      });

      return { success: true, policies, nextCursor };
    },
    {
      params: t.Object({ address: t.String() }),
      query: t.Optional(
        t.Object({
          limit: t.Optional(t.String()),
          cursor: t.Optional(t.String()),
        })
      ),
      detail: {
        summary: "List policies created by an address",
        description:
          "Scans recent transaction blocks from the address and returns created Policy objects.",
      },
    }
  )

  .get(
    "/policies/:objectId",
    async ({ params, set }) => {
      const objectId = String(params.objectId || "").trim();
      if (!objectId.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "Invalid policy object id" };
      }

      const policy = await getPolicyDetails(
        suiDiscoveryClient,
        objectId,
        dkgExecutor.getAdminAddress()
      );
      if (!policy) {
        set.status = 404;
        return { success: false, error: "Policy not found" };
      }

      return { success: true, policy };
    },
    {
      params: t.Object({ objectId: t.String() }),
      detail: {
        summary: "Fetch policy details",
        description:
          "Fetches the on-chain Policy object and returns decoded fields.",
      },
    }
  )

  // --- Policy Creation ---
  .post(
    "/policy/create",
    async ({ body, set }) => {
      try {
        const stableId = String(body.stableId ?? "").trim();
        const version = String(body.version ?? "").trim();
        if (!stableId) throw new Error("Missing stableId");
        if (!version) throw new Error("Missing version");

        for (const addr of body.allowDestinations ?? []) {
          assertValidHex(addr, "allowDestinations");
        }
        for (const addr of body.denyDestinations ?? []) {
          assertValidHex(addr, "denyDestinations");
        }
        for (const cid of body.allowChainIds ?? []) {
          assertValidHex(cid.chainId, "allowChainIds[].chainId");
        }

        const rules = (body.rules ?? []).map((r: any) => {
          const p = String(r.params ?? "");
          if (p) assertValidHex(p, "rules[].params");
          return {
            ruleType: Number(r.ruleType),
            namespace: Number(r.namespace ?? 0),
            params: p,
          };
        });

        const r = await dkgExecutor.createPolicyV4({
          stableId,
          version,
          expiresAtMs: body.expiresAtMs ? Number(body.expiresAtMs) : undefined,
          allowNamespaces: body.allowNamespaces,
          allowChainIds: body.allowChainIds,
          allowDestinations: body.allowDestinations,
          denyDestinations: body.denyDestinations,
          rules,
        });

        return { success: true, policyObjectId: r.policyObjectId, digest: r.digest };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        const isValidation = msg.includes("invalid hex") || msg.includes("odd-length hex") || msg.includes("Missing ");
        logger.error({ err: error }, "Create PolicyV4 failed");
        set.status = isValidation ? 400 : 500;
        return { success: false, error: msg };
      }
    },
    {
      body: t.Object({
        stableId: t.String(),
        version: t.String(),
        expiresAtMs: t.Optional(t.Number()),
        allowNamespaces: t.Optional(t.Array(t.Number())),
        allowChainIds: t.Optional(
          t.Array(t.Object({ namespace: t.Number(), chainId: t.String() }))
        ),
        allowDestinations: t.Optional(t.Array(t.String())),
        denyDestinations: t.Optional(t.Array(t.String())),
        rules: t.Array(
          t.Object({
            ruleType: t.Number(),
            namespace: t.Optional(t.Number()),
            params: t.String(),
          })
        ),
      }),
      detail: {
        summary: "Create and share Policy",
        description:
          "Creates a shared Policy object with an extensible generic rules engine. Rule types: 1=MaxNativeValue, 2=EVMSelectorAllow, 3=EVMSelectorDeny, 4=ERC20MaxAmount, 5=BTCScriptTypes, 6=BTCMaxFeeRate, 7=SOLProgramAllow, 8=SOLProgramDeny, 9=TimeWindow, 10=PeriodLimit, 11=RateLimit.",
      },
    }
  )

  .post(
    "/policy/receipt/mint",
    async ({ body, set, request }) => {
      try {
        const policyObjectId = String(body.policyObjectId ?? "").trim();
        const bindingObjectId = String(body.bindingObjectId ?? "").trim();
        const namespace = Number(body.namespace);
        const chainId = String(body.chainId ?? "").trim();
        const intentHashHex = String(body.intentHashHex ?? "").trim();
        const destinationHex = String(body.destinationHex ?? "").trim();
        const nativeValueHex = String(body.nativeValueHex ?? "").trim();
        const contextDataHex = String(body.contextDataHex ?? "");

        if (!policyObjectId.startsWith("0x")) throw new Error("Invalid policyObjectId");
        if (!bindingObjectId.startsWith("0x")) throw new Error("Invalid bindingObjectId");

        // Wallet ownership check: resolve dwalletId from binding
        if (isAuthEnabled()) {
          const callerKey = request.headers.get("x-kairo-api-key") ?? "";
          const record = getKeyRecord(callerKey);
          if (record && !record.isAdmin) {
            const dwalletId = await resolveDwalletIdFromBinding(bindingObjectId);
            if (dwalletId && !keyOwnsWallet(callerKey, dwalletId)) {
              set.status = 403;
              return { success: false, error: "Forbidden: API key does not own the wallet in this binding" };
            }
          }
        }

        if (!intentHashHex) throw new Error("Missing intentHashHex");
        if (!nativeValueHex) throw new Error("Missing nativeValueHex");
        assertValidHex(chainId, "chainId");
        assertValidHex(intentHashHex, "intentHashHex");
        assertValidHex(destinationHex, "destinationHex");
        assertValidHex(nativeValueHex, "nativeValueHex");
        if (contextDataHex) assertValidHex(contextDataHex, "contextDataHex");

        const r = await dkgExecutor.mintReceiptV4({
          policyObjectId,
          bindingObjectId,
          namespace,
          chainId,
          intentHashHex,
          destinationHex,
          nativeValueHex,
          contextDataHex: contextDataHex || undefined,
        });

        return {
          success: true,
          receiptId: r.receiptId,
          allowed: r.allowed,
          digest: r.digest,
        };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        const isValidation =
          msg.includes("invalid hex") || msg.includes("odd-length hex") ||
          msg.includes("Missing ") || msg.includes("does not exist") ||
          msg.includes("not registered in the vault");
        logger.error({ err: error }, "Mint V4 receipt failed");
        set.status = isValidation ? 400 : 500;
        return { success: false, error: msg };
      }
    },
    {
      body: t.Object({
        policyObjectId: t.String(),
        bindingObjectId: t.String(),
        namespace: t.Number(),
        chainId: t.String(),
        intentHashHex: t.String(),
        destinationHex: t.String(),
        nativeValueHex: t.String(),
        contextDataHex: t.Optional(t.String()),
      }),
      detail: {
        summary: "Mint PolicyReceipt",
        description:
          "Evaluates all generic rules and mints a receipt. The receipt's `allowed` field indicates whether the transaction is approved.",
      },
    }
  )

  .post(
    "/policy/sign",
    async ({ body, set, request }) => {
      try {
        // Wallet ownership check
        const dwalletId = String(body.dwalletId ?? "").trim();
        if (isAuthEnabled()) {
          const callerKey = request.headers.get("x-kairo-api-key") ?? "";
          if (!keyOwnsWallet(callerKey, dwalletId)) {
            set.status = 403;
            return { success: false, error: "Forbidden: API key does not own this wallet" };
          }
        }

        const r = await dkgExecutor.policyGatedAuthorizeSignV4({
          vaultObjectId: String(body.vaultObjectId ?? "").trim(),
          receiptId: String(body.receiptId ?? "").trim(),
          bindingObjectId: String(body.bindingObjectId ?? "").trim(),
          dwalletId: String(body.dwalletId ?? "").trim(),
          intentDigestHex: String(body.intentDigestHex ?? "").trim(),
          namespace: Number(body.namespace),
          chainId: String(body.chainId ?? "").trim(),
          destinationHex: String(body.destinationHex ?? "").trim(),
          receiptTtlMs: body.receiptTtlMs ? Number(body.receiptTtlMs) : undefined,
        });

        return { success: true, digest: r.digest };
      } catch (error) {
        logger.error({ err: error }, "V4 policy-gated sign failed");
        set.status = 500;
        return { success: false, error: error instanceof Error ? error.message : String(error) };
      }
    },
    {
      body: t.Object({
        vaultObjectId: t.String(),
        receiptId: t.String(),
        bindingObjectId: t.String(),
        dwalletId: t.String(),
        intentDigestHex: t.String(),
        namespace: t.Number(),
        chainId: t.String(),
        destinationHex: t.String(),
        receiptTtlMs: t.Optional(t.Number()),
      }),
      detail: {
        summary: "Policy-gated vault signing",
        description: "Authorize signing through the vault using a PolicyReceipt.",
      },
    }
  );
