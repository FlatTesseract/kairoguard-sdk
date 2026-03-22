/**
 * Utility Routes - Audit, Sui objects, and misc operations
 *
 * Handles:
 * - Audit event listing
 * - Sui object fetching (restricted)
 * - Airgap bootstrap bundle
 * - Ika helpers for browser clients (protocol parameters)
 */

import { Elysia, t } from "elysia";
import { SuiClient } from "@mysten/sui/client";
import { config } from "../config.js";
import { dkgExecutor } from "../dkg-executor.js";
import { getSuiRpcUrlForNetwork } from "../policy-discovery.js";

// Separate Sui client for read-only calls
const suiDiscoveryClient = new SuiClient({
  url: getSuiRpcUrlForNetwork(config.sui.network),
});

export const utilityRoutes = new Elysia({ prefix: "/api" })
  // Airgapped bootstrap bundle for extension/offline flows
  .get(
    "/airgap/bootstrap",
    async () => {
      return {
        adminAddress: dkgExecutor.getAdminAddress(),
        network: config.sui.network,
        curve: 0, // SECP256K1
      };
    },
    {
      detail: {
        summary: "Airgap bootstrap bundle",
        description:
          "Returns adminAddress + network needed for imported-key verification/signing inputs.",
      },
    }
  )

  // Protocol public parameters (proxy for browser clients)
  //
  // Why: Some browser environments cannot reach Sui RPC endpoints directly (VPN/proxy/firewall),
  // which causes `fetch()` failures inside @mysten/sui + @ika.xyz/sdk. These parameters are public,
  // so it is safe for the backend to proxy them.
  .get(
    "/ika/protocol-public-parameters",
    async ({ set }) => {
      // Fetching protocol params server-side exceeds the container memory limit.
      // Clients should fall back to fetching directly via the Ika SDK.
      set.status = 503;
      return {
        success: false,
        error: "Protocol parameters are not available from the backend. Use the Ika SDK directly.",
        fallback: "sdk",
      };
    },
    {
      query: t.Optional(
        t.Object({
          curve: t.Optional(t.String()),
          encoding: t.Optional(t.String()),
        })
      ),
      detail: {
        summary: "Get Ika protocol public parameters",
        description:
          "Returns protocol public parameters bytes for a curve (secp256k1/ed25519). Default is raw binary; pass encoding=json only for debugging.",
      },
    }
  )

  // Fetch a Sui object by id (restricted to safe object types)
  .get(
    "/sui/object/:objectId",
    async ({ params, set }) => {
      const objectId = String(params.objectId || "").trim();
      if (!objectId.startsWith("0x")) {
        set.status = 400;
        return { success: false, error: "Invalid object id" };
      }

      const obj = await suiDiscoveryClient.getObject({
        id: objectId,
        options: {
          showType: true,
          showContent: true,
          showBcs: true,
          showOwner: true,
        },
      });

      const type = String((obj as any)?.data?.type ?? "");
      const allowed =
        type.endsWith("::coordinator_inner::EncryptedUserSecretKeyShare") ||
        type.endsWith("::policy_registry::PolicyReceipt") ||
        type.endsWith("::policy_registry::PolicyReceiptV2") ||
        type.endsWith("::policy_registry::PolicyReceiptV3") ||
        type.endsWith("::policy_registry::PolicyReceiptV4");

      if (!allowed) {
        set.status = 403;
        return {
          success: false,
          error: "Object type not allowed",
          type: type || undefined,
        };
      }

      return { success: true, object: obj };
    },
    {
      params: t.Object({ objectId: t.String() }),
      detail: {
        summary: "Fetch Sui object (restricted)",
        description:
          "Returns a Sui object needed for client-side flows (EncryptedUserSecretKeyShare / PolicyReceipt).",
      },
    }
  )

  // Sui RPC Proxy - allows SDK clients to use backend's configured RPC (e.g., Shinami)
  // without exposing the API key. Streams responses to avoid memory issues.
  .post(
    "/sui-rpc",
    async ({ body, set }) => {
      const rpcUrl = getSuiRpcUrlForNetwork(config.sui.network);
      try {
        const response = await fetch(rpcUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        set.status = response.status;
        set.headers["Content-Type"] = "application/json";
        const text = await response.text();
        return new Response(text, {
          status: response.status,
          headers: { "Content-Type": "application/json" },
        });
      } catch (err) {
        set.status = 502;
        return {
          success: false,
          error: "Failed to proxy Sui RPC request",
          message: err instanceof Error ? err.message : String(err),
        };
      }
    },
    {
      body: t.Any(),
      detail: {
        summary: "Sui RPC Proxy",
        description:
          "Proxies JSON-RPC requests to the backend's configured Sui RPC endpoint (e.g., Shinami). SDK clients can use this instead of configuring their own RPC.",
      },
    }
  )

  // Audit feed (in-memory only)
  .get(
    "/audit/events",
    ({ query }) => {
      const limitRaw = Number((query as any)?.limit ?? 50);
      const limit = Number.isFinite(limitRaw)
        ? Math.max(1, Math.min(200, Math.floor(limitRaw)))
        : 50;
      const events = dkgExecutor.listAuditEvents(limit);
      return { success: true, events };
    },
    {
      query: t.Optional(
        t.Object({
          limit: t.Optional(t.String()),
        })
      ),
      detail: {
        summary: "List recent audit events",
        description:
          "Returns a best-effort in-memory audit feed of DKG/import/presign/sign activity.",
      },
    }
  );
