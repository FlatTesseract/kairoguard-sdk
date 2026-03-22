/**
 * DKG Routes - dWallet creation and management
 *
 * Handles:
 * - DKG submission and status
 * - Imported key verification
 * - dWallet activation and queries
 */

import { Elysia, t } from "elysia";
import { dkgExecutor } from "../dkg-executor.js";
import { bindWallet } from "../key-registry.js";

export const dkgRoutes = new Elysia({ prefix: "/api" })
  // DKG Submit endpoint
  .post(
    "/dkg/submit",
    ({ body }) => {
      const request = dkgExecutor.submitRequest(body);
      return {
        success: true,
        requestId: request.id,
        status: request.status,
      };
    },
    {
      body: t.Object({
        userPublicOutput: t.Array(t.Number()),
        userDkgMessage: t.Array(t.Number()),
        encryptedUserShareAndProof: t.Array(t.Number()),
        sessionIdentifier: t.Array(t.Number()),
        signerPublicKey: t.Array(t.Number()),
        encryptionKeyAddress: t.String(),
        encryptionKey: t.Array(t.Number()),
        encryptionKeySignature: t.Array(t.Number()),
        curve: t.Optional(t.Number()),
      }),
      detail: {
        summary: "Submit DKG data",
        description:
          "Submit DKG computation results to create a dWallet (SECP256K1 for Ethereum by default)",
      },
    }
  )

  // DKG Status endpoint
  .get(
    "/dkg/status/:requestId",
    async ({ params, request }) => {
      const status = dkgExecutor.getRequest(params.requestId);
      if (!status) {
        return {
          success: false,
          error: "Request not found",
        };
      }
      const dWalletId = String(status.dWalletObjectId ?? "").trim();
      if (status.status === "completed" && dWalletId.startsWith("0x")) {
        const callerKey = request.headers.get("x-kairo-api-key");
        if (callerKey) {
          await bindWallet(callerKey, dWalletId);
        }
      }
      return {
        success: true,
        requestId: status.id,
        status: status.status,
        dWalletCapObjectId: status.dWalletCapObjectId,
        dWalletObjectId: status.dWalletObjectId,
        encryptedUserSecretKeyShareId: status.encryptedUserSecretKeyShareId,
        ethereumAddress: status.ethereumAddress,
        solanaAddress: (status as any).solanaAddress,
        error: status.error,
      };
    },
    {
      params: t.Object({
        requestId: t.String(),
      }),
      detail: {
        summary: "Get DKG status",
        description: "Check the status of a DKG request",
      },
    }
  )

  // Imported-key verification submit endpoint
  .post(
    "/imported/verify/submit",
    ({ body }) => {
      const request = dkgExecutor.submitImportedVerifyRequest(body);
      return {
        success: true,
        requestId: request.id,
        status: request.status,
      };
    },
    {
      body: t.Object({
        curve: t.Number(),
        sessionIdentifier: t.Array(t.Number()),
        signerPublicKey: t.Array(t.Number()),
        encryptionKeyAddress: t.String(),
        encryptionKey: t.Array(t.Number()),
        encryptionKeySignature: t.Array(t.Number()),
        importInput: t.Object({
          userPublicOutput: t.Array(t.Number()),
          userMessage: t.Array(t.Number()),
          encryptedUserShareAndProof: t.Array(t.Number()),
        }),
        expectedEvmAddress: t.Optional(t.String()),
      }),
      detail: {
        summary: "Submit imported-key verification",
        description:
          "Submit an imported-key dWallet verification request (prepared offline; no private key is sent).",
      },
    }
  )

  // Imported-key verification status endpoint
  .get(
    "/imported/verify/status/:requestId",
    ({ params }) => {
      const request = dkgExecutor.getImportedVerifyRequest(params.requestId);
      if (!request) {
        return { success: false, error: "Request not found" };
      }
      return {
        success: true,
        requestId: request.id,
        status: request.status,
        dWalletCapObjectId: request.dWalletCapObjectId,
        dWalletObjectId: request.dWalletObjectId,
        encryptedUserSecretKeyShareId: request.encryptedUserSecretKeyShareId,
        ethereumAddress: request.ethereumAddress,
        solanaAddress: (request as any).solanaAddress,
        digest: request.digest,
        error: request.error,
      };
    },
    {
      params: t.Object({ requestId: t.String() }),
      detail: {
        summary: "Get imported-key verification status",
        description: "Check the status of an imported-key verification request",
      },
    }
  )

  // Get dWallet details
  .get(
    "/dwallet/:dWalletId",
    async ({ params }) => {
      try {
        const ikaClient = dkgExecutor.getIkaClient();
        const dWallet = await ikaClient.getDWallet(params.dWalletId);
        return {
          success: true,
          dWallet: {
            id: dWallet?.id,
            state: dWallet?.state,
            dwalletCapId: dWallet?.dwallet_cap_id,
          },
        };
      } catch (error) {
        return {
          success: false,
          error:
            error instanceof Error ? error.message : "Failed to get dWallet",
        };
      }
    },
    {
      params: t.Object({
        dWalletId: t.String(),
      }),
      detail: {
        summary: "Get dWallet details",
        description: "Fetch dWallet state from the network",
      },
    }
  )

  // Get full dWallet JSON
  .get(
    "/dwallet/full/:dWalletId",
    async ({ params, set }) => {
      try {
        const ikaClient = dkgExecutor.getIkaClient();
        const dWallet = await ikaClient.getDWallet(params.dWalletId);
        return { success: true, dWallet };
      } catch (error) {
        set.status = 500;
        return {
          success: false,
          error:
            error instanceof Error ? error.message : "Failed to get dWallet",
        };
      }
    },
    {
      params: t.Object({ dWalletId: t.String() }),
      detail: {
        summary: "Get full dWallet JSON",
        description:
          "Returns the full dWallet object from the Ika client (needed for client-side share decryption).",
      },
    }
  )

  // Activate an imported-key dWallet
  .post(
    "/dwallet/activate",
    async ({ body, set }) => {
      try {
        const dWalletId = String(body.dWalletId ?? "");
        const encryptedUserSecretKeyShareId = String(
          body.encryptedUserSecretKeyShareId ?? ""
        );
        const userOutputSignature = Array.isArray(body.userOutputSignature)
          ? (body.userOutputSignature as number[])
          : [];

        if (!dWalletId.startsWith("0x")) throw new Error("Invalid dWalletId");
        if (!encryptedUserSecretKeyShareId.startsWith("0x"))
          throw new Error("Invalid encryptedUserSecretKeyShareId");
        if (!userOutputSignature.length)
          throw new Error("Missing userOutputSignature");

        const r = await dkgExecutor.activateDWallet({
          dWalletId,
          encryptedUserSecretKeyShareId,
          userOutputSignature,
        });
        return { success: true, digest: r.digest };
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        if (/requires confirmation/i.test(msg) || /reaffirm/i.test(msg)) {
          set.status = 409;
        } else {
          set.status = 500;
        }
        return { success: false, error: msg };
      }
    },
    {
      body: t.Object({
        dWalletId: t.String(),
        encryptedUserSecretKeyShareId: t.String(),
        userOutputSignature: t.Array(t.Number()),
      }),
      detail: {
        summary: "Activate dWallet (accept encrypted user share)",
        description:
          "Accepts the encrypted user secret key share for an imported-key dWallet, activating it for signing.",
      },
    }
  );
