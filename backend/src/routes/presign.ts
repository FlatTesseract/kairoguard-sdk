/**
 * Presign Routes - Presign operations
 *
 * Handles:
 * - Presign request submission
 * - Presign status queries
 */

import { Elysia, t } from "elysia";
import { dkgExecutor } from "../dkg-executor.js";

export const presignRoutes = new Elysia({ prefix: "/api" })
  // Presign request endpoint
  .post(
    "/presign/request",
    ({ body }) => {
      const request = dkgExecutor.submitPresignRequest(body);
      return {
        success: true,
        requestId: request.id,
        status: request.status,
      };
    },
    {
      body: t.Object({
        dWalletId: t.String(),
        curve: t.Optional(t.Number()),
        signatureAlgorithm: t.Optional(t.Number()),
        encryptedUserSecretKeyShareId: t.Optional(t.String()),
        userOutputSignature: t.Optional(t.Array(t.Number())),
      }),
      detail: {
        summary: "Request presign",
        description:
          "Request a presign for signing messages (supports multiple curves/signature algorithms).",
      },
    }
  )

  // Presign status endpoint
  .get(
    "/presign/status/:requestId",
    ({ params }) => {
      const request = dkgExecutor.getPresignRequest(params.requestId);
      if (!request) {
        return {
          success: false,
          error: "Request not found",
        };
      }
      return {
        success: true,
        requestId: request.id,
        status: request.status,
        presignId: request.presignId,
        presignBytes: request.presignBytes,
        error: request.error,
      };
    },
    {
      params: t.Object({
        requestId: t.String(),
      }),
      detail: {
        summary: "Get presign status",
        description: "Check the status of a presign request",
      },
    }
  );
