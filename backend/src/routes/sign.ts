/**
 * Sign Routes - MPC signing operations
 *
 * Handles:
 * - Sign request submission
 * - Sign status queries
 */

import { Elysia, t } from "elysia";
import { dkgExecutor } from "../dkg-executor.js";

export const signRoutes = new Elysia({ prefix: "/api" })
  // Sign request endpoint (non-custodial)
  .post(
    "/sign/request",
    ({ body }) => {
      const request = dkgExecutor.submitSignRequest(body);
      return {
        success: true,
        requestId: request.id,
        status: request.status,
      };
    },
    {
      body: t.Object({
        dWalletId: t.String(),
        dWalletCapId: t.String(),
        encryptedUserSecretKeyShareId: t.String(),
        userOutputSignature: t.Array(t.Number()),
        presignId: t.String(),
        messageHex: t.String(),
        userSignMessage: t.Array(t.Number()),
        policyReceiptId: t.String(),
        policyBindingObjectId: t.Optional(t.String()),
        policyObjectId: t.Optional(t.String()),
        policyVersion: t.Optional(t.String()),
        custodyChainObjectId: t.Optional(t.String()),
        custodyPackageId: t.Optional(t.String()),
        // Optional: Ethereum transaction for broadcast
        ethTx: t.Optional(
          t.Object({
            to: t.String(),
            value: t.String(),
            nonce: t.Number(),
            gasLimit: t.String(),
            maxFeePerGas: t.String(),
            maxPriorityFeePerGas: t.String(),
            chainId: t.Number(),
            from: t.String(),
          })
        ),
      }),
      detail: {
        summary: "Request signature (non-custodial)",
        description:
          "Submit userSignMessage (computed client-side) to complete Ethereum signature. Optionally broadcast to EVM chain.",
      },
    }
  )

  // Sign status endpoint
  .get(
    "/sign/status/:requestId",
    ({ params }) => {
      const request = dkgExecutor.getSignRequest(params.requestId);
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
        // Sui transaction digest for the sign request (includes vault authorization when enabled)
        digest: request.digest,
        signatureHex: request.signatureHex,
        signId: request.signId,
        ethTxHash: request.ethTxHash,
        ethBlockNumber: request.ethBlockNumber,
        error: request.error,
      };
    },
    {
      params: t.Object({
        requestId: t.String(),
      }),
      detail: {
        summary: "Get sign request status",
        description: "Check the status of a sign request",
      },
    }
  );
