/**
 * EVM Routes - Ethereum/EVM chain operations
 *
 * Handles:
 * - Transaction parameter fetching (nonce, gas)
 * - Chain-specific operations
 */

import { Elysia, t } from "elysia";
import { dkgExecutor } from "../dkg-executor.js";

export const evmRoutes = new Elysia({ prefix: "/api" })
  // Get Ethereum transaction parameters (Base Sepolia default)
  .get(
    "/eth/tx-params/:address",
    async ({ params }) => {
      try {
        const txParams = await dkgExecutor.getEthTxParams(params.address);
        return {
          success: true,
          ...txParams,
        };
      } catch (error) {
        return {
          success: false,
          error:
            error instanceof Error
              ? error.message
              : "Failed to get transaction parameters",
        };
      }
    },
    {
      params: t.Object({
        address: t.String(),
      }),
      detail: {
        summary: "Get ETH transaction parameters",
        description:
          "Fetch nonce and gas prices for an Ethereum address (for signing)",
      },
    }
  )

  // Chain-aware EVM tx params
  .get(
    "/evm/tx-params/:chainId/:address",
    async ({ params, set }) => {
      const chainIdNum = Number(params.chainId);
      if (!Number.isFinite(chainIdNum)) {
        set.status = 400;
        return { success: false, error: "Invalid chainId" };
      }
      try {
        const txParams = await dkgExecutor.getEvmTxParams({
          address: params.address,
          chainId: chainIdNum,
        });
        return { success: true, ...txParams };
      } catch (error) {
        return {
          success: false,
          error:
            error instanceof Error
              ? error.message
              : "Failed to get transaction parameters",
        };
      }
    },
    {
      params: t.Object({
        chainId: t.String(),
        address: t.String(),
      }),
      detail: {
        summary: "Get EVM transaction parameters",
        description:
          "Fetch nonce and gas prices for an address on a specific EVM chainId (for signing)",
      },
    }
  );
