/**
 * Solana Routes
 *
 * API endpoints for Solana transaction signing and broadcasting.
 */

import { Elysia, t } from "elysia";
import bs58 from "bs58";
import { logger } from "../logger.js";
import { createSolanaConnector, type SolanaConnector, getProgramName } from "../chains/solana/index.js";
import { ChainNamespace, type SolanaCluster } from "../chains/types.js";
import { chainConnectorRegistry } from "../chains/registry.js";
import { dkgExecutor } from "../dkg-executor.js";
import { PublicKey, Transaction, VersionedTransaction } from "@solana/web3.js";

// Initialize Solana connectors for supported clusters
const SOLANA_CLUSTERS: SolanaCluster[] = ["mainnet-beta", "devnet", "testnet"];

for (const cluster of SOLANA_CLUSTERS) {
  const connector = createSolanaConnector(cluster);
  chainConnectorRegistry.registerConnector(connector);
}

/**
 * Get Solana connector for cluster.
 */
function getSolanaConnector(cluster: SolanaCluster): SolanaConnector {
  const connector = chainConnectorRegistry.getConnector(ChainNamespace.SOLANA, cluster);
  if (!connector) {
    throw new Error(`Solana connector not found for cluster: ${cluster}`);
  }
  return connector as SolanaConnector;
}

export const solanaRoutes = new Elysia({ prefix: "/api/solana" })
  /**
   * Parse a Solana transaction and extract details.
   */
  .post(
    "/parse",
    async ({ body }) => {
      try {
        const connector = getSolanaConnector(body.cluster);

        // Decode transaction from base58 or base64
        let txBytes: Uint8Array;
        if (body.encoding === "base64") {
          txBytes = Uint8Array.from(Buffer.from(body.transaction, "base64"));
        } else {
          txBytes = bs58.decode(body.transaction);
        }

        const parsed = await connector.parseTransaction(txBytes);

        return {
          success: true,
          transaction: {
            from: parsed.from,
            destinations: parsed.destinations,
            amounts: parsed.amounts.map((a) => a.toString()),
            intentHash: Buffer.from(parsed.intentHash).toString("hex"),
            programIds: parsed.sol?.programIds || [],
            programNames: (parsed.sol?.programIds || []).map(getProgramName),
            instructionCount: parsed.sol?.instructions.length || 0,
            recentBlockhash: parsed.sol?.recentBlockhash,
          },
        };
      } catch (error) {
        logger.error({ error }, "Failed to parse Solana transaction");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to parse transaction",
        };
      }
    },
    {
      body: t.Object({
        cluster: t.Union([
          t.Literal("mainnet-beta"),
          t.Literal("devnet"),
          t.Literal("testnet"),
        ]),
        transaction: t.String(),
        encoding: t.Optional(t.Union([t.Literal("base58"), t.Literal("base64")])),
      }),
      detail: {
        summary: "Parse Solana transaction",
        description: "Parse a Solana transaction and extract details for policy verification",
      },
    }
  )

  /**
   * Prepare a Solana transaction for MPC signing.
   * Returns the canonical message bytes that must be signed by the fee payer.
   */
  .post(
    "/prepare",
    async ({ body }) => {
      try {
        const connector = getSolanaConnector(body.cluster);

        // Decode transaction from base58/base64
        let txBytes: Uint8Array;
        if (body.encoding === "base64") {
          txBytes = Uint8Array.from(Buffer.from(body.transaction, "base64"));
        } else {
          txBytes = bs58.decode(body.transaction);
        }

        const parsed = await connector.parseTransaction(txBytes);
        const messageBytes = connector.getMessageBytes(txBytes);

        return {
          success: true,
          parsed: {
            from: parsed.from,
            destinations: parsed.destinations,
            amounts: parsed.amounts.map((a) => a.toString()),
            intentHash: Buffer.from(parsed.intentHash).toString("hex"),
            programIds: parsed.sol?.programIds || [],
            programNames: (parsed.sol?.programIds || []).map(getProgramName),
            instructionCount: parsed.sol?.instructions.length || 0,
            recentBlockhash: parsed.sol?.recentBlockhash,
          },
          intentHashHex: `0x${Buffer.from(parsed.intentHash).toString("hex")}`,
          messageToSign: Buffer.from(messageBytes).toString("hex"),
        };
      } catch (error) {
        logger.error({ error }, "Failed to prepare Solana transaction");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Prepare failed",
        };
      }
    },
    {
      body: t.Object({
        cluster: t.Union([
          t.Literal("mainnet-beta"),
          t.Literal("devnet"),
          t.Literal("testnet"),
        ]),
        transaction: t.String(),
        encoding: t.Optional(t.Union([t.Literal("base58"), t.Literal("base64")])),
      }),
      detail: {
        summary: "Prepare Solana transaction for signing",
        description:
          "Parse a Solana transaction and return message bytes for createUserSignMessageWithPublicOutput.",
      },
    }
  )

  /**
   * Get transaction parameters (blockhash, fees).
   */
  .get(
    "/tx-params/:cluster",
    async ({ params }) => {
      try {
        const connector = getSolanaConnector(params.cluster as SolanaCluster);
        const txParams = await connector.getTxParams("");

        return {
          success: true,
          recentBlockhash: txParams.recentBlockhash,
          priorityFee: {
            suggested: txParams.fee.suggested,
            minimum: txParams.fee.minimum,
            maximum: txParams.fee.maximum,
          },
        };
      } catch (error) {
        logger.error({ error }, "Failed to get Solana tx params");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to get tx params",
        };
      }
    },
    {
      params: t.Object({
        cluster: t.String(),
      }),
      detail: {
        summary: "Get Solana transaction parameters",
        description: "Get recent blockhash and priority fee estimates",
      },
    }
  )

  /**
   * Derive Solana address from Ed25519 public key.
   */
  .post(
    "/address",
    async ({ body }) => {
      try {
        const connector = getSolanaConnector(body.cluster);
        const publicKey = Buffer.from(body.publicKeyHex, "hex");

        if (publicKey.length !== 32) {
          throw new Error("Invalid Ed25519 public key length (expected 32 bytes)");
        }

        const address = connector.deriveAddress(publicKey);

        return {
          success: true,
          address,
          cluster: body.cluster,
        };
      } catch (error) {
        logger.error({ error }, "Failed to derive Solana address");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to derive address",
        };
      }
    },
    {
      body: t.Object({
        cluster: t.Union([
          t.Literal("mainnet-beta"),
          t.Literal("devnet"),
          t.Literal("testnet"),
        ]),
        publicKeyHex: t.String(),
      }),
      detail: {
        summary: "Derive Solana address",
        description: "Derive a Solana address from an Ed25519 public key",
      },
    }
  )

  /**
   * Validate a Solana address.
   */
  .post(
    "/validate-address",
    async ({ body }) => {
      try {
        const connector = getSolanaConnector(body.cluster);
        const valid = connector.validateAddress(body.address);

        return {
          success: true,
          valid,
          address: body.address,
          cluster: body.cluster,
        };
      } catch (error) {
        return {
          success: true,
          valid: false,
          address: body.address,
          cluster: body.cluster,
          error: error instanceof Error ? error.message : "Validation failed",
        };
      }
    },
    {
      body: t.Object({
        cluster: t.Union([
          t.Literal("mainnet-beta"),
          t.Literal("devnet"),
          t.Literal("testnet"),
        ]),
        address: t.String(),
      }),
      detail: {
        summary: "Validate Solana address",
        description: "Validate a Solana address",
      },
    }
  )

  /**
   * Sign a Solana transaction.
   */
  .post(
    "/sign",
    async ({ body }) => {
      try {
        const connector = getSolanaConnector(body.cluster);

        // Decode transaction
        let txBytes: Uint8Array;
        if (body.encoding === "base64") {
          txBytes = Uint8Array.from(Buffer.from(body.transaction, "base64"));
        } else {
          txBytes = bs58.decode(body.transaction);
        }

        // Parse the transaction
        const parsed = await connector.parseTransaction(txBytes);
        const messageBytes = connector.getMessageBytes(txBytes);
        const intentHashHex = `0x${Buffer.from(parsed.intentHash).toString("hex")}`;

        logger.info(
          {
            cluster: body.cluster,
            from: parsed.from,
            destinations: parsed.destinations,
            programIds: parsed.sol?.programIds,
            intentHash: Buffer.from(parsed.intentHash).toString("hex").slice(0, 16) + "...",
          },
          "Solana sign request received"
        );

        if (!body.policyReceiptId?.startsWith("0x")) {
          throw new Error("policyReceiptId is required for Solana signing");
        }
        if (!body.presignId?.startsWith("0x")) {
          throw new Error("presignId is required for Solana signing");
        }
        if (!Array.isArray(body.userSignMessage) || body.userSignMessage.length === 0) {
          throw new Error("userSignMessage is required for Solana signing");
        }

        const signResult = await dkgExecutor.executeSolanaSign({
          dWalletId: body.dWalletId,
          dWalletCapId: body.dWalletCapId,
          presignId: body.presignId,
          messageBytes,
          userSignMessage: body.userSignMessage,
          encryptedUserSecretKeyShareId: body.encryptedUserSecretKeyShareId,
          userOutputSignature: body.userOutputSignature,
          policyReceiptId: body.policyReceiptId,
          policyObjectId: body.policyObjectId,
          policyVersion: body.policyVersion,
          policyBindingObjectId: body.policyBindingObjectId,
          intentHashHex,
          cluster: body.cluster,
          destinations: parsed.destinations,
        });

        // Attach signature and broadcast.
        const feePayer = parsed.from ? new PublicKey(parsed.from) : null;
        const sig = Buffer.from(signResult.signatureBytes);

        let signedTxBytes: Uint8Array;
        try {
          // Versioned transaction (v0)
          const vt = VersionedTransaction.deserialize(Buffer.from(txBytes));
          vt.signatures[0] = sig;
          signedTxBytes = vt.serialize();
        } catch {
          // Legacy transaction
          if (!feePayer) throw new Error("Missing fee payer public key (from)");
          const tx = Transaction.from(Buffer.from(txBytes));
          tx.addSignature(feePayer, sig);
          signedTxBytes = tx.serialize();
        }

        const broadcast = await connector.broadcast(signedTxBytes);
        if (!broadcast.success) {
          throw new Error(broadcast.error || "Broadcast failed");
        }

        return {
          success: true,
          signId: signResult.signId,
          digest: signResult.digest,
          signature: {
            raw: signResult.signatureHex,
          },
          txHash: broadcast.txHash,
          parsed: {
            from: parsed.from,
            destinations: parsed.destinations,
            amounts: parsed.amounts.map((a) => a.toString()),
            intentHash: Buffer.from(parsed.intentHash).toString("hex"),
            programIds: parsed.sol?.programIds || [],
          },
        };
      } catch (error) {
        logger.error({ error }, "Failed to process Solana sign request");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Sign request failed",
        };
      }
    },
    {
      body: t.Object({
        cluster: t.Union([
          t.Literal("mainnet-beta"),
          t.Literal("devnet"),
          t.Literal("testnet"),
        ]),
        transaction: t.String(),
        encoding: t.Optional(t.Union([t.Literal("base58"), t.Literal("base64")])),
        dWalletId: t.String(),
        dWalletCapId: t.String(),
        presignId: t.String(),
        policyReceiptId: t.String(),
        policyObjectId: t.Optional(t.String()),
        policyVersion: t.Optional(t.String()),
        policyBindingObjectId: t.Optional(t.String()),
        // User MPC inputs
        userSignMessage: t.Array(t.Number()),
        encryptedUserSecretKeyShareId: t.Optional(t.String()),
        userOutputSignature: t.Optional(t.Array(t.Number())),
      }),
      detail: {
        summary: "Sign Solana transaction",
        description:
          "Sign and broadcast a Solana transaction using MPC with policy verification (Ed25519).",
      },
    }
  )

  /**
   * Broadcast a signed Solana transaction.
   */
  .post(
    "/broadcast",
    async ({ body }) => {
      try {
        const connector = getSolanaConnector(body.cluster);

        // Decode transaction
        let txBytes: Uint8Array;
        if (body.encoding === "base64") {
          txBytes = Uint8Array.from(Buffer.from(body.transaction, "base64"));
        } else {
          txBytes = bs58.decode(body.transaction);
        }

        const result = await connector.broadcast(txBytes);

        if (result.success) {
          logger.info(
            { signature: result.txHash, cluster: body.cluster },
            "Solana transaction broadcast successful"
          );
        }

        return result;
      } catch (error) {
        logger.error({ error }, "Failed to broadcast Solana transaction");
        return {
          success: false,
          txHash: "",
          error: error instanceof Error ? error.message : "Broadcast failed",
        };
      }
    },
    {
      body: t.Object({
        cluster: t.Union([
          t.Literal("mainnet-beta"),
          t.Literal("devnet"),
          t.Literal("testnet"),
        ]),
        transaction: t.String(),
        encoding: t.Optional(t.Union([t.Literal("base58"), t.Literal("base64")])),
      }),
      detail: {
        summary: "Broadcast Solana transaction",
        description: "Broadcast a signed Solana transaction to the network",
      },
    }
  )

  /**
   * Get account balance.
   */
  .get(
    "/balance/:cluster/:address",
    async ({ params }) => {
      try {
        const connector = getSolanaConnector(params.cluster as SolanaCluster);

        if (!connector.validateAddress(params.address)) {
          throw new Error("Invalid Solana address");
        }

        // Get balance via RPC
        const response = await fetch(connector["rpcUrl"], {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "getBalance",
            params: [params.address],
          }),
        });

        const result = await response.json();

        if (result.error) {
          throw new Error(result.error.message);
        }

        const lamports = BigInt(result.result?.value || 0);
        const sol = Number(lamports) / 1_000_000_000;

        return {
          success: true,
          address: params.address,
          cluster: params.cluster,
          balance: {
            lamports: lamports.toString(),
            sol: sol.toFixed(9),
          },
        };
      } catch (error) {
        logger.error({ error }, "Failed to get Solana balance");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to get balance",
        };
      }
    },
    {
      params: t.Object({
        cluster: t.String(),
        address: t.String(),
      }),
      detail: {
        summary: "Get Solana account balance",
        description: "Get the SOL balance for an address",
      },
    }
  )

  /**
   * Get supported Solana clusters.
   */
  .get(
    "/clusters",
    () => {
      return {
        success: true,
        clusters: SOLANA_CLUSTERS.map((cluster) => ({
          id: cluster,
          name: cluster === "mainnet-beta" ? "Mainnet" : cluster.charAt(0).toUpperCase() + cluster.slice(1),
          namespace: ChainNamespace.SOLANA,
        })),
      };
    },
    {
      detail: {
        summary: "List supported Solana clusters",
        description: "Get a list of supported Solana clusters",
      },
    }
  );
