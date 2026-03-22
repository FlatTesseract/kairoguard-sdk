/**
 * Bitcoin Routes
 *
 * API endpoints for Bitcoin transaction signing and broadcasting.
 */

import { Elysia, t } from "elysia";
import { logger } from "../logger.js";
import { createBitcoinConnector, type BitcoinConnector } from "../chains/bitcoin/index.js";
import {
  ChainNamespace,
  BitcoinScriptType,
  type BitcoinNetwork,
  type ParsedTransaction,
} from "../chains/types.js";
import { chainConnectorRegistry } from "../chains/registry.js";
import { dkgExecutor } from "../dkg-executor.js";
import { bytesToHex } from "../chains/bitcoin/psbt.js";

// Initialize Bitcoin connectors for supported networks
const BITCOIN_NETWORKS: BitcoinNetwork[] = ["mainnet", "testnet", "signet"];

for (const network of BITCOIN_NETWORKS) {
  const connector = createBitcoinConnector(network);
  chainConnectorRegistry.registerConnector(connector);
}

/**
 * Get Bitcoin connector for network.
 */
function getBitcoinConnector(network: BitcoinNetwork): BitcoinConnector {
  const connector = chainConnectorRegistry.getConnector(ChainNamespace.BITCOIN, network);
  if (!connector) {
    throw new Error(`Bitcoin connector not found for network: ${network}`);
  }
  return connector as BitcoinConnector;
}

export const bitcoinRoutes = new Elysia({ prefix: "/api/bitcoin" })
  /**
   * Parse a PSBT and extract transaction details.
   */
  .post(
    "/parse",
    async ({ body }) => {
      try {
        const connector = getBitcoinConnector(body.network);
        const parsed = await connector.parseTransaction(body.psbtHex);
        const utxos = parsed.btc?.utxos ?? [];
        const scriptType = parsed.btc?.scriptType ?? BitcoinScriptType.P2WPKH;
        const inputCount = utxos.length;
        const outputCount = parsed.amounts.length;

        // Best-effort fee rate estimate (sat/vB) from PSBT utxos/outputs.
        // NOTE: This is an approximation for unsigned PSBTs; it is still useful for policy maxFeeRate gating.
        const sumIn = utxos.reduce((acc, u) => acc + (u.value ?? 0n), 0n);
        const sumOut = parsed.amounts.reduce((acc, v) => acc + (v ?? 0n), 0n);
        const fee = sumIn > sumOut ? sumIn - sumOut : 0n;
        const inputVb =
          scriptType === BitcoinScriptType.P2PKH
            ? 148n
            : scriptType === BitcoinScriptType.P2TR
              ? 58n
              : 68n; // P2WPKH default
        const vbytesEst = 10n + BigInt(inputCount) * inputVb + BigInt(outputCount) * 34n;
        const feeRateSatVb =
          vbytesEst > 0n ? Number((fee + vbytesEst - 1n) / vbytesEst) : 0;

        return {
          success: true,
          transaction: {
            destinations: parsed.destinations,
            amounts: parsed.amounts.map((a) => a.toString()),
            intentHash: Buffer.from(parsed.intentHash).toString("hex"),
            scriptType,
            utxoCount: inputCount,
            feeRateSatVb,
          },
        };
      } catch (error) {
        logger.error({ error }, "Failed to parse PSBT");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to parse PSBT",
        };
      }
    },
    {
      body: t.Object({
        network: t.Union([
          t.Literal("mainnet"),
          t.Literal("testnet"),
          t.Literal("signet"),
        ]),
        psbtHex: t.String(),
      }),
      detail: {
        summary: "Parse Bitcoin PSBT",
        description: "Parse a PSBT and extract transaction details for policy verification",
      },
    }
  )

  /**
   * Get fee estimates for a Bitcoin network.
   */
  .get(
    "/fees/:network",
    async ({ params }) => {
      try {
        const connector = getBitcoinConnector(params.network as BitcoinNetwork);
        const txParams = await connector.getTxParams("");

        return {
          success: true,
          fees: {
            fastestFee: txParams.fee.maximum,
            halfHourFee: txParams.fee.suggested,
            hourFee: txParams.fee.minimum,
          },
        };
      } catch (error) {
        logger.error({ error }, "Failed to get Bitcoin fee estimates");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to get fee estimates",
        };
      }
    },
    {
      params: t.Object({
        network: t.String(),
      }),
      detail: {
        summary: "Get Bitcoin fee estimates",
        description: "Get current fee estimates in sat/vB for a Bitcoin network",
      },
    }
  )

  /**
   * Derive Bitcoin address from public key.
   */
  .post(
    "/address",
    async ({ body }) => {
      try {
        const connector = getBitcoinConnector(body.network);
        const publicKey = Buffer.from(body.publicKeyHex, "hex");
        const address = connector.deriveAddress(publicKey, {
          scriptType: body.scriptType ?? BitcoinScriptType.P2WPKH,
        });

        return {
          success: true,
          address,
          network: body.network,
          scriptType: body.scriptType ?? BitcoinScriptType.P2WPKH,
        };
      } catch (error) {
        logger.error({ error }, "Failed to derive Bitcoin address");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Failed to derive address",
        };
      }
    },
    {
      body: t.Object({
        network: t.Union([
          t.Literal("mainnet"),
          t.Literal("testnet"),
          t.Literal("signet"),
        ]),
        publicKeyHex: t.String(),
        scriptType: t.Optional(t.Number()),
      }),
      detail: {
        summary: "Derive Bitcoin address",
        description: "Derive a Bitcoin address from a public key",
      },
    }
  )

  /**
   * Validate a Bitcoin address.
   */
  .post(
    "/validate-address",
    async ({ body }) => {
      try {
        const connector = getBitcoinConnector(body.network);
        const valid = connector.validateAddress(body.address);

        return {
          success: true,
          valid,
          address: body.address,
          network: body.network,
        };
      } catch (error) {
        return {
          success: true,
          valid: false,
          address: body.address,
          network: body.network,
          error: error instanceof Error ? error.message : "Validation failed",
        };
      }
    },
    {
      body: t.Object({
        network: t.Union([
          t.Literal("mainnet"),
          t.Literal("testnet"),
          t.Literal("signet"),
        ]),
        address: t.String(),
      }),
      detail: {
        summary: "Validate Bitcoin address",
        description: "Validate a Bitcoin address for a specific network",
      },
    }
  )

  /**
   * Sign a Bitcoin transaction (PSBT).
   * This endpoint handles the full signing flow:
   * 1. Parse PSBT
   * 2. Compute sighash/preimage
   * 3. Request MPC signature via Ika network
   * 4. Return signature for client-side PSBT finalization
   */
  .post(
    "/sign",
    async ({ body }) => {
      try {
        const connector = getBitcoinConnector(body.network);

        // Parse the PSBT
        const parsed = await connector.parseTransaction(body.psbtHex);
        const scriptType = parsed.btc?.scriptType ?? BitcoinScriptType.P2WPKH;
        const useTaproot = scriptType === BitcoinScriptType.P2TR;

        logger.info(
          {
            network: body.network,
            destinations: parsed.destinations,
            scriptType,
            useTaproot,
            intentHash: Buffer.from(parsed.intentHash).toString("hex").slice(0, 16) + "...",
          },
          "Bitcoin sign request received"
        );

        // Get the message bytes to sign
        let messageBytes: Uint8Array;
        let tapScriptData: ReturnType<typeof connector.prepareTaprootScriptPath> | undefined;

        if (useTaproot && body.publicKeyHex) {
          // For Taproot, we need the full preimage for script-path signing
          const publicKey = Buffer.from(body.publicKeyHex, "hex");
          const result = connector.getTaprootScriptpathPreimage(
            body.psbtHex,
            body.inputIndex ?? 0,
            publicKey
          );
          messageBytes = result.preimage;
          tapScriptData = result.tapScriptData;
          
          logger.debug(
            {
              preimageLength: messageBytes.length,
              leafHashHex: bytesToHex(result.leafHash),
            },
            "Computed Taproot script-path preimage"
          );
        } else {
          // For ECDSA (P2PKH, P2WPKH), provide SHA256(preimage) so Ika's Hash.SHA256 produces hash256(preimage)
          messageBytes = connector.getEcdsaMessageForIkaSigning(
            body.psbtHex,
            body.inputIndex ?? 0,
            body.sighashType ?? 0x01
          );
        }

        // Validate user MPC inputs
        if (!body.userSignMessage || body.userSignMessage.length === 0) {
          return {
            success: false,
            error: "userSignMessage is required for MPC signing",
            parsed: {
              destinations: parsed.destinations,
              amounts: parsed.amounts.map((a) => a.toString()),
              intentHash: Buffer.from(parsed.intentHash).toString("hex"),
              scriptType,
              messageToSign: bytesToHex(messageBytes),
            },
          };
        }

        if (!body.presignId) {
          return {
            success: false,
            error: "presignId is required for MPC signing",
            parsed: {
              destinations: parsed.destinations,
              amounts: parsed.amounts.map((a) => a.toString()),
              intentHash: Buffer.from(parsed.intentHash).toString("hex"),
              scriptType,
              messageToSign: bytesToHex(messageBytes),
            },
          };
        }

        // Execute Bitcoin MPC signing
        const signResult = await dkgExecutor.executeBitcoinSign({
          dWalletId: body.dWalletId,
          dWalletCapId: body.dWalletCapId,
          presignId: body.presignId,
          messageBytes,
          userSignMessage: body.userSignMessage,
          userOutputSignature: body.userOutputSignature,
          encryptedUserSecretKeyShareId: body.encryptedUserSecretKeyShareId,
          useTaproot,
          policyReceiptId: body.policyReceiptId,
          policyObjectId: body.policyObjectId,
          policyVersion: body.policyVersion,
          policyBindingObjectId: body.policyBindingObjectId,
          intentHashHex: `0x${bytesToHex(parsed.intentHash)}`,
          network: body.network,
          destinations: parsed.destinations,
        });

        // Format the signature for the script type
        const formattedSignature = connector.formatSignatureForType(
          signResult.signatureBytes,
          scriptType,
          body.sighashType
        );

        // Optionally finalize PSBT server-side if publicKeyHex is provided
        let finalized: { psbtHex: string; txHex: string } | undefined;
        if (body.publicKeyHex) {
          const publicKey = Buffer.from(body.publicKeyHex, "hex");
          finalized = connector.finalizeSignedPsbt({
            psbtHex: body.psbtHex,
            inputIndex: body.inputIndex ?? 0,
            scriptType,
            signature: signResult.signatureBytes,
            publicKey,
            sighashType: body.sighashType,
          });
        }

        logger.info(
          {
            signId: signResult.signId,
            signatureLength: signResult.signatureBytes.length,
            formattedLength: formattedSignature.length,
            scriptType,
            network: body.network,
          },
          "Bitcoin MPC signing completed"
        );

        return {
          success: true,
          signId: signResult.signId,
          digest: signResult.digest,
          signature: {
            raw: signResult.signatureHex,
            formatted: bytesToHex(formattedSignature),
          },
          signed: finalized
            ? {
                psbtHex: finalized.psbtHex,
                txHex: finalized.txHex,
              }
            : undefined,
          parsed: {
            destinations: parsed.destinations,
            amounts: parsed.amounts.map((a) => a.toString()),
            intentHash: Buffer.from(parsed.intentHash).toString("hex"),
            scriptType,
          },
          // Include Taproot data if applicable
          taproot: tapScriptData ? {
            leafScript: bytesToHex(tapScriptData.leafScript),
            leafHash: bytesToHex(tapScriptData.leafHash),
            controlBlock: bytesToHex(tapScriptData.controlBlock),
            leafVersion: tapScriptData.leafVersion,
          } : undefined,
        };
      } catch (error) {
        logger.error({ error }, "Failed to process Bitcoin sign request");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Sign request failed",
        };
      }
    },
    {
      body: t.Object({
        network: t.Union([
          t.Literal("mainnet"),
          t.Literal("testnet"),
          t.Literal("signet"),
        ]),
        psbtHex: t.String(),
        dWalletId: t.String(),
        dWalletCapId: t.String(),
        presignId: t.String(),
        // User MPC inputs
        userSignMessage: t.Array(t.Number()),
        encryptedUserSecretKeyShareId: t.Optional(t.String()),
        userOutputSignature: t.Optional(t.Array(t.Number())),
        // Policy inputs (required for BTC hard gate)
        policyObjectId: t.Optional(t.String()),
        policyVersion: t.Optional(t.String()),
        policyReceiptId: t.String(),
        policyBindingObjectId: t.Optional(t.String()),
        // Signing options
        inputIndex: t.Optional(t.Number()),
        sighashType: t.Optional(t.Number()),
        publicKeyHex: t.Optional(t.String()),
      }),
      detail: {
        summary: "Sign Bitcoin transaction",
        description:
          "Sign a Bitcoin PSBT using MPC. Returns the signature for client-side PSBT finalization.",
      },
    }
  )

  /**
   * Prepare a PSBT for signing.
   * Returns the sighash/preimage that needs to be signed via MPC.
   */
  .post(
    "/prepare",
    async ({ body }) => {
      try {
        const connector = getBitcoinConnector(body.network);

        // Parse the PSBT
        const parsed = await connector.parseTransaction(body.psbtHex);
        const scriptType = parsed.btc?.scriptType ?? BitcoinScriptType.P2WPKH;
        const useTaproot = scriptType === BitcoinScriptType.P2TR;
        const sighashType = body.sighashType ?? 0x01;

        // Get all sighashes for the PSBT
        const publicKey = body.publicKeyHex
          ? Buffer.from(body.publicKeyHex, "hex")
          : undefined;
        
        const sighashes = connector.getAllSighashes(body.psbtHex, publicKey);

        return {
          success: true,
          parsed: {
            destinations: parsed.destinations,
            amounts: parsed.amounts.map((a) => a.toString()),
            scriptType,
            useTaproot,
            inputCount: parsed.btc?.utxos.length ?? 0,
          },
          inputs: sighashes.map((s) => ({
            inputIndex: s.inputIndex,
            sighash: bytesToHex(s.sighash),
            scriptType: s.scriptType,
            // This is the message bytes the client should feed into createUserSignMessageWithPublicOutput.
            // For ECDSA inputs we provide SHA256(preimage) so Ika's Hash.SHA256 yields hash256(preimage).
            // For Taproot script-path we provide the full preimage (Ika applies Hash.SHA256 once).
            messageToSign:
              s.preimage && s.scriptType === BitcoinScriptType.P2TR
                ? bytesToHex(s.preimage)
                : bytesToHex(
                    connector.getEcdsaMessageForIkaSigning(
                      body.psbtHex,
                      s.inputIndex,
                      sighashType
                    )
                  ),
            sighashType,
            preimage: s.preimage ? bytesToHex(s.preimage) : undefined,
            taproot: s.tapScriptData ? {
              leafScript: bytesToHex(s.tapScriptData.leafScript),
              leafHash: bytesToHex(s.tapScriptData.leafHash),
              controlBlock: bytesToHex(s.tapScriptData.controlBlock),
              leafVersion: s.tapScriptData.leafVersion,
            } : undefined,
          })),
        };
      } catch (error) {
        logger.error({ error }, "Failed to prepare PSBT for signing");
        return {
          success: false,
          error: error instanceof Error ? error.message : "Prepare failed",
        };
      }
    },
    {
      body: t.Object({
        network: t.Union([
          t.Literal("mainnet"),
          t.Literal("testnet"),
          t.Literal("signet"),
        ]),
        psbtHex: t.String(),
        publicKeyHex: t.Optional(t.String()),
        sighashType: t.Optional(t.Number()),
      }),
      detail: {
        summary: "Prepare PSBT for signing",
        description:
          "Parse a PSBT and return sighashes/preimages for each input. Use this before calling createUserSignMessage on the client.",
      },
    }
  )

  /**
   * Broadcast a signed Bitcoin transaction.
   */
  .post(
    "/broadcast",
    async ({ body }) => {
      try {
        const connector = getBitcoinConnector(body.network);
        const txBytes = Buffer.from(body.txHex, "hex");
        const result = await connector.broadcast(txBytes);

        if (result.success) {
          logger.info(
            { txHash: result.txHash, network: body.network },
            "Bitcoin transaction broadcast successful"
          );
        }

        return result;
      } catch (error) {
        logger.error({ error }, "Failed to broadcast Bitcoin transaction");
        return {
          success: false,
          txHash: "",
          error: error instanceof Error ? error.message : "Broadcast failed",
        };
      }
    },
    {
      body: t.Object({
        network: t.Union([
          t.Literal("mainnet"),
          t.Literal("testnet"),
          t.Literal("signet"),
        ]),
        txHex: t.String(),
      }),
      detail: {
        summary: "Broadcast Bitcoin transaction",
        description: "Broadcast a signed Bitcoin transaction to the network",
      },
    }
  )

  /**
   * Get supported Bitcoin networks.
   */
  .get(
    "/networks",
    () => {
      return {
        success: true,
        networks: BITCOIN_NETWORKS.map((network) => ({
          id: network,
          name: network.charAt(0).toUpperCase() + network.slice(1),
          namespace: ChainNamespace.BITCOIN,
        })),
      };
    },
    {
      detail: {
        summary: "List supported Bitcoin networks",
        description: "Get a list of supported Bitcoin networks",
      },
    }
  );
