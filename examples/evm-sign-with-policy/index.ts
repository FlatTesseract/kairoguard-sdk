import {
  KairoClient,
  buildMintEvmReceiptTx,
  computeEvmIntentFromUnsignedTxBytes,
} from "@kairoguard/sdk";

async function main() {
  const apiKey = process.env.KAIRO_API_KEY;
  if (!apiKey) {
    throw new Error("Missing KAIRO_API_KEY");
  }

  const client = new KairoClient({
    apiKey,
    backendUrl: process.env.KAIRO_BACKEND_URL,
    network: "testnet",
  });

  const wallet = await client.createWallet({
    curve: "Secp256k1",
    stableId: "example-evm-wallet",
  });

  const { intentHash } = computeEvmIntentFromUnsignedTxBytes({
    chainId: 84532,
    unsignedTxBytesHex: "0x02",
  });

  const receiptTx = buildMintEvmReceiptTx({
    packageId: "0xYOUR_PACKAGE_ID",
    policyObjectId: "0xYOUR_POLICY_OBJECT_ID",
    evmChainId: 84532,
    intentHash,
    toEvm: "0x0000000000000000000000000000000000000000",
  });

  console.log("Created wallet:", wallet.walletId);
  console.log("Intent hash:", intentHash);
  console.log("Prepared Sui receipt tx:", receiptTx);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
