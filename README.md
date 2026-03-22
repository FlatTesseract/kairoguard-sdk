# `@kairoguard/sdk`

[![npm version](https://img.shields.io/npm/v/@kairoguard/sdk)](https://www.npmjs.com/package/@kairoguard/sdk)
[![CI](https://github.com/FlatTesseract/kairo-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/FlatTesseract/kairo-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Kairo SDK helps agents and applications safely perform policy-aware onchain actions with multi-chain intent hashing, receipt minting on Sui, and dWallet lifecycle support.

## Install

```bash
npm install @kairoguard/sdk
```

## Why Kairo

- Multi-chain transaction intent support for EVM, Bitcoin, and Solana
- Sui policy receipt transaction builders for hard-gating flows
- dWallet creation and signing workflow primitives for agent builders
- CLI utilities for keystore and audit operations

## Hero Example (EVM + Policy Receipt)

```ts
import {
  KairoClient,
  computeEvmIntentFromUnsignedTxBytes,
  buildMintEvmReceiptTx,
} from "@kairoguard/sdk";

const client = new KairoClient({
  apiKey: process.env.KAIRO_API_KEY!,
  network: "testnet",
});

const wallet = await client.createWallet({
  curve: "Secp256k1",
  stableId: "demo-wallet",
});

const { intentHash } = computeEvmIntentFromUnsignedTxBytes({
  chainId: 84532, // Base Sepolia
  unsignedTxBytesHex: "0x...",
});

const receiptTx = buildMintEvmReceiptTx({
  packageId: "0x...",
  policyObjectId: "0x...",
  evmChainId: 84532,
  intentHash,
  toEvm: "0x0000000000000000000000000000000000000000",
});

console.log(wallet.walletId, receiptTx);
```

More complete runnable examples are in [`examples/`](./examples).

## Quick Start

1. Create a `KairoClient` with your API key.
2. Create or load a dWallet.
3. Compute chain-specific intent and run your policy receipt flow.

## Supported Chains

| Chain | Status |
| --- | --- |
| EVM | Supported |
| Bitcoin | Supported (intent utilities) |
| Solana | Supported (intent utilities) |
| Sui | Supported (receipt/policy tx builders) |

## Open Source vs Managed Components

### Open source in this repo

- TypeScript SDK source
- Public interfaces and helper utilities
- Example integrations

### Managed/private components

- Hosted backend services and relayer infrastructure
- Managed indexing and operational cloud dependencies

## CLI Usage

```bash
# Audit a bundle
npx @kairoguard/sdk kairo-audit audit <bundle-path>

# List locally stored keys
npx @kairoguard/sdk kairo list-keys
```

## Security and Support

- Vulnerability reporting: see [`SECURITY.md`](./SECURITY.md)
- Contribution guide: see [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Docs: [www.kairoguard.com/docs](https://www.kairoguard.com/docs)
