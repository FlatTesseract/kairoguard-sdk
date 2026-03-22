# Kairo

[![npm version](https://img.shields.io/npm/v/@kairoguard/sdk)](https://www.npmjs.com/package/@kairoguard/sdk)
[![CI](https://github.com/FlatTesseract/kairoguard-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/FlatTesseract/kairoguard-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Kairo is a policy-enforced, multi-chain signing system for agentic and wallet applications.  
This repository contains the SDK, core Sui Move contracts, and a stripped hackathon backend used for end-to-end demo verification.

## Project Structure

- `src/`: TypeScript SDK (`@kairoguard/sdk`)
- `contracts/`: Sui Move packages (`kairo_policy_engine`, `kairo_governance`)
- `backend/`: Hackathon edition backend (DKG, policy, vault, signing routes)
- `examples/`: Runnable SDK examples
- `docs/`: Architecture, custody, security, and flow docs

## How Kairo Works

1. A client prepares transaction intent (EVM/BTC/Solana).
2. Policy rules are evaluated and a policy receipt is minted on Sui.
3. Signing requests pass through the PolicyVault, which consumes valid receipts.
4. The backend coordinates DKG/presign/sign flows and returns signatures.

## Supported Chains

| Chain | Status |
| --- | --- |
| EVM | Supported |
| Bitcoin | Supported |
| Solana | Supported |
| Sui | Supported (policy, governance, custody, receipts) |

## Quick Start

### 1) SDK

```bash
npm install @kairoguard/sdk
```

```ts
import { KairoClient } from "@kairoguard/sdk";

const client = new KairoClient({
  apiKey: process.env.KAIRO_API_KEY!,
  network: "testnet",
});
```

### 2) Backend (hackathon edition)

```bash
cd backend
cp env.example .env
bun install
bun run src/index.ts
```

### 3) Contracts

Contracts are in `contracts/kairo_policy_engine` and `contracts/kairo_governance`.

## Open Source Boundary

### Open source in this repo

- SDK interfaces and client implementations
- Sui Move policy/custody/governance modules
- Core backend logic for demo flows
- Reference docs and examples

### Not included here

- Hosted production infrastructure and managed operations
- Internal deployment assets and upgrade metadata

## Security

- Vulnerability reporting: see [`SECURITY.md`](./SECURITY.md)
- Threat model and architecture security notes: see [`docs/SECURITY.md`](./docs/SECURITY.md)

## Documentation Index

- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)
- [`docs/FLOWS.md`](./docs/FLOWS.md)
- [`docs/POLICY_ENGINE.md`](./docs/POLICY_ENGINE.md)
- [`docs/POLICY_VAULT.md`](./docs/POLICY_VAULT.md)
- [`docs/CUSTODY.md`](./docs/CUSTODY.md)
- [`docs/DATA_MODEL.md`](./docs/DATA_MODEL.md)
- [`docs/RECOVERY.md`](./docs/RECOVERY.md)

## License

MIT
