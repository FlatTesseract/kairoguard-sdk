# Kairo Backend (Hackathon Edition)

This backend powers the policy-gated signing flow used by the SDK and demo.

## Included in this public version

- DKG and wallet provisioning routes
- Presign and signing routes
- Policy receipt minting and policy-gated signing routes
- Vault provisioning and status routes
- EVM, Bitcoin, and Solana helper/signing routes

Auxiliary routes for admin, zkLogin, governance, and local dev pages are intentionally excluded from this hackathon edition.

## Requirements

- Bun 1.1+
- Access to Sui testnet (or your configured network)

## Setup

```bash
cp env.example .env
```

Fill required values in `.env`:

- `SUI_ADMIN_SECRET_KEY`
- `KAIRO_POLICY_VAULT_OBJECT_ID`
- `KAIRO_POLICY_REGISTRY_ID`
- `KAIRO_CUSTODY_CHAIN_OBJECT_ID`

## Run locally

```bash
bun install
bun run src/index.ts
```

Backend starts on `http://localhost:3001` by default.

## Health check

```bash
curl http://localhost:3001/health
```
