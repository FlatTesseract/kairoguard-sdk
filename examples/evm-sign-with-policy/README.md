# EVM Sign With Policy

This example shows a minimal policy-aware flow:

1. Initialize `KairoClient`
2. Create a wallet
3. Compute EVM intent from an unsigned transaction payload
4. Build a Sui transaction to mint a policy receipt

## Prerequisites

- Node.js 18+
- A valid Kairo API key
- Sui package + policy object IDs for your environment

## Run

```bash
npm install
npm run dev
```

## Environment variables

- `KAIRO_API_KEY`
- `KAIRO_BACKEND_URL` (optional)
