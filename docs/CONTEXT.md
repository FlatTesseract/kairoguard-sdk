# Kairo — Current State (Living Context)

This file is a lightweight “what’s true right now” snapshot so new contributors can quickly orient.

## Repo layout

- **Browser extension (MV3)**: `external/key-spring/browser-extension/`
- **Backend (Bun/Elysia)**: `external/key-spring/backend/`
- **Demo frontend (Next.js)**: `external/key-spring/frontend/`
- **Sui Move policy engine**: `sui/kairo_policy_engine/`
- **SDK**: `packages/kairo-sdk/`

## What we implemented / restored recently

### Sui Move (`sui/kairo_policy_engine`)

- **Restored canonical Move sources** under `sui/kairo_policy_engine/sources/` (they had been emptied/moved).
- **`policy_registry.move`** now contains:
  - `Policy` and `PolicyReceipt` (hard-gate artifact).
  - `PolicyRegistry` (shared object), `PolicyVersion`, `PolicyChange` (version commitments + changelog).
  - `PolicyBinding` (shared object) to support “confirm policy updates” style gating via reaffirmation.
- **`custody_ledger.move`** now contains:
  - v0 append functions (caller-supplied `event_hash`) and
  - v2 append functions that compute `event_hash` **on-chain** via keccak256 over canonical BCS encoding.
- Added **`publish-fresh.ps1`** helper to publish a brand new Move package by temporarily moving aside `Published.toml` and cleaning build artifacts (fixes the “modules must all have 0x0 addresses” error).

### Browser extension UX (non-technical)

Setup → Policy now supports friendly guardrails:
- **Networks**: pick which networks are allowed (checkboxes).
- **Safer actions**: toggles to block common risky approvals (token approvals / NFT approvals).
- **Confirm policy updates**: UI wiring exists to store a “binding id” and call backend endpoints when available.

### Backend

- Backend derives the **admin address** from `SUI_ADMIN_SECRET_KEY` and serves it via:
  - `GET /health`
  - `GET /api/airgap/bootstrap`
- Added `KAIRO_POLICY_REGISTRY_ID` to backend config parsing (so registry-aware flows can be enabled when endpoints are present).
- Added `external/key-spring/backend/env.example` template and improved `run-demo.ps1` so only `SUI_ADMIN_SECRET_KEY` is required for startup (policy ids can be per-user from the extension).

### SDK (`packages/kairo-sdk`)

Restored:
- `src/auditBundle.ts` + `src/cli.ts`
- `src/types.ts`, `src/suiReceipts.ts`, `src/index.ts`
- `package.json` (was empty/corrupted)

The SDK now builds again and provides a minimal receipt verifier and an audit CLI entrypoint (`kairo-audit`).

## Fresh publish + registry setup (testnet)

1) **Publish Move package** (fresh package):

- Preferred on Windows:
  - `cd sui/kairo_policy_engine`
  - `.\publish-fresh.ps1`

2) **Create & share the PolicyRegistry**:

- Call `policy_registry::create_and_share_policy_registry`.
- The created shared object id becomes `KAIRO_POLICY_REGISTRY_ID`.

3) **Configure backend** (`external/key-spring/backend/.env`):

- `SUI_ADMIN_SECRET_KEY=suiprivkey...` (new wallet)
- `KAIRO_POLICY_MINT_PACKAGE_ID=0x...` (published package id)
- `KAIRO_CUSTODY_PACKAGE_ID=0x...` (same package id currently)
- `KAIRO_POLICY_REGISTRY_ID=0x...` (registry shared object id)

## Operational gotchas

- **Port collision**: if you see inconsistent `/health` results, make sure only one backend is listening on `:3001` (we hit a case where two `bun` processes were both bound).

- **`bun.lockb` must stay in sync with `package.json`**: The Dockerfile runs `bun install --frozen-lockfile`. If you upgrade a dependency in `package.json` (e.g. `@ika.xyz/sdk`), you **must** run `bun install` in the backend directory and commit the updated `bun.lockb`. An npm `package-lock.json` is not a substitute — bun ignores it.

- **Docker HEALTHCHECK start-period**: The backend takes ~60-90s to boot (IkaClient initialization makes many Sui RPC calls). The Dockerfile `HEALTHCHECK --start-period` must be large enough (currently 120s) or the container will be marked unhealthy before it's ready. If startup time increases (e.g. SDK upgrade), bump this value.

- **Protocol params are fetched client-side**: `ikaClient.getProtocolPublicParameters()` can be memory-intensive in constrained runtime environments. The backend endpoint returns 503; the browser extension fetches directly via the Ika SDK using the RPC URL from `/api/airgap/bootstrap`.

- **`SUI_RPC_URL` is critical for production**: Public testnet RPC endpoints may have strict rate limits (429). Both the backend and the extension (via the bootstrap response) use this URL. Without a dedicated high-throughput RPC endpoint, startup validation, encryption key fetches, and protocol params may fail intermittently.

- **Single replica recommended**: Running multiple backend instances against the same Sui RPC provider causes rate-limit contention at startup. Use 1 replica unless you have a high-throughput RPC plan.

- **Sui RPC rate-limit detection**: `isRpcRateLimited()` in `dkg-executor.ts` matches `429`, `"too many requests"`, and `"rate limit"`. If the Sui RPC provider changes its error format, update this function or startup validation will crash instead of gracefully continuing.

