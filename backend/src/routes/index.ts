/**
 * Kairo API Routes Module
 *
 * This module exports all API route handlers organized by domain:
 *
 * - **dkgRoutes**: DKG submission, status, and dWallet management endpoints
 * - **presignRoutes**: Presignature request and status endpoints
 * - **signRoutes**: MPC signing request and status endpoints
 * - **policyRoutes**: Policy creation, registry, binding, and receipt endpoints
 * - **vaultRouter**: PolicyVault registration and management (hard-gated signing)
 * - **evmRoutes**: EVM transaction parameter retrieval endpoints
 * - **bitcoinRoutes**: Bitcoin PSBT parsing, signing, and broadcasting endpoints
 * - **solanaRoutes**: Solana transaction signing and broadcasting endpoints
 * - **utilityRoutes**: Audit events, Sui object fetching, and bootstrap endpoints
 *
 * Routes are implemented as Elysia plugins and can be mounted via `.use()`.
 *
 * @module routes
 */

export { dkgRoutes } from "./dkg.js";
export { presignRoutes } from "./presign.js";
export { signRoutes } from "./sign.js";
export { policyRoutes } from "./policy.js";
export { vaultRoutes } from "./vault.js";
export { evmRoutes } from "./evm.js";
export { bitcoinRoutes } from "./bitcoin.js";
export { solanaRoutes } from "./solana.js";
export { utilityRoutes } from "./utility.js";