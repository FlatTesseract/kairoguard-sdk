/**
 * Enforcement Configuration
 * 
 * Centralized configuration for all enforcement-related settings.
 * This is the single source of truth for:
 * - Custody mode (REQUIRED is the default for all signing operations)
 * - Policy enforcement requirements
 * - Network-aware defaults
 * 
 * Enforcement Philosophy:
 * - All networks: Custody REQUIRED by default (every signing operation must produce a custody record)
 * - Override: Possible via environment or request, but BEST_EFFORT/DISABLED must not be used for production signing
 */

import { CustodyMode } from "../custody-mode.js";

/**
 * Network types supported.
 */
export type Network = "mainnet" | "testnet";

/**
 * Enforcement level for various checks.
 */
export enum EnforcementLevel {
  /** Must pass - fail the operation if check fails */
  STRICT = "STRICT",
  /** Should pass - warn but continue if check fails */
  WARN = "WARN",
  /** Skip the check entirely */
  SKIP = "SKIP",
}

/**
 * Complete enforcement configuration.
 */
export interface EnforcementConfig {
  /** Current network */
  network: Network;
  
  /** Custody enforcement mode */
  custodyMode: CustodyMode;
  
  /** Policy receipt validation level */
  policyValidation: EnforcementLevel;
  
  /** Policy binding validation level */
  policyBindingValidation: EnforcementLevel;
  
  /** Whether to require signature verification */
  requireSignatureVerification: boolean;
  
  /** Whether operations are in development mode */
  isDevelopment: boolean;
}

/**
 * Default enforcement config for mainnet.
 * Strict settings for production compliance.
 */
export const MAINNET_DEFAULTS: EnforcementConfig = {
  network: "mainnet",
  custodyMode: CustodyMode.REQUIRED,
  policyValidation: EnforcementLevel.STRICT,
  policyBindingValidation: EnforcementLevel.STRICT,
  requireSignatureVerification: true,
  isDevelopment: false,
};

/**
 * Default enforcement config for testnet.
 * Flexible settings for development.
 */
export const TESTNET_DEFAULTS: EnforcementConfig = {
  network: "testnet",
  custodyMode: CustodyMode.REQUIRED,
  policyValidation: EnforcementLevel.STRICT,
  policyBindingValidation: EnforcementLevel.WARN,
  requireSignatureVerification: true,
  isDevelopment: true,
};

/**
 * Get default enforcement config for a network.
 */
export function getNetworkDefaults(network: Network): EnforcementConfig {
  return network === "mainnet" ? MAINNET_DEFAULTS : TESTNET_DEFAULTS;
}

/**
 * Build enforcement config from environment and overrides.
 */
export function buildEnforcementConfig(params: {
  network: Network;
  custodyModeOverride?: CustodyMode;
  policyValidationOverride?: EnforcementLevel;
  policyBindingValidationOverride?: EnforcementLevel;
}): EnforcementConfig {
  const defaults = getNetworkDefaults(params.network);
  
  return {
    ...defaults,
    custodyMode: params.custodyModeOverride ?? defaults.custodyMode,
    policyValidation: params.policyValidationOverride ?? defaults.policyValidation,
    policyBindingValidation: params.policyBindingValidationOverride ?? defaults.policyBindingValidation,
  };
}

/**
 * Check if custody is required for the given config.
 */
export function isCustodyRequired(config: EnforcementConfig): boolean {
  return config.custodyMode === CustodyMode.REQUIRED;
}

/**
 * Check if custody is enabled (not disabled).
 */
export function isCustodyEnabled(config: EnforcementConfig): boolean {
  return config.custodyMode !== CustodyMode.DISABLED;
}

/**
 * Check if policy validation should fail on error.
 */
export function shouldFailOnPolicyError(config: EnforcementConfig): boolean {
  return config.policyValidation === EnforcementLevel.STRICT;
}

/**
 * Check if policy binding validation should fail on error.
 */
export function shouldFailOnBindingError(config: EnforcementConfig): boolean {
  return config.policyBindingValidation === EnforcementLevel.STRICT;
}

/**
 * Get a human-readable summary of enforcement settings.
 */
export function getEnforcementSummary(config: EnforcementConfig): string {
  return [
    `Network: ${config.network}`,
    `Custody: ${config.custodyMode}`,
    `Policy: ${config.policyValidation}`,
    `Binding: ${config.policyBindingValidation}`,
    `Dev Mode: ${config.isDevelopment}`,
  ].join(", ");
}
