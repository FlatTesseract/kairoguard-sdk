/**
 * Custody enforcement mode for Kairo policy operations.
 *
 * Controls whether custody chain append is required for compliance.
 */
export enum CustodyMode {
  /**
   * Fail the entire operation if custody append fails.
   * Default for production / compliance-critical operations.
   * A signature without a custody event is a gap in the chain of custody.
   */
  REQUIRED = "REQUIRED",

  /**
   * Log and continue if custody append fails.
   * NOT compliant. Only for local development — must never be used in
   * testnet or production for transaction signing.
   */
  BEST_EFFORT = "BEST_EFFORT",

  /**
   * Skip custody entirely.
   * Only for non-signing operations (e.g., login message signing).
   * Must NOT be used for transaction signing — every signing operation
   * requires a custody record.
   */
  DISABLED = "DISABLED",
}

/** Status of custody append operation */
export type CustodyStatus = "appended" | "failed" | "skipped" | "disabled";

/**
 * Resolve effective custody mode from operation override, config, and network.
 */
export function resolveEffectiveCustodyMode(
  operationOverride: CustodyMode | undefined,
  configMode: CustodyMode,
): CustodyMode {
  // Operation-level override takes precedence
  if (operationOverride !== undefined) {
    return operationOverride;
  }
  return configMode;
}
