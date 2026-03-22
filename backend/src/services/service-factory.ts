/**
 * Service Factory - Creates and wires up all Kairo services
 *
 * This factory provides a clean way to instantiate all extracted services
 * with proper dependency injection. The services can be used alongside
 * the existing DKGExecutorService for gradual migration.
 *
 * Usage:
 * ```typescript
 * const services = createServices();
 * // Use individual services
 * const presignResult = await services.presign.executePresignTransaction({...});
 * ```
 */

import { SuiClientBase, getSharedSuiClientBase } from "./sui-client-base.js";
import { DKGService } from "./dkg-service.js";
import { PresignService } from "./presign-service.js";
import { SignService } from "./sign-service.js";
import { PolicyService } from "./policy-service.js";
import { BroadcastService } from "./broadcast-service.js";
import { SuiCustodyService } from "./sui-custody-service.js";

/**
 * Collection of all Kairo services
 */
export interface KairoServices {
  /** Shared Sui/Ika client infrastructure */
  base: SuiClientBase;
  /** DKG and wallet management */
  dkg: DKGService;
  /** Presign operations */
  presign: PresignService;
  /** MPC signing */
  sign: SignService;
  /** Policy management */
  policy: PolicyService;
  /** EVM broadcast */
  broadcast: BroadcastService;
  /** Sui custody operations */
  custody: SuiCustodyService;
}

/**
 * Create all Kairo services with the shared Sui client base.
 *
 * This is the recommended way to instantiate services for production use.
 * All services share the same SuiClientBase instance for efficient resource usage.
 *
 * @returns Collection of all services
 */
export function createServices(): KairoServices {
  const base = getSharedSuiClientBase();
  return createServicesWithBase(base);
}

/**
 * Create all Kairo services with a custom Sui client base.
 *
 * This is useful for testing where you want to inject a mock base.
 *
 * @param base - Custom SuiClientBase instance
 * @returns Collection of all services
 */
export function createServicesWithBase(base: SuiClientBase): KairoServices {
  const custody = new SuiCustodyService(base);

  const policy = new PolicyService(
    base,
    // Inject custody append function
    async (params) => {
      return custody.appendCustodyEventWithReceipt({
        custodyPackageId: params.custodyPackageId,
        custodyChainObjectId: params.custodyChainObjectId,
        receiptObjectId: params.receiptObjectId,
        policyObjectId: params.policyObjectId,
        intentHashHex: params.intentHashHex as any,
        toEvm: params.toEvm,
        mintDigest: params.mintDigest,
      });
    },
    // Inject custody chain creation function
    async (params) => {
      return custody.createAndShareCustodyChainForPolicy({
        custodyPackageId: params.custodyPackageId,
        policyObjectId: params.policyObjectId,
      });
    }
  );

  return {
    base,
    dkg: new DKGService(base),
    presign: new PresignService(base),
    sign: new SignService(base),
    policy,
    broadcast: new BroadcastService(),
    custody,
  };
}

/**
 * Lazy-initialized singleton services instance.
 * Use getServices() for production code.
 */
let _servicesInstance: KairoServices | null = null;

/**
 * Get the shared services instance.
 *
 * This creates services on first call and returns the cached instance thereafter.
 * Use this for production code where you want consistent service instances.
 *
 * @returns Shared services instance
 */
export function getServices(): KairoServices {
  if (!_servicesInstance) {
    _servicesInstance = createServices();
  }
  return _servicesInstance;
}

/**
 * Reset the shared services instance.
 *
 * Use this in tests to ensure clean state between test cases.
 */
export function resetServices(): void {
  _servicesInstance = null;
}
