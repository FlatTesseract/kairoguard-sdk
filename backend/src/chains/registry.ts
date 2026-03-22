/**
 * Chain Connector Registry
 *
 * Central registry for managing chain connectors.
 * Allows dynamic registration and lookup of connectors by namespace and chainId.
 */

import { logger } from "../logger.js";
import {
  type ChainConnector,
  type ChainConnectorRegistry,
  type ChainId,
  ChainNamespace,
  namespaceToString,
} from "./types.js";

/**
 * Default implementation of the chain connector registry.
 */
class DefaultChainConnectorRegistry implements ChainConnectorRegistry {
  private connectors = new Map<string, ChainConnector>();

  private makeKey(namespace: ChainNamespace, chainId: ChainId): string {
    return `${namespace}:${chainId}`;
  }

  getConnector(namespace: ChainNamespace, chainId: ChainId): ChainConnector | undefined {
    return this.connectors.get(this.makeKey(namespace, chainId));
  }

  registerConnector(connector: ChainConnector): void {
    const key = this.makeKey(connector.namespace, connector.chainId);
    if (this.connectors.has(key)) {
      logger.warn(
        { namespace: namespaceToString(connector.namespace), chainId: connector.chainId },
        "Overwriting existing chain connector"
      );
    }
    this.connectors.set(key, connector);
    logger.info(
      { namespace: namespaceToString(connector.namespace), chainId: connector.chainId },
      "Registered chain connector"
    );
  }

  listConnectors(): ChainConnector[] {
    return Array.from(this.connectors.values());
  }
}

/**
 * Global chain connector registry instance.
 */
export const chainConnectorRegistry: ChainConnectorRegistry = new DefaultChainConnectorRegistry();

/**
 * Get a connector from the global registry.
 * Throws if not found.
 */
export function getConnectorOrThrow(namespace: ChainNamespace, chainId: ChainId): ChainConnector {
  const connector = chainConnectorRegistry.getConnector(namespace, chainId);
  if (!connector) {
    throw new Error(
      `No connector registered for ${namespaceToString(namespace)} chainId=${chainId}`
    );
  }
  return connector;
}

/**
 * Check if a connector is registered.
 */
export function hasConnector(namespace: ChainNamespace, chainId: ChainId): boolean {
  return chainConnectorRegistry.getConnector(namespace, chainId) !== undefined;
}
