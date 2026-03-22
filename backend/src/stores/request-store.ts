/**
 * Request Store Interface
 * 
 * Generic interface for in-memory request stores.
 * Centralizes storage, retrieval, and cleanup of pending requests.
 * 
 * Future: Can be swapped for durable storage without changing callers.
 */

/**
 * Base request type that all stored requests must extend.
 */
export interface BaseRequest {
  id: string;
  status: "pending" | "processing" | "completed" | "failed";
  createdAt: Date;
  error?: string;
}

/**
 * Store configuration options.
 */
export interface StoreConfig {
  /** How long to keep completed/failed requests before cleanup (ms) */
  retentionMs: number;
  /** Optional: Maximum number of requests to store (oldest evicted first) */
  maxSize?: number;
}

/**
 * Default configuration.
 */
export const DEFAULT_STORE_CONFIG: StoreConfig = {
  retentionMs: 60 * 60 * 1000, // 1 hour
  maxSize: 10_000,
};

/**
 * Generic request store interface.
 */
export interface IRequestStore<T extends BaseRequest> {
  /** Store a new request */
  set(id: string, request: T): void;
  
  /** Get a request by ID */
  get(id: string): T | undefined;
  
  /** Check if a request exists */
  has(id: string): boolean;
  
  /** Delete a request */
  delete(id: string): boolean;
  
  /** Get all requests */
  values(): IterableIterator<T>;
  
  /** Get all requests matching a filter */
  filter(predicate: (request: T) => boolean): T[];
  
  /** Get pending requests */
  getPending(): T[];
  
  /** Get processing requests */
  getProcessing(): T[];
  
  /** Update a request's status */
  updateStatus(id: string, status: T["status"], updates?: Partial<T>): boolean;
  
  /** Mark as processing */
  markProcessing(id: string): boolean;
  
  /** Mark as completed with results */
  markCompleted(id: string, results: Partial<T>): boolean;
  
  /** Mark as failed with error */
  markFailed(id: string, error: string): boolean;
  
  /** Cleanup old completed/failed requests */
  cleanup(): number;
  
  /** Get store size */
  size(): number;
  
  /** Clear all requests */
  clear(): void;
}

/**
 * In-memory implementation of IRequestStore.
 */
export class InMemoryRequestStore<T extends BaseRequest> implements IRequestStore<T> {
  private store = new Map<string, T>();
  private config: StoreConfig;
  private storeName: string;

  constructor(storeName: string, config: Partial<StoreConfig> = {}) {
    this.storeName = storeName;
    this.config = { ...DEFAULT_STORE_CONFIG, ...config };
  }

  set(id: string, request: T): void {
    // Check max size and evict oldest if needed
    if (this.config.maxSize && this.store.size >= this.config.maxSize) {
      this.evictOldest();
    }
    this.store.set(id, request);
  }

  get(id: string): T | undefined {
    return this.store.get(id);
  }

  has(id: string): boolean {
    return this.store.has(id);
  }

  delete(id: string): boolean {
    return this.store.delete(id);
  }

  values(): IterableIterator<T> {
    return this.store.values();
  }

  filter(predicate: (request: T) => boolean): T[] {
    return Array.from(this.store.values()).filter(predicate);
  }

  getPending(): T[] {
    return this.filter(r => r.status === "pending");
  }

  getProcessing(): T[] {
    return this.filter(r => r.status === "processing");
  }

  updateStatus(id: string, status: T["status"], updates?: Partial<T>): boolean {
    const request = this.store.get(id);
    if (!request) return false;
    
    this.store.set(id, {
      ...request,
      status,
      ...updates,
    });
    return true;
  }

  markProcessing(id: string): boolean {
    return this.updateStatus(id, "processing");
  }

  markCompleted(id: string, results: Partial<T>): boolean {
    return this.updateStatus(id, "completed", results);
  }

  markFailed(id: string, error: string): boolean {
    return this.updateStatus(id, "failed", { error } as Partial<T>);
  }

  cleanup(): number {
    const cutoffTime = Date.now() - this.config.retentionMs;
    let cleaned = 0;

    for (const [id, request] of this.store) {
      if (
        (request.status === "completed" || request.status === "failed") &&
        request.createdAt.getTime() < cutoffTime
      ) {
        this.store.delete(id);
        cleaned++;
      }
    }

    return cleaned;
  }

  size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }

  /**
   * Evict the oldest request to make room for new ones.
   */
  private evictOldest(): void {
    let oldestId: string | null = null;
    let oldestTime = Infinity;

    for (const [id, request] of this.store) {
      const time = request.createdAt.getTime();
      if (time < oldestTime) {
        oldestTime = time;
        oldestId = id;
      }
    }

    if (oldestId) {
      this.store.delete(oldestId);
    }
  }

  /**
   * Export store contents for debugging/monitoring.
   */
  toArray(): T[] {
    return Array.from(this.store.values());
  }

  /**
   * Get store name for logging.
   */
  getName(): string {
    return this.storeName;
  }
}
