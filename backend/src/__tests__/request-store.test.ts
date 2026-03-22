/**
 * Request Store Tests
 * 
 * Validates the in-memory request store implementation.
 */

import { describe, it, expect, beforeEach } from "bun:test";
import {
  InMemoryRequestStore,
  type BaseRequest,
  DEFAULT_STORE_CONFIG,
} from "../stores/request-store.js";

// Test request type
interface TestRequest extends BaseRequest {
  data: string;
  result?: string;
}

describe("InMemoryRequestStore", () => {
  let store: InMemoryRequestStore<TestRequest>;

  beforeEach(() => {
    store = new InMemoryRequestStore<TestRequest>("test");
  });

  describe("basic operations", () => {
    it("should set and get a request", () => {
      const request: TestRequest = {
        id: "req-1",
        status: "pending",
        data: "test data",
        createdAt: new Date(),
      };

      store.set("req-1", request);
      const retrieved = store.get("req-1");

      expect(retrieved).toBeDefined();
      expect(retrieved?.id).toBe("req-1");
      expect(retrieved?.data).toBe("test data");
    });

    it("should return undefined for non-existent request", () => {
      expect(store.get("non-existent")).toBeUndefined();
    });

    it("should check if request exists", () => {
      store.set("req-1", {
        id: "req-1",
        status: "pending",
        data: "test",
        createdAt: new Date(),
      });

      expect(store.has("req-1")).toBe(true);
      expect(store.has("req-2")).toBe(false);
    });

    it("should delete a request", () => {
      store.set("req-1", {
        id: "req-1",
        status: "pending",
        data: "test",
        createdAt: new Date(),
      });

      expect(store.delete("req-1")).toBe(true);
      expect(store.get("req-1")).toBeUndefined();
      expect(store.delete("req-1")).toBe(false);
    });

    it("should report correct size", () => {
      expect(store.size()).toBe(0);

      store.set("req-1", { id: "req-1", status: "pending", data: "1", createdAt: new Date() });
      expect(store.size()).toBe(1);

      store.set("req-2", { id: "req-2", status: "pending", data: "2", createdAt: new Date() });
      expect(store.size()).toBe(2);

      store.delete("req-1");
      expect(store.size()).toBe(1);
    });
  });

  describe("status updates", () => {
    it("should update status", () => {
      store.set("req-1", {
        id: "req-1",
        status: "pending",
        data: "test",
        createdAt: new Date(),
      });

      const updated = store.updateStatus("req-1", "processing");
      expect(updated).toBe(true);
      expect(store.get("req-1")?.status).toBe("processing");
    });

    it("should mark as processing", () => {
      store.set("req-1", {
        id: "req-1",
        status: "pending",
        data: "test",
        createdAt: new Date(),
      });

      store.markProcessing("req-1");
      expect(store.get("req-1")?.status).toBe("processing");
    });

    it("should mark as completed with results", () => {
      store.set("req-1", {
        id: "req-1",
        status: "processing",
        data: "test",
        createdAt: new Date(),
      });

      store.markCompleted("req-1", { result: "success" });
      const request = store.get("req-1");
      expect(request?.status).toBe("completed");
      expect(request?.result).toBe("success");
    });

    it("should mark as failed with error", () => {
      store.set("req-1", {
        id: "req-1",
        status: "processing",
        data: "test",
        createdAt: new Date(),
      });

      store.markFailed("req-1", "Something went wrong");
      const request = store.get("req-1");
      expect(request?.status).toBe("failed");
      expect(request?.error).toBe("Something went wrong");
    });

    it("should return false for non-existent request", () => {
      expect(store.updateStatus("non-existent", "processing")).toBe(false);
      expect(store.markProcessing("non-existent")).toBe(false);
      expect(store.markCompleted("non-existent", {})).toBe(false);
      expect(store.markFailed("non-existent", "error")).toBe(false);
    });
  });

  describe("filtering", () => {
    beforeEach(() => {
      store.set("req-1", { id: "req-1", status: "pending", data: "1", createdAt: new Date() });
      store.set("req-2", { id: "req-2", status: "pending", data: "2", createdAt: new Date() });
      store.set("req-3", { id: "req-3", status: "processing", data: "3", createdAt: new Date() });
      store.set("req-4", { id: "req-4", status: "completed", data: "4", createdAt: new Date() });
      store.set("req-5", { id: "req-5", status: "failed", data: "5", createdAt: new Date() });
    });

    it("should get pending requests", () => {
      const pending = store.getPending();
      expect(pending.length).toBe(2);
      expect(pending.map(r => r.id).sort()).toEqual(["req-1", "req-2"]);
    });

    it("should get processing requests", () => {
      const processing = store.getProcessing();
      expect(processing.length).toBe(1);
      expect(processing[0].id).toBe("req-3");
    });

    it("should filter with custom predicate", () => {
      const filtered = store.filter(r => r.data === "1" || r.data === "5");
      expect(filtered.length).toBe(2);
    });
  });

  describe("cleanup", () => {
    it("should cleanup old completed requests", () => {
      // Create requests with old timestamps
      const oldDate = new Date(Date.now() - 2 * 60 * 60 * 1000); // 2 hours ago
      const newDate = new Date();

      store.set("old-completed", {
        id: "old-completed",
        status: "completed",
        data: "old",
        createdAt: oldDate,
      });
      store.set("old-failed", {
        id: "old-failed",
        status: "failed",
        data: "old",
        createdAt: oldDate,
      });
      store.set("old-pending", {
        id: "old-pending",
        status: "pending",
        data: "old",
        createdAt: oldDate,
      });
      store.set("new-completed", {
        id: "new-completed",
        status: "completed",
        data: "new",
        createdAt: newDate,
      });

      const cleaned = store.cleanup();

      expect(cleaned).toBe(2); // old-completed and old-failed
      expect(store.has("old-completed")).toBe(false);
      expect(store.has("old-failed")).toBe(false);
      expect(store.has("old-pending")).toBe(true); // pending not cleaned
      expect(store.has("new-completed")).toBe(true); // recent not cleaned
    });
  });

  describe("max size enforcement", () => {
    it("should evict oldest when max size reached", () => {
      const smallStore = new InMemoryRequestStore<TestRequest>("small", {
        maxSize: 3,
      });

      smallStore.set("req-1", {
        id: "req-1",
        status: "pending",
        data: "1",
        createdAt: new Date(1000),
      });
      smallStore.set("req-2", {
        id: "req-2",
        status: "pending",
        data: "2",
        createdAt: new Date(2000),
      });
      smallStore.set("req-3", {
        id: "req-3",
        status: "pending",
        data: "3",
        createdAt: new Date(3000),
      });

      expect(smallStore.size()).toBe(3);

      // Add a 4th request - should evict req-1 (oldest)
      smallStore.set("req-4", {
        id: "req-4",
        status: "pending",
        data: "4",
        createdAt: new Date(4000),
      });

      expect(smallStore.size()).toBe(3);
      expect(smallStore.has("req-1")).toBe(false); // evicted
      expect(smallStore.has("req-2")).toBe(true);
      expect(smallStore.has("req-3")).toBe(true);
      expect(smallStore.has("req-4")).toBe(true);
    });
  });

  describe("iteration", () => {
    it("should iterate over all values", () => {
      store.set("req-1", { id: "req-1", status: "pending", data: "1", createdAt: new Date() });
      store.set("req-2", { id: "req-2", status: "pending", data: "2", createdAt: new Date() });

      const values = Array.from(store.values());
      expect(values.length).toBe(2);
    });

    it("should export to array", () => {
      store.set("req-1", { id: "req-1", status: "pending", data: "1", createdAt: new Date() });
      store.set("req-2", { id: "req-2", status: "pending", data: "2", createdAt: new Date() });

      const array = store.toArray();
      expect(array.length).toBe(2);
    });
  });

  describe("clear", () => {
    it("should clear all requests", () => {
      store.set("req-1", { id: "req-1", status: "pending", data: "1", createdAt: new Date() });
      store.set("req-2", { id: "req-2", status: "pending", data: "2", createdAt: new Date() });

      store.clear();
      expect(store.size()).toBe(0);
    });
  });
});
