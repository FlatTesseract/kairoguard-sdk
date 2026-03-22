/**
 * Kairo Backend Server
 *
 * Main entry point for the backend API.
 * Routes are organized into focused modules under ./routes/
 */

// Prefer IPv4 first to avoid intermittent egress failures when DNS returns IPv6
// but the runtime/network cannot route IPv6 reliably.
import dns from "node:dns";
dns.setDefaultResultOrder("ipv4first");

import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { dkgExecutor } from "./dkg-executor.js";
import {
  dkgRoutes,
  presignRoutes,
  signRoutes,
  policyRoutes,
  vaultRoutes,
  evmRoutes,
  bitcoinRoutes,
  solanaRoutes,
  utilityRoutes,
} from "./routes/index.js";
import {
  initRegistry,
  getKeyRecord,
  isAuthEnabled,
  type ApiKeyRecord,
} from "./key-registry.js";

// Sliding-window rate limiter (per API key)
const RATE_LIMIT_WINDOW_MS = 60_000;
const TIER_LIMITS: Record<string, number> = { default: 120, premium: 600 };
const rateLimitBuckets = new Map<string, number[]>();

function rateLimitCheck(apiKey: string, tier: string): { allowed: boolean; retryAfterMs: number } {
  const max = TIER_LIMITS[tier] ?? TIER_LIMITS.default;
  const now = Date.now();
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  let bucket = rateLimitBuckets.get(apiKey);
  if (!bucket) {
    bucket = [];
    rateLimitBuckets.set(apiKey, bucket);
  }
  while (bucket.length > 0 && bucket[0] < cutoff) bucket.shift();
  if (bucket.length >= max) {
    const oldest = bucket[0];
    return { allowed: false, retryAfterMs: oldest + RATE_LIMIT_WINDOW_MS - now };
  }
  bucket.push(now);
  return { allowed: true, retryAfterMs: 0 };
}

// Periodically purge stale rate-limit buckets
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS * 2;
  for (const [key, bucket] of rateLimitBuckets) {
    if (bucket.length === 0 || bucket[bucket.length - 1] < cutoff) {
      rateLimitBuckets.delete(key);
    }
  }
}, RATE_LIMIT_WINDOW_MS * 5);

/**
 * Create the Elysia app with all routes and middleware
 */
function createApp() {
  const app = new Elysia()
    // Request logging
    .onRequest(({ request }) => {
      const startTime = Date.now();
      request.headers.set("x-request-start", startTime.toString());
    })
    .onAfterResponse(({ request, set }) => {
      const startTime = parseInt(request.headers.get("x-request-start") || "0");
      const duration = Date.now() - startTime;
      const method = request.method;
      const path = new URL(request.url).pathname;
      const statusCode = typeof set.status === "number" ? set.status : 200;

      logger.info({ method, path, statusCode, duration }, "HTTP Request");
    })

    // Error handler
    .onError(({ error, code, set }) => {
      logger.error({ err: error, code }, "Request error");

      if (code === "VALIDATION") {
        set.status = 400;
        return {
          success: false,
          error: "Validation Error",
          message: (error as Error).message || "Validation failed",
        };
      }

      if (code === "NOT_FOUND") {
        set.status = 404;
        return {
          success: false,
          error: "Not Found",
          message: "Route not found",
        };
      }

      set.status = 500;
      return {
        success: false,
        error: "Internal Server Error",
        message: (error as Error).message || "Unknown error",
      };
    })

    // CORS
    .use(
      cors({
        origin: "*",
        credentials: true,
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "X-Kairo-Api-Key", "Authorization"],
      })
    )

    // API key authentication + rate limiting (registry-based)
    .derive(({ request }) => {
      const provided = request.headers.get("x-kairo-api-key") ?? "";
      const record = provided ? getKeyRecord(provided) : null;
      return { apiKeyRecord: record as ApiKeyRecord | null, apiKeyRaw: provided };
    })
    .onBeforeHandle(({ request, set, apiKeyRecord, apiKeyRaw }) => {
      if (!isAuthEnabled()) return;

      const path = new URL(request.url).pathname;
      if (path === "/health" || request.method === "OPTIONS") return;
      if (path === "/api/sui-rpc") return;
      if (path.startsWith("/api/vault/status/") || path.startsWith("/api/vault/info")) return;
      if (path.startsWith("/api/audit/")) return;

      if (!apiKeyRecord) {
        set.status = 401;
        return {
          success: false,
          error: "Unauthorized",
          message: "Missing or invalid X-Kairo-Api-Key header",
        };
      }

      const rl = rateLimitCheck(apiKeyRaw, apiKeyRecord.tier);
      if (!rl.allowed) {
        set.status = 429;
        set.headers["retry-after"] = String(Math.ceil(rl.retryAfterMs / 1000));
        return {
          success: false,
          error: "Rate limit exceeded",
          message: `Too many requests. Retry after ${Math.ceil(rl.retryAfterMs / 1000)}s`,
        };
      }
    })

    // Health check
    .get("/health", () => ({
      status: "healthy",
      timestamp: new Date().toISOString(),
      adminAddress: dkgExecutor.getAdminAddress(),
      suiNetwork: config.sui.network,
      kairoPolicyMintPackageId: config.kairo.policyMintPackageId || undefined,
      kairoPolicyRegistryId: (config.kairo as any).policyRegistryId || undefined,
      kairoCustodyPackageId: config.kairo.custodyPackageId || undefined,
    }))

    // Mount all route modules
    .use(dkgRoutes)
    .use(presignRoutes)
    .use(signRoutes)
    .use(policyRoutes)
    .use(vaultRoutes)
    .use(evmRoutes)
    .use(bitcoinRoutes)
    .use(solanaRoutes)
    .use(utilityRoutes);

  return app;
}

// Graceful shutdown
let keepaliveInterval: NodeJS.Timeout | null = null;
let selfPingInterval: NodeJS.Timeout | null = null;

async function gracefulShutdown(signal: string) {
  logger.info({ signal }, "Starting graceful shutdown");
  if (keepaliveInterval) {
    clearInterval(keepaliveInterval);
    keepaliveInterval = null;
  }
  if (selfPingInterval) {
    clearInterval(selfPingInterval);
    selfPingInterval = null;
  }
  dkgExecutor.stop();
  process.exit(0);
}

// Start server
async function start() {
  // Global error handlers to prevent crashes
  process.on("uncaughtException", (error) => {
    logger.error(
      { error: error.message, stack: error.stack },
      "Uncaught exception - process continuing"
    );
  });

  process.on("unhandledRejection", (reason) => {
    logger.error({ reason }, "Unhandled promise rejection - process continuing");
  });

  // Initialize API key registry
  await initRegistry(config.auth.adminKey || undefined);

  logger.info(
    {
      adminAddress: dkgExecutor.getAdminAddress(),
      authEnabled: isAuthEnabled(),
    },
    "Starting Kairo Backend"
  );

  // Start DKG executor
  dkgExecutor.start();

  // Create and start app
  const app = createApp();

  app.listen({
    port: config.server.port,
    hostname: config.server.host,
  });

  logger.info(
    {
      url: `http://${config.server.host}:${config.server.port}`,
      adminAddress: dkgExecutor.getAdminAddress(),
    },
    "Server is running"
  );

  // Keepalive interval - logs heartbeat every 5 minutes
  keepaliveInterval = setInterval(() => {
    const memUsage = process.memoryUsage();
    logger.info(
      {
        uptime: Math.floor(process.uptime()),
        heapUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024),
        rssMB: Math.round(memUsage.rss / 1024 / 1024),
      },
      "Service heartbeat"
    );
  }, 5 * 60 * 1000);

  // Self-ping interval - keeps the HTTP server active
  selfPingInterval = setInterval(async () => {
    try {
      const response = await fetch(
        `http://127.0.0.1:${config.server.port}/health`
      );
      if (!response.ok) {
        logger.warn(
          { status: response.status },
          "Self-ping health check returned non-OK status"
        );
      }
    } catch (error) {
      logger.error({ error }, "Self-ping health check failed");
    }
  }, 60 * 1000);

  // Shutdown handlers
  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdown("SIGINT"));
}

start();
