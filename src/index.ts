import { Hono } from "hono";
import { logger } from "hono/logger";
import { createClerkHandler } from "./auth/clerk-handler";
import { createAuthMiddleware } from "./auth/oauth-middleware";
import { createOAuthServer } from "./auth/oauth-server";
import { loadConfig } from "./config";
import { createMcpProxy } from "./proxy/mcp-proxy";
import { SessionManager } from "./proxy/session-manager";

const config = loadConfig();
const sessionManager = new SessionManager(config.servers);

const app = new Hono();

app.use("*", logger());

// --- Public routes (no auth required) ---

const oauthServer = createOAuthServer(config.cookieEncryptionKey);
app.route("/", oauthServer);

const clerkHandler = createClerkHandler({
	clerkClientId: config.clerkClientId,
	clerkClientSecret: config.clerkClientSecret,
	clerkSecretKey: config.clerkSecretKey,
	clerkFrontendApi: config.clerkFrontendApi,
	cookieEncryptionKey: config.cookieEncryptionKey,
});
app.route("/", clerkHandler);

// --- Protected routes (auth required) ---

const authMiddleware = createAuthMiddleware(config.cookieEncryptionKey);
app.use("/:serverName/mcp", authMiddleware);

const mcpProxy = createMcpProxy(sessionManager);
app.route("/", mcpProxy);

// --- Health check ---

app.get("/health", (c) =>
	c.json({ status: "ok", servers: Object.keys(config.servers) }),
);

// --- Graceful shutdown ---

function cleanup() {
	console.log("[Gateway] Shutting down, killing all subprocesses...");
	sessionManager.destroyAll();
	process.exit(0);
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

// --- Startup logging ---

const serverNames = Object.keys(config.servers);
console.log(`[Gateway] Starting on port ${config.port}`);
console.log(`[Gateway] Configured servers: ${serverNames.join(", ")}`);
console.log("[Gateway] MCP endpoints:");
for (const name of serverNames) {
	console.log(`  - /${name}/mcp`);
}

export default {
	port: config.port,
	fetch: app.fetch,
};
