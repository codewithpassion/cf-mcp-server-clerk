import { z } from "zod";
import type { GatewayConfig, ServerConfig } from "./types.js";

const serverConfigSchema = z.object({
	command: z.string(),
	args: z.array(z.string()),
	env: z.record(z.string()).optional(),
});

const serversFileSchema = z.object({
	servers: z.record(serverConfigSchema),
});

const envSchema = z.object({
	CLERK_CLIENT_ID: z.string().min(1, "CLERK_CLIENT_ID is required"),
	CLERK_CLIENT_SECRET: z.string().min(1, "CLERK_CLIENT_SECRET is required"),
	CLERK_SECRET_KEY: z.string().min(1, "CLERK_SECRET_KEY is required"),
	CLERK_FRONTEND_API: z.string().url("CLERK_FRONTEND_API must be a valid URL"),
	COOKIE_ENCRYPTION_KEY: z.string().min(1, "COOKIE_ENCRYPTION_KEY is required"),
	PORT: z.coerce.number().int().positive().default(8788),
});

function formatZodErrors(error: z.ZodError): string {
	return error.issues
		.map((i) => `  - ${i.path.join(".")}: ${i.message}`)
		.join("\n");
}

/**
 * Loads and validates gateway configuration from mcp-servers.json and environment variables.
 * Bun loads .env automatically; .dev.vars is also supported for backwards compatibility.
 */
export async function loadConfig(): Promise<GatewayConfig> {
	await loadDevVars();

	const servers = await loadServersFile();

	const envResult = envSchema.safeParse(process.env);
	if (!envResult.success) {
		throw new Error(
			`Invalid environment configuration:\n${formatZodErrors(envResult.error)}`,
		);
	}

	const env = envResult.data;

	return {
		servers,
		port: env.PORT,
		clerkClientId: env.CLERK_CLIENT_ID,
		clerkClientSecret: env.CLERK_CLIENT_SECRET,
		clerkSecretKey: env.CLERK_SECRET_KEY,
		clerkFrontendApi: env.CLERK_FRONTEND_API,
		cookieEncryptionKey: env.COOKIE_ENCRYPTION_KEY,
	};
}

async function loadServersFile(): Promise<Record<string, ServerConfig>> {
	const path = `${process.cwd()}/mcp-servers.json`;
	const file = Bun.file(path);

	if (!(await file.exists())) {
		throw new Error(
			`mcp-servers.json not found at ${path}. Create it with at least one server entry.`,
		);
	}

	const raw = await file.json();
	const result = serversFileSchema.safeParse(raw);

	if (!result.success) {
		throw new Error(
			`Invalid mcp-servers.json:\n${formatZodErrors(result.error)}`,
		);
	}

	return result.data.servers as Record<string, ServerConfig>;
}

/**
 * Loads .dev.vars file if it exists, setting env vars that are not already defined.
 * This provides backwards compatibility with the Cloudflare Workers dev workflow.
 */
async function loadDevVars(): Promise<void> {
	const path = `${process.cwd()}/.dev.vars`;
	const file = Bun.file(path);

	if (!(await file.exists())) {
		return;
	}

	const content = await file.text();
	for (const line of content.split("\n")) {
		const trimmed = line.trim();
		if (trimmed === "" || trimmed.startsWith("#")) continue;

		const eqIndex = trimmed.indexOf("=");
		if (eqIndex === -1) continue;

		const key = trimmed.slice(0, eqIndex).trim();
		const value = trimmed.slice(eqIndex + 1).trim();

		// Don't override existing env vars
		if (process.env[key] === undefined) {
			process.env[key] = value;
		}
	}
}
