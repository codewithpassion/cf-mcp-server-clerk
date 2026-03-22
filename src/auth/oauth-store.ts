// oauth-store.ts
// In-memory stores replacing Cloudflare KV

import type { AuthCode, AuthRequest, OAuthClient } from "./types";

/** Registered OAuth clients */
const clients = new Map<string, OAuthClient>();

/** Pending authorization codes (TTL: 600s) */
const authCodes = new Map<string, AuthCode>();

/** OAuth state tokens mapping state -> AuthRequest (TTL: 600s) */
const oauthStates = new Map<
	string,
	{ oauthReqInfo: AuthRequest; expiresAt: number }
>();

/** Cleanup interval: every 60s, evict expired entries */
const CLEANUP_INTERVAL_MS = 60_000;

function evictExpired(): void {
	const now = Date.now();
	for (const [key, entry] of authCodes) {
		if (entry.expiresAt <= now) {
			authCodes.delete(key);
		}
	}
	for (const [key, entry] of oauthStates) {
		if (entry.expiresAt <= now) {
			oauthStates.delete(key);
		}
	}
}

setInterval(evictExpired, CLEANUP_INTERVAL_MS);

export function storeClient(client: OAuthClient): void {
	clients.set(client.clientId, client);
}

export function getClient(clientId: string): OAuthClient | undefined {
	return clients.get(clientId);
}

export function storeAuthCode(authCode: AuthCode): void {
	authCodes.set(authCode.code, authCode);
}

export function getAndDeleteAuthCode(code: string): AuthCode | undefined {
	const entry = authCodes.get(code);
	if (!entry) return undefined;
	authCodes.delete(code);
	if (entry.expiresAt <= Date.now()) return undefined;
	return entry;
}

export function storeOAuthState(
	stateToken: string,
	oauthReqInfo: AuthRequest,
	ttlSeconds = 600,
): void {
	oauthStates.set(stateToken, {
		oauthReqInfo,
		expiresAt: Date.now() + ttlSeconds * 1000,
	});
}

export function getAndDeleteOAuthState(
	stateToken: string,
): AuthRequest | undefined {
	const entry = oauthStates.get(stateToken);
	if (!entry) return undefined;
	oauthStates.delete(stateToken);
	if (entry.expiresAt <= Date.now()) return undefined;
	return entry.oauthReqInfo;
}
