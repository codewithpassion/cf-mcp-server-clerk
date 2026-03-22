// oauth-server.ts
// Hono router with OAuth 2.1 server endpoints

import { Hono } from "hono";
import { SignJWT } from "jose";
import { OAuthError } from "./csrf";
import { getAndDeleteAuthCode, getClient, storeClient } from "./oauth-store";
import type { OAuthClient } from "./types";

type Env = {
	Variables: {
		cookieEncryptionKey: string;
	};
};

const app = new Hono<Env>();

/** POST /register — RFC 7591 Dynamic Client Registration */
app.post("/register", async (c) => {
	const body = await c.req.json<{
		client_name?: string;
		redirect_uris: string[];
		client_uri?: string;
		policy_uri?: string;
		tos_uri?: string;
		contacts?: string[];
	}>();

	if (
		!body.redirect_uris ||
		!Array.isArray(body.redirect_uris) ||
		body.redirect_uris.length === 0
	) {
		return new OAuthError(
			"invalid_client_metadata",
			"redirect_uris is required",
			400,
		).toResponse();
	}

	const clientId = crypto.randomUUID();
	const secretBytes = new Uint8Array(32);
	crypto.getRandomValues(secretBytes);
	const clientSecret = Array.from(secretBytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");

	const client: OAuthClient = {
		clientId,
		clientSecret,
		clientName: body.client_name,
		redirectUris: body.redirect_uris,
		clientUri: body.client_uri,
		policyUri: body.policy_uri,
		tosUri: body.tos_uri,
		contacts: body.contacts,
		registeredAt: Date.now(),
	};

	storeClient(client);

	return c.json({
		client_id: clientId,
		client_secret: clientSecret,
		client_name: client.clientName,
		redirect_uris: client.redirectUris,
		client_uri: client.clientUri,
		policy_uri: client.policyUri,
		tos_uri: client.tosUri,
		contacts: client.contacts,
	});
});

/** POST /token — Authorization Code Grant */
app.post("/token", async (c) => {
	const formData = await c.req.parseBody();

	const grantType = formData.grant_type as string | undefined;
	if (grantType !== "authorization_code") {
		return new OAuthError(
			"unsupported_grant_type",
			"Only authorization_code grant type is supported",
			400,
		).toResponse();
	}

	const code = formData.code as string | undefined;
	const redirectUri = formData.redirect_uri as string | undefined;
	const clientId = formData.client_id as string | undefined;
	const clientSecret = formData.client_secret as string | undefined;
	const codeVerifier = formData.code_verifier as string | undefined;

	if (!code || !clientId || !clientSecret) {
		return new OAuthError(
			"invalid_request",
			"Missing required parameters: code, client_id, client_secret",
			400,
		).toResponse();
	}

	// Validate client credentials
	const client = getClient(clientId);
	if (!client || client.clientSecret !== clientSecret) {
		return new OAuthError(
			"invalid_client",
			"Invalid client credentials",
			401,
		).toResponse();
	}

	// Get and delete auth code (one-time use)
	const authCode = getAndDeleteAuthCode(code);
	if (!authCode) {
		return new OAuthError(
			"invalid_grant",
			"Invalid or expired authorization code",
			400,
		).toResponse();
	}

	// Validate client_id matches the one in the auth code
	if (authCode.clientId !== clientId) {
		return new OAuthError(
			"invalid_grant",
			"Authorization code was issued to a different client",
			400,
		).toResponse();
	}

	// Validate redirect_uri matches
	if (redirectUri && authCode.redirectUri !== redirectUri) {
		return new OAuthError(
			"invalid_grant",
			"redirect_uri does not match",
			400,
		).toResponse();
	}

	// PKCE S256 validation
	if (authCode.codeChallenge) {
		if (!codeVerifier) {
			return new OAuthError(
				"invalid_grant",
				"code_verifier is required for PKCE",
				400,
			).toResponse();
		}

		const encoder = new TextEncoder();
		const digest = await crypto.subtle.digest(
			"SHA-256",
			encoder.encode(codeVerifier),
		);
		const computed = btoa(String.fromCharCode(...new Uint8Array(digest)))
			.replace(/\+/g, "-")
			.replace(/\//g, "_")
			.replace(/=+$/, "");

		if (computed !== authCode.codeChallenge) {
			return new OAuthError(
				"invalid_grant",
				"PKCE code_verifier does not match code_challenge",
				400,
			).toResponse();
		}
	}

	// Sign JWT with user props
	const cookieEncryptionKey = c.get("cookieEncryptionKey");
	const secret = new TextEncoder().encode(cookieEncryptionKey);

	const jwt = await new SignJWT(authCode.props)
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.setExpirationTime("24h")
		.sign(secret);

	return c.json({
		access_token: jwt,
		token_type: "Bearer",
		expires_in: 86400,
	});
});

/** GET /.well-known/oauth-authorization-server */
app.get("/.well-known/oauth-authorization-server", (c) => {
	const url = new URL(c.req.raw.url);

	if (url.hostname !== "localhost" && !url.hostname.startsWith("127.")) {
		url.protocol = "https:";
	}

	const base = `${url.protocol}//${url.host}`;

	return c.json({
		issuer: base,
		authorization_endpoint: `${base}/authorize`,
		token_endpoint: `${base}/token`,
		registration_endpoint: `${base}/register`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		code_challenge_methods_supported: ["S256"],
		scopes_supported: ["mcp:*"],
	});
});

/** GET /.well-known/oauth-protected-resource — RFC 9728 */
app.get("/.well-known/oauth-protected-resource", (c) => {
	const url = new URL(c.req.raw.url);

	if (url.hostname !== "localhost" && !url.hostname.startsWith("127.")) {
		url.protocol = "https:";
	}

	url.pathname = "/";
	url.search = "";
	url.hash = "";
	const resourceUrl = url.href;
	const authServerUrl = resourceUrl.slice(0, -1);

	return c.json({
		resource: resourceUrl,
		authorization_servers: [authServerUrl],
		bearer_methods_supported: ["header"],
		scopes_supported: ["mcp:*"],
	});
});

export { app as oauthServer };
