// oauth-middleware.ts
// Hono middleware for Bearer token validation

import { createMiddleware } from "hono/factory";
import { jwtVerify } from "jose";
import type { Props } from "./types";

/**
 * Creates a Hono middleware that validates Bearer JWT tokens.
 * On success, sets `c.var.props` with the decoded user context.
 * On failure, returns 401 with WWW-Authenticate header per RFC 9728.
 */
export function createAuthMiddleware(cookieEncryptionKey: string) {
	return createMiddleware<{
		Variables: { props: Props };
	}>(async (c, next) => {
		const authHeader = c.req.header("Authorization");
		if (!authHeader || !authHeader.startsWith("Bearer ")) {
			return unauthorizedResponse(c.req.raw.url);
		}

		const token = authHeader.slice(7);
		const secret = new TextEncoder().encode(cookieEncryptionKey);

		try {
			const { payload } = await jwtVerify(token, secret, {
				algorithms: ["HS256"],
			});
			c.set("props", payload as unknown as Props);
			await next();
		} catch {
			return unauthorizedResponse(c.req.raw.url);
		}
	});
}

function unauthorizedResponse(requestUrl: string): Response {
	const url = new URL(requestUrl);
	if (url.hostname !== "localhost" && !url.hostname.startsWith("127.")) {
		url.protocol = "https:";
	}
	const metadataUrl = `${url.protocol}//${url.host}/.well-known/oauth-protected-resource`;

	return new Response(JSON.stringify({ error: "unauthorized" }), {
		status: 401,
		headers: {
			"Content-Type": "application/json",
			"WWW-Authenticate": `Bearer resource_metadata="${metadataUrl}"`,
		},
	});
}
