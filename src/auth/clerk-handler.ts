// clerk-handler.ts
// Clerk OAuth flow ported from Cloudflare Workers to Hono + in-memory stores

import { verifyToken } from "@clerk/backend";
import { Hono } from "hono";
import {
	addApprovedClient,
	bindStateToSession,
	isClientApproved,
	validateSessionBinding,
} from "./cookies";
import { generateCSRFProtection, OAuthError, validateCSRFToken } from "./csrf";
import {
	getAndDeleteOAuthState,
	getClient,
	storeAuthCode,
	storeOAuthState,
} from "./oauth-store";
import { cookiePrefix, cookieSecureFlag } from "./request-utils";
import type { AuthCode, AuthRequest, OAuthClient, Props } from "./types";

interface ClerkHandlerConfig {
	clerkClientId: string;
	clerkClientSecret: string;
	clerkSecretKey: string;
	clerkFrontendApi: string;
	cookieEncryptionKey: string;
}

// --- HTML rendering helpers ---

function sanitizeText(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

function sanitizeUrl(url: string): string {
	const normalized = url.trim();
	if (normalized.length === 0) return "";

	for (let i = 0; i < normalized.length; i++) {
		const code = normalized.charCodeAt(i);
		if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
			return "";
		}
	}

	let parsedUrl: URL;
	try {
		parsedUrl = new URL(normalized);
	} catch {
		return "";
	}

	const scheme = parsedUrl.protocol.slice(0, -1).toLowerCase();
	if (scheme !== "https" && scheme !== "http") return "";

	return normalized;
}

function renderApprovalDialog(
	request: Request,
	options: {
		client: OAuthClient | undefined;
		csrfToken: string;
		server: { name: string; logo?: string; description?: string };
		setCookie: string;
		state: Record<string, unknown>;
	},
): Response {
	const { client, server, state, csrfToken, setCookie } = options;

	const encodedState = btoa(JSON.stringify(state));

	const serverName = sanitizeText(server.name);
	const clientName = client?.clientName
		? sanitizeText(client.clientName)
		: "Unknown MCP Client";
	const serverDescription = server.description
		? sanitizeText(server.description)
		: "";

	const logoUrl = server.logo ? sanitizeText(sanitizeUrl(server.logo)) : "";
	const clientUri = client?.clientUri
		? sanitizeText(sanitizeUrl(client.clientUri))
		: "";
	const policyUri = client?.policyUri
		? sanitizeText(sanitizeUrl(client.policyUri))
		: "";
	const tosUri = client?.tosUri ? sanitizeText(sanitizeUrl(client.tosUri)) : "";

	const contacts =
		client?.contacts && client.contacts.length > 0
			? sanitizeText(client.contacts.join(", "))
			: "";

	const redirectUris =
		client?.redirectUris && client.redirectUris.length > 0
			? client.redirectUris
					.map((uri) => {
						const validated = sanitizeUrl(uri);
						return validated ? sanitizeText(validated) : "";
					})
					.filter((uri) => uri !== "")
			: [];

	const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${clientName} | Authorization Request</title>
        <style>
          :root {
            --primary-color: #0070f3;
            --error-color: #f44336;
            --border-color: #e5e7eb;
            --text-color: #333;
            --background-color: #fff;
            --card-shadow: 0 8px 36px 8px rgba(0, 0, 0, 0.1);
          }

          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         Helvetica, Arial, sans-serif, "Apple Color Emoji",
                         "Segoe UI Emoji", "Segoe UI Symbol";
            line-height: 1.6;
            color: var(--text-color);
            background-color: #f9fafb;
            margin: 0;
            padding: 0;
          }

          .container {
            max-width: 600px;
            margin: 2rem auto;
            padding: 1rem;
          }

          .precard {
            padding: 2rem;
            text-align: center;
          }

          .card {
            background-color: var(--background-color);
            border-radius: 8px;
            box-shadow: var(--card-shadow);
            padding: 2rem;
          }

          .header {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1.5rem;
          }

          .logo {
            width: 48px;
            height: 48px;
            margin-right: 1rem;
            border-radius: 8px;
            object-fit: contain;
          }

          .title {
            margin: 0;
            font-size: 1.3rem;
            font-weight: 400;
          }

          .alert {
            margin: 0;
            font-size: 1.5rem;
            font-weight: 400;
            margin: 1rem 0;
            text-align: center;
          }

          .description {
            color: #555;
          }

          .client-info {
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem 1rem 0.5rem;
            margin-bottom: 1.5rem;
          }

          .client-name {
            font-weight: 600;
            font-size: 1.2rem;
            margin: 0 0 0.5rem 0;
          }

          .client-detail {
            display: flex;
            margin-bottom: 0.5rem;
            align-items: baseline;
          }

          .detail-label {
            font-weight: 500;
            min-width: 120px;
          }

          .detail-value {
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            word-break: break-all;
          }

          .detail-value a {
            color: inherit;
            text-decoration: underline;
          }

          .detail-value.small {
            font-size: 0.8em;
          }

          .actions {
            display: flex;
            justify-content: flex-end;
            gap: 1rem;
            margin-top: 2rem;
          }

          .button {
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            font-size: 1rem;
          }

          .button-primary {
            background-color: var(--primary-color);
            color: white;
          }

          .button-secondary {
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-color);
          }

          @media (max-width: 640px) {
            .container {
              margin: 1rem auto;
              padding: 0.5rem;
            }

            .card {
              padding: 1.5rem;
            }

            .client-detail {
              flex-direction: column;
            }

            .detail-label {
              min-width: unset;
              margin-bottom: 0.25rem;
            }

            .actions {
              flex-direction: column;
            }

            .button {
              width: 100%;
            }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="precard">
            <div class="header">
              ${logoUrl ? `<img src="${logoUrl}" alt="${serverName} Logo" class="logo">` : ""}
            <h1 class="title"><strong>${serverName}</strong></h1>
            </div>

            ${serverDescription ? `<p class="description">${serverDescription}</p>` : ""}
          </div>

          <div class="card">

            <h2 class="alert"><strong>${clientName || "A new MCP Client"}</strong> is requesting access</h2>

            <div class="client-info">
              <div class="client-detail">
                <div class="detail-label">Name:</div>
                <div class="detail-value">
                  ${clientName}
                </div>
              </div>

              ${
								clientUri
									? `
                <div class="client-detail">
                  <div class="detail-label">Website:</div>
                  <div class="detail-value small">
                    <a href="${clientUri}" target="_blank" rel="noopener noreferrer">
                      ${clientUri}
                    </a>
                  </div>
                </div>
              `
									: ""
							}

              ${
								policyUri
									? `
                <div class="client-detail">
                  <div class="detail-label">Privacy Policy:</div>
                  <div class="detail-value">
                    <a href="${policyUri}" target="_blank" rel="noopener noreferrer">
                      ${policyUri}
                    </a>
                  </div>
                </div>
              `
									: ""
							}

              ${
								tosUri
									? `
                <div class="client-detail">
                  <div class="detail-label">Terms of Service:</div>
                  <div class="detail-value">
                    <a href="${tosUri}" target="_blank" rel="noopener noreferrer">
                      ${tosUri}
                    </a>
                  </div>
                </div>
              `
									: ""
							}

              ${
								redirectUris.length > 0
									? `
                <div class="client-detail">
                  <div class="detail-label">Redirect URIs:</div>
                  <div class="detail-value small">
                    ${redirectUris.map((uri) => `<div>${uri}</div>`).join("")}
                  </div>
                </div>
              `
									: ""
							}

              ${
								contacts
									? `
                <div class="client-detail">
                  <div class="detail-label">Contact:</div>
                  <div class="detail-value">${contacts}</div>
                </div>
              `
									: ""
							}
            </div>

            <p>This MCP Client is requesting to be authorized on ${serverName}. If you approve, you will be redirected to complete authentication.</p>

            <form method="post" action="${new URL(request.url).pathname}">
              <input type="hidden" name="state" value="${encodedState}">
              <input type="hidden" name="csrf_token" value="${csrfToken}">

              <div class="actions">
                <button type="button" class="button button-secondary" onclick="window.history.back()">Cancel</button>
                <button type="submit" class="button button-primary">Approve</button>
              </div>
            </form>
          </div>
        </div>
      </body>
    </html>
  `;

	return new Response(htmlContent, {
		headers: {
			"Content-Security-Policy": "frame-ancestors 'none'",
			"Content-Type": "text/html; charset=utf-8",
			"Set-Cookie": setCookie,
			"X-Frame-Options": "DENY",
		},
	});
}

// --- Main factory ---

function getCallbackUrl(request: Request): string {
	const url = new URL(request.url);
	if (url.hostname !== "localhost" && !url.hostname.startsWith("127.")) {
		url.protocol = "https:";
	}
	url.pathname = "/callback";
	url.search = "";
	url.hash = "";
	return url.href;
}

function getUpstreamAuthorizeUrl(opts: {
	upstream_url: string;
	client_id: string;
	scope: string;
	redirect_uri: string;
	state?: string;
}): string {
	const upstream = new URL(opts.upstream_url);
	upstream.searchParams.set("client_id", opts.client_id);
	upstream.searchParams.set("redirect_uri", opts.redirect_uri);
	upstream.searchParams.set("scope", opts.scope);
	if (opts.state) upstream.searchParams.set("state", opts.state);
	upstream.searchParams.set("response_type", "code");
	return upstream.href;
}

export function createClerkHandler(config: ClerkHandlerConfig): Hono {
	const app = new Hono();

	function parseAuthRequestFromQuery(
		url: URL,
	): AuthRequest & { clientId: string } {
		return {
			clientId: url.searchParams.get("client_id") || "",
			redirectUri: url.searchParams.get("redirect_uri") || "",
			scope: url.searchParams.get("scope") || "",
			state: url.searchParams.get("state") || undefined,
			codeChallenge: url.searchParams.get("code_challenge") || undefined,
			codeChallengeMethod:
				url.searchParams.get("code_challenge_method") || undefined,
			responseType: url.searchParams.get("response_type") || undefined,
		};
	}

	function redirectToClerk(
		request: Request,
		stateToken: string,
		headers: Record<string, string> = {},
	): Response {
		const redirectUri = getCallbackUrl(request);
		console.log("[redirectToClerk] Using redirect_uri:", redirectUri);

		return new Response(null, {
			headers: {
				...headers,
				location: getUpstreamAuthorizeUrl({
					client_id: config.clerkClientId,
					redirect_uri: redirectUri,
					scope: "openid profile email public_metadata",
					state: stateToken,
					upstream_url: `${config.clerkFrontendApi}/oauth/authorize`,
				}),
			},
			status: 302,
		});
	}

	function generateAuthCode(
		clientId: string,
		redirectUri: string,
		scope: string,
		props: Props,
		codeChallenge?: string,
		codeChallengeMethod?: string,
	): string {
		const code = crypto.randomUUID();
		const authCode: AuthCode = {
			code,
			clientId,
			redirectUri,
			scope,
			props,
			codeChallenge,
			codeChallengeMethod,
			expiresAt: Date.now() + 600_000,
		};
		storeAuthCode(authCode);
		return code;
	}

	// GET /authorize
	app.get("/authorize", async (c) => {
		const url = new URL(c.req.raw.url);
		const oauthReqInfo = parseAuthRequestFromQuery(url);

		if (!oauthReqInfo.clientId) {
			return c.text("Invalid request: missing client_id", 400);
		}

		const client = getClient(oauthReqInfo.clientId);

		// Check if client is already approved
		if (
			await isClientApproved(
				c.req.raw,
				oauthReqInfo.clientId,
				config.cookieEncryptionKey,
			)
		) {
			const stateToken = crypto.randomUUID();
			storeOAuthState(stateToken, oauthReqInfo);
			const { setCookie: sessionBindingCookie } = await bindStateToSession(
				stateToken,
				c.req.raw,
			);
			return redirectToClerk(c.req.raw, stateToken, {
				"Set-Cookie": sessionBindingCookie,
			});
		}

		// Generate CSRF protection for the approval form
		const { token: csrfToken, setCookie } = generateCSRFProtection(c.req.raw);

		return renderApprovalDialog(c.req.raw, {
			client,
			csrfToken,
			server: {
				description:
					"This is a demo MCP Remote Server using Clerk for authentication.",
				logo: "https://avatars.githubusercontent.com/u/49538330?s=200&v=4",
				name: "MCP Auth Gateway",
			},
			setCookie,
			state: { oauthReqInfo },
		});
	});

	// POST /authorize
	app.post("/authorize", async (c) => {
		try {
			const formData = await c.req.raw.formData();
			validateCSRFToken(formData, c.req.raw);

			const encodedState = formData.get("state");
			if (!encodedState || typeof encodedState !== "string") {
				return c.text("Missing state in form data", 400);
			}

			let state: { oauthReqInfo?: AuthRequest };
			try {
				state = JSON.parse(atob(encodedState));
			} catch {
				return c.text("Invalid state data", 400);
			}

			if (!state.oauthReqInfo || !state.oauthReqInfo.clientId) {
				return c.text("Invalid request", 400);
			}

			const approvedClientCookie = await addApprovedClient(
				c.req.raw,
				state.oauthReqInfo.clientId,
				config.cookieEncryptionKey,
			);

			const stateToken = crypto.randomUUID();
			storeOAuthState(stateToken, state.oauthReqInfo);
			const { setCookie: sessionBindingCookie } = await bindStateToSession(
				stateToken,
				c.req.raw,
			);

			const headers = new Headers();
			headers.append("Set-Cookie", approvedClientCookie);
			headers.append("Set-Cookie", sessionBindingCookie);

			return redirectToClerk(
				c.req.raw,
				stateToken,
				Object.fromEntries(headers),
			);
		} catch (error: unknown) {
			console.error("POST /authorize error:", error);
			if (error instanceof OAuthError) {
				return error.toResponse();
			}
			const message = error instanceof Error ? error.message : "Unknown error";
			return c.text(`Internal server error: ${message}`, 500);
		}
	});

	// GET /callback
	app.get("/callback", async (c) => {
		const url = new URL(c.req.raw.url);
		const stateFromQuery = url.searchParams.get("state");

		if (!stateFromQuery) {
			return new OAuthError(
				"invalid_request",
				"Missing state parameter",
				400,
			).toResponse();
		}

		// Validate session binding
		try {
			await validateSessionBinding(c.req.raw, stateFromQuery);
		} catch (error) {
			if (error instanceof OAuthError) {
				return error.toResponse();
			}
			return c.text("Internal server error", 500);
		}

		// Get and delete OAuth state (one-time use)
		const oauthReqInfo = getAndDeleteOAuthState(stateFromQuery);
		if (!oauthReqInfo) {
			return new OAuthError(
				"invalid_request",
				"Invalid or expired state",
				400,
			).toResponse();
		}

		if (!oauthReqInfo.clientId) {
			return c.text("Invalid OAuth request data", 400);
		}

		const code = c.req.query("code");
		if (!code) {
			return c.text("Missing authorization code", 400);
		}

		// Exchange the code for tokens (access_token + id_token)
		const tokenEndpoint = `${config.clerkFrontendApi}/oauth/token`;
		const basicAuth = btoa(
			`${config.clerkClientId}:${config.clerkClientSecret}`,
		);
		const redirectUri = getCallbackUrl(c.req.raw);
		console.log("[/callback] Exchanging code with redirect_uri:", redirectUri);

		const tokenResp = await fetch(tokenEndpoint, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Authorization: `Basic ${basicAuth}`,
			},
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: redirectUri,
			}).toString(),
		});

		if (!tokenResp.ok) {
			console.error("Token exchange failed:", await tokenResp.text());
			return c.text("Failed to exchange authorization code for token", 500);
		}

		const tokenData = (await tokenResp.json()) as {
			access_token: string;
			id_token: string;
			token_type: string;
		};

		// Verify the JWT and extract user data from claims
		let verifiedToken: Awaited<ReturnType<typeof verifyToken>> | undefined;
		try {
			verifiedToken = await verifyToken(tokenData.id_token, {
				secretKey: config.clerkSecretKey,
			});
		} catch (error: unknown) {
			console.error("Token verification failed:", error);
			return c.text("Failed to verify token", 500);
		}

		// Extract user data from JWT claims
		const userId = verifiedToken.sub;
		const sessionId = verifiedToken.sid as string;
		const email = verifiedToken.email as string | undefined;
		const firstName = verifiedToken.given_name as string | undefined;
		const lastName = verifiedToken.family_name as string | undefined;
		const imageUrl = verifiedToken.picture as string | undefined;

		const publicMetadata =
			(verifiedToken.public_metadata as Record<string, unknown>) || {};
		const role = publicMetadata.role as string | undefined;

		const props: Props = {
			userId,
			sessionId,
			email,
			firstName,
			lastName,
			imageUrl,
			role,
			metadata: publicMetadata,
		};

		// Generate auth code with user props and redirect client
		const authCode = generateAuthCode(
			oauthReqInfo.clientId,
			oauthReqInfo.redirectUri,
			oauthReqInfo.scope,
			props,
			oauthReqInfo.codeChallenge,
			oauthReqInfo.codeChallengeMethod,
		);

		const clientRedirectUrl = new URL(oauthReqInfo.redirectUri);
		clientRedirectUrl.searchParams.set("code", authCode);
		if (oauthReqInfo.state) {
			clientRedirectUrl.searchParams.set("state", oauthReqInfo.state);
		}

		// Clear the session binding cookie (one-time use)
		const consentedCookieName = `${cookiePrefix(c.req.raw)}CONSENTED_STATE`;
		const secure = cookieSecureFlag(c.req.raw);
		const clearSessionCookie = `${consentedCookieName}=; HttpOnly;${secure} Path=/; SameSite=Lax; Max-Age=0`;

		const headers = new Headers({
			Location: clientRedirectUrl.href,
		});
		headers.set("Set-Cookie", clearSessionCookie);

		return new Response(null, {
			status: 302,
			headers,
		});
	});

	return app;
}
