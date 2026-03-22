export type { Props } from "./types.js";

/**
 * Constructs an authorization URL for the upstream Clerk OAuth service.
 */
export function getUpstreamAuthorizeUrl({
	upstream_url,
	client_id,
	scope,
	redirect_uri,
	state,
}: {
	upstream_url: string;
	client_id: string;
	scope: string;
	redirect_uri: string;
	state?: string;
}): string {
	const upstream = new URL(upstream_url);
	upstream.searchParams.set("client_id", client_id);
	upstream.searchParams.set("redirect_uri", redirect_uri);
	upstream.searchParams.set("scope", scope);
	if (state) upstream.searchParams.set("state", state);
	upstream.searchParams.set("response_type", "code");
	return upstream.href;
}

/**
 * Sanitizes text content for safe display in HTML by escaping special characters.
 */
export function sanitizeText(text: string): string {
	return text
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

/**
 * Validates a URL for security using an allowlist approach.
 * Only allows https: and http: schemes. Returns empty string on failure.
 */
export function sanitizeUrl(url: string): string {
	const normalized = url.trim();
	if (normalized.length === 0) return "";

	// Reject control characters (RFC 3986)
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

/**
 * Builds the OAuth callback URL from the current request,
 * fixing the protocol to HTTPS when running behind cloudflared.
 */
export function getCallbackUrl(request: Request): string {
	const url = new URL(request.url);
	if (isHTTPS(request)) {
		url.protocol = "https:";
	}
	url.pathname = "/callback";
	url.search = "";
	return url.href;
}

/**
 * Detects whether the original request was made over HTTPS,
 * checking the X-Forwarded-Proto header (set by cloudflared/reverse proxies).
 */
export function isHTTPS(request: Request): boolean {
	const proto = request.headers.get("x-forwarded-proto");
	if (proto === "https") return true;

	const url = new URL(request.url);
	return url.protocol === "https:";
}

/**
 * Returns the cookie name prefix based on the environment.
 * Uses "__Host-" in production (requires Secure flag) or "" in development.
 */
export function cookiePrefix(): string {
	return process.env.NODE_ENV === "production" ? "__Host-" : "";
}
