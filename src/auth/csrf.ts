// csrf.ts
// CSRF protection utilities ported from workers-oauth-utils.ts

import { isLocalhost } from "./request-utils";

/**
 * OAuth 2.1 compliant error class.
 */
export class OAuthError extends Error {
	constructor(
		public code: string,
		public description: string,
		public statusCode = 400,
	) {
		super(description);
		this.name = "OAuthError";
	}

	toResponse(): Response {
		return new Response(
			JSON.stringify({
				error: this.code,
				error_description: this.description,
			}),
			{
				status: this.statusCode,
				headers: { "Content-Type": "application/json" },
			},
		);
	}
}

function csrfCookieName(request: Request): string {
	return isLocalhost(request) ? "CSRF_TOKEN" : "__Host-CSRF_TOKEN";
}

/**
 * Generates a new CSRF token and corresponding cookie for form protection.
 */
export function generateCSRFProtection(request: Request): {
	token: string;
	setCookie: string;
} {
	const name = csrfCookieName(request);
	const token = crypto.randomUUID();
	const secure = !isLocalhost(request);
	const setCookie = `${name}=${token}; HttpOnly;${secure ? " Secure;" : ""} Path=/; SameSite=Lax; Max-Age=600`;
	return { token, setCookie };
}

/**
 * Validates that the CSRF token from the form matches the token in the cookie.
 * Throws OAuthError on mismatch.
 */
export function validateCSRFToken(formData: FormData, request: Request): void {
	const name = csrfCookieName(request);

	const tokenFromForm = formData.get("csrf_token");
	if (!tokenFromForm || typeof tokenFromForm !== "string") {
		throw new OAuthError(
			"invalid_request",
			"Missing CSRF token in form data",
			400,
		);
	}

	const cookieHeader = request.headers.get("Cookie") || "";
	const cookies = cookieHeader.split(";").map((c) => c.trim());
	const csrfCookie = cookies.find((c) => c.startsWith(`${name}=`));
	const tokenFromCookie = csrfCookie
		? csrfCookie.substring(name.length + 1)
		: null;

	if (!tokenFromCookie) {
		throw new OAuthError("invalid_request", "Missing CSRF token cookie", 400);
	}

	if (tokenFromForm !== tokenFromCookie) {
		throw new OAuthError("invalid_request", "CSRF token mismatch", 400);
	}
}
