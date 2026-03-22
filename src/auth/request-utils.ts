// request-utils.ts
// Shared request inspection helpers

export function isLocalhost(request: Request): boolean {
	const url = new URL(request.url);
	return url.hostname === "localhost" || url.hostname.startsWith("127.");
}

export function cookiePrefix(request: Request): string {
	return isLocalhost(request) ? "" : "__Host-";
}

export function cookieSecureFlag(request: Request): string {
	return isLocalhost(request) ? "" : " Secure;";
}
