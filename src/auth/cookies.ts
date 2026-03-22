// cookies.ts
// Cookie signing, client approval, and state session binding utilities

import { OAuthError } from "./csrf";
import { cookiePrefix, cookieSecureFlag } from "./request-utils";

async function importKey(secret: string): Promise<CryptoKey> {
	if (!secret) {
		throw new Error("cookieSecret is required for signing cookies");
	}
	const enc = new TextEncoder();
	return crypto.subtle.importKey(
		"raw",
		enc.encode(secret),
		{ hash: "SHA-256", name: "HMAC" },
		false,
		["sign", "verify"],
	);
}

export async function signData(data: string, secret: string): Promise<string> {
	const key = await importKey(secret);
	const enc = new TextEncoder();
	const signatureBuffer = await crypto.subtle.sign(
		"HMAC",
		key,
		enc.encode(data),
	);
	return Array.from(new Uint8Array(signatureBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function verifySignature(
	signatureHex: string,
	data: string,
	secret: string,
): Promise<boolean> {
	const key = await importKey(secret);
	const enc = new TextEncoder();
	try {
		const signatureBytes = new Uint8Array(
			signatureHex.match(/.{1,2}/g)?.map((byte) => Number.parseInt(byte, 16)) ??
				[],
		);
		return await crypto.subtle.verify(
			"HMAC",
			key,
			signatureBytes.buffer,
			enc.encode(data),
		);
	} catch {
		return false;
	}
}

async function getApprovedClientsFromCookie(
	request: Request,
	cookieSecret: string,
): Promise<string[] | null> {
	const name = `${cookiePrefix(request)}APPROVED_CLIENTS`;

	const cookieHeader = request.headers.get("Cookie");
	if (!cookieHeader) return null;

	const cookies = cookieHeader.split(";").map((c) => c.trim());
	const targetCookie = cookies.find((c) => c.startsWith(`${name}=`));
	if (!targetCookie) return null;

	const cookieValue = targetCookie.substring(name.length + 1);
	const parts = cookieValue.split(".");
	if (parts.length !== 2) return null;

	const [sigHex, base64Payload] = parts;
	const payload = atob(base64Payload);
	const isValid = await verifySignature(sigHex, payload, cookieSecret);
	if (!isValid) return null;

	try {
		const approvedClients = JSON.parse(payload);
		if (
			!Array.isArray(approvedClients) ||
			!approvedClients.every((item) => typeof item === "string")
		) {
			return null;
		}
		return approvedClients as string[];
	} catch {
		return null;
	}
}

export async function isClientApproved(
	request: Request,
	clientId: string,
	cookieSecret: string,
): Promise<boolean> {
	const approvedClients = await getApprovedClientsFromCookie(
		request,
		cookieSecret,
	);
	return approvedClients?.includes(clientId) ?? false;
}

export async function addApprovedClient(
	request: Request,
	clientId: string,
	cookieSecret: string,
): Promise<string> {
	const name = `${cookiePrefix(request)}APPROVED_CLIENTS`;
	const THIRTY_DAYS_IN_SECONDS = 2592000;

	const existingApprovedClients =
		(await getApprovedClientsFromCookie(request, cookieSecret)) || [];
	const updatedApprovedClients = Array.from(
		new Set([...existingApprovedClients, clientId]),
	);

	const payload = JSON.stringify(updatedApprovedClients);
	const signature = await signData(payload, cookieSecret);
	const cookieValue = `${signature}.${btoa(payload)}`;
	const secure = cookieSecureFlag(request);

	return `${name}=${cookieValue}; HttpOnly;${secure} Path=/; SameSite=Lax; Max-Age=${THIRTY_DAYS_IN_SECONDS}`;
}

async function sha256Hex(input: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(input);
	const hashBuffer = await crypto.subtle.digest("SHA-256", data);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function bindStateToSession(
	stateToken: string,
	request: Request,
): Promise<{ setCookie: string }> {
	const name = `${cookiePrefix(request)}CONSENTED_STATE`;
	const hashHex = await sha256Hex(stateToken);
	const secure = cookieSecureFlag(request);

	const setCookie = `${name}=${hashHex}; HttpOnly;${secure} Path=/; SameSite=Lax; Max-Age=600`;
	return { setCookie };
}

export async function validateSessionBinding(
	request: Request,
	stateToken: string,
): Promise<void> {
	const name = `${cookiePrefix(request)}CONSENTED_STATE`;

	const cookieHeader = request.headers.get("Cookie") || "";
	const cookies = cookieHeader.split(";").map((c) => c.trim());
	const consentedStateCookie = cookies.find((c) => c.startsWith(`${name}=`));
	const consentedStateHash = consentedStateCookie
		? consentedStateCookie.substring(name.length + 1)
		: null;

	if (!consentedStateHash) {
		throw new OAuthError(
			"invalid_request",
			"Missing session binding cookie - authorization flow must be restarted",
			400,
		);
	}

	const stateHash = await sha256Hex(stateToken);
	if (stateHash !== consentedStateHash) {
		throw new OAuthError(
			"invalid_request",
			"State token does not match session - possible CSRF attack detected",
			400,
		);
	}
}
