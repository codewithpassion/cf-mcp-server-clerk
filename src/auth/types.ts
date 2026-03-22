// types.ts
// Local type definitions for the auth module

export type Props = {
	userId: string;
	sessionId: string;
	email?: string;
	firstName?: string;
	lastName?: string;
	imageUrl?: string;
	role?: string;
	metadata?: Record<string, unknown>;
	[key: string]: unknown;
};

export interface OAuthClient {
	clientId: string;
	clientSecret: string;
	clientName?: string;
	redirectUris: string[];
	clientUri?: string;
	policyUri?: string;
	tosUri?: string;
	contacts?: string[];
	registeredAt: number;
}

export interface AuthCode {
	code: string;
	clientId: string;
	redirectUri: string;
	scope: string;
	props: Props;
	codeChallenge?: string;
	codeChallengeMethod?: string;
	expiresAt: number;
}

export interface AuthRequest {
	clientId: string;
	redirectUri: string;
	scope: string;
	state?: string;
	codeChallenge?: string;
	codeChallengeMethod?: string;
	responseType?: string;
}
