/** User context from Clerk JWT, available in auth middleware */
export type Props = {
	userId: string;
	sessionId: string;
	email?: string;
	firstName?: string;
	lastName?: string;
	imageUrl?: string;
	role?: string;
	metadata?: Record<string, unknown>;
};

/** OAuth dynamic client registration (RFC 7591) */
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

/** Authorization code grant intermediate state */
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

/** OAuth authorization request info */
export interface AuthRequest {
	clientId: string;
	redirectUri: string;
	scope: string;
	state?: string;
	codeChallenge?: string;
	codeChallengeMethod?: string;
	responseType?: string;
}

/** MCP server definition from config file */
export interface ServerConfig {
	command: string;
	args: string[];
	env?: Record<string, string>;
}

/** Gateway configuration */
export interface GatewayConfig {
	servers: Record<string, ServerConfig>;
	port: number;
	clerkClientId: string;
	clerkClientSecret: string;
	clerkSecretKey: string;
	clerkFrontendApi: string;
	cookieEncryptionKey: string;
}

/** Runtime session entry mapping MCP session to subprocess */
export interface SessionEntry {
	sessionId: string;
	serverName: string;
	claudeSessionUuid: string;
	process: unknown; // Bun.Subprocess - typed as unknown for portability
	bridge: unknown; // StdioBridge instance
	lastActivity: number;
}
