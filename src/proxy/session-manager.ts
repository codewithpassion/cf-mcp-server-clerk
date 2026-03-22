import type { ServerConfig } from "../types";
import { ProcessManager } from "./process-manager";
import { StdioBridge } from "./stdio-bridge";

interface Session {
	sessionId: string;
	serverName: string;
	claudeSessionUuid: string;
	bridge: StdioBridge;
	lastActivity: number;
}

export class SessionManager {
	private sessions = new Map<string, Session>();
	private processManager: ProcessManager;
	private cleanupInterval: Timer;

	constructor(private serverConfigs: Record<string, ServerConfig>) {
		this.processManager = new ProcessManager();
		this.cleanupInterval = setInterval(
			() => this.cleanupIdleSessions(),
			5 * 60 * 1000,
		);
	}

	createSession(serverName: string): {
		sessionId: string;
		bridge: StdioBridge;
	} {
		const config = this.serverConfigs[serverName];
		if (!config) throw new Error(`Unknown server: ${serverName}`);

		const sessionId = crypto.randomUUID();
		const claudeSessionUuid = crypto.randomUUID();

		const managed = this.processManager.spawn(
			sessionId,
			serverName,
			config,
			claudeSessionUuid,
		);
		const writer = managed.stdin.getWriter();
		const bridge = new StdioBridge(writer, managed.stdout);

		this.sessions.set(sessionId, {
			sessionId,
			serverName,
			claudeSessionUuid,
			bridge,
			lastActivity: Date.now(),
		});

		return { sessionId, bridge };
	}

	getSession(sessionId: string): Session | undefined {
		const session = this.sessions.get(sessionId);
		if (!session) return undefined;

		if (!this.processManager.isAlive(sessionId)) {
			console.log(
				`[SessionManager] Process died for session ${sessionId}, respawning...`,
			);
			const config = this.serverConfigs[session.serverName];
			if (!config) {
				this.sessions.delete(sessionId);
				return undefined;
			}

			this.processManager.kill(sessionId);
			const managed = this.processManager.spawn(
				sessionId,
				session.serverName,
				config,
				session.claudeSessionUuid,
			);
			const writer = managed.stdin.getWriter();
			session.bridge = new StdioBridge(writer, managed.stdout);
		}

		session.lastActivity = Date.now();
		return session;
	}

	destroySession(sessionId: string): void {
		const session = this.sessions.get(sessionId);
		if (session) {
			session.bridge.close();
			this.processManager.kill(sessionId);
			this.sessions.delete(sessionId);
		}
	}

	destroyAll(): void {
		for (const [id] of this.sessions) {
			this.destroySession(id);
		}
		clearInterval(this.cleanupInterval);
	}

	private cleanupIdleSessions(): void {
		const IDLE_TIMEOUT = 30 * 60 * 1000;
		const now = Date.now();
		for (const [id, session] of this.sessions) {
			if (now - session.lastActivity > IDLE_TIMEOUT) {
				console.log(`[SessionManager] Cleaning up idle session ${id}`);
				this.destroySession(id);
			}
		}
	}
}
