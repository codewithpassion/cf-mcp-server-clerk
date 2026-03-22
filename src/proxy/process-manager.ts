import type { ServerConfig } from "../types";

export interface ManagedProcess {
	subprocess: ReturnType<typeof Bun.spawn>;
	stdin: WritableStream;
	stdout: ReadableStream;
	serverName: string;
	claudeSessionUuid: string;
	spawnedAt: number;
}

export class ProcessManager {
	private processes = new Map<string, ManagedProcess>();

	spawn(
		sessionId: string,
		serverName: string,
		config: ServerConfig,
		claudeSessionUuid: string,
	): ManagedProcess {
		const args = [...config.args];
		if (
			config.command === "claude" &&
			args[0] === "mcp" &&
			args[1] === "serve"
		) {
			args.push("--session-id", claudeSessionUuid);
		}

		const subprocess = Bun.spawn([config.command, ...args], {
			stdin: "pipe",
			stdout: "pipe",
			stderr: "inherit",
			env: { ...process.env, ...config.env },
		});

		const managed: ManagedProcess = {
			subprocess,
			stdin: subprocess.stdin as unknown as WritableStream,
			stdout: subprocess.stdout as unknown as ReadableStream,
			serverName,
			claudeSessionUuid,
			spawnedAt: Date.now(),
		};

		this.processes.set(sessionId, managed);
		return managed;
	}

	get(sessionId: string): ManagedProcess | undefined {
		return this.processes.get(sessionId);
	}

	isAlive(sessionId: string): boolean {
		const mp = this.processes.get(sessionId);
		if (!mp) return false;
		return mp.subprocess.exitCode === null;
	}

	kill(sessionId: string): void {
		const mp = this.processes.get(sessionId);
		if (mp) {
			mp.subprocess.kill();
			this.processes.delete(sessionId);
		}
	}

	killAll(): void {
		for (const [id] of this.processes) {
			this.kill(id);
		}
	}
}
