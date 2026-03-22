const encoder = new TextEncoder();

export class StdioBridge {
	private pendingRequests = new Map<
		string | number,
		{
			resolve: (response: unknown) => void;
			reject: (error: Error) => void;
		}
	>();
	private sseControllers = new Set<ReadableStreamDefaultController>();
	private buffer = "";
	private closed = false;

	constructor(
		private stdin: WritableStreamDefaultWriter,
		stdout: ReadableStream,
	) {
		this.startReading(stdout);
	}

	private async startReading(stdout: ReadableStream): Promise<void> {
		const reader = stdout.getReader();
		const decoder = new TextDecoder();

		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;

				this.buffer += decoder.decode(value, { stream: true });

				for (
					let newlineIndex = this.buffer.indexOf("\n");
					newlineIndex !== -1;
					newlineIndex = this.buffer.indexOf("\n")
				) {
					const line = this.buffer.slice(0, newlineIndex).trim();
					this.buffer = this.buffer.slice(newlineIndex + 1);

					if (line.length === 0) continue;

					try {
						const message = JSON.parse(line);
						this.dispatch(message);
					} catch {
						// Skip non-JSON lines (subprocess logging)
					}
				}
			}
		} catch {
			// stdout closed
		} finally {
			this.closed = true;
			for (const [id, { reject }] of this.pendingRequests) {
				reject(new Error("Subprocess closed"));
				this.pendingRequests.delete(id);
			}
			for (const controller of this.sseControllers) {
				try {
					controller.close();
				} catch {
					// already closed
				}
			}
			this.sseControllers.clear();
		}
	}

	private dispatch(message: Record<string, unknown>): void {
		if ("id" in message && message.id != null) {
			const pending = this.pendingRequests.get(message.id as string | number);
			if (pending) {
				pending.resolve(message);
				this.pendingRequests.delete(message.id as string | number);
				return;
			}
		}

		// Notification or unmatched response — forward to all SSE controllers
		const encoded = encoder.encode(`data: ${JSON.stringify(message)}\n\n`);
		for (const controller of this.sseControllers) {
			try {
				controller.enqueue(encoded);
			} catch {
				this.sseControllers.delete(controller);
			}
		}
	}

	async request(message: {
		id: string | number;
		[key: string]: unknown;
	}): Promise<unknown> {
		if (this.closed) throw new Error("Bridge is closed");

		return new Promise((resolve, reject) => {
			const timeout = setTimeout(() => {
				this.pendingRequests.delete(message.id);
				reject(new Error("Request timed out"));
			}, 30_000);

			this.pendingRequests.set(message.id, {
				resolve: (response) => {
					clearTimeout(timeout);
					resolve(response);
				},
				reject: (error) => {
					clearTimeout(timeout);
					reject(error);
				},
			});

			this.send(message).catch((err) => {
				clearTimeout(timeout);
				this.pendingRequests.delete(message.id);
				reject(err);
			});
		});
	}

	async send(message: Record<string, unknown>): Promise<void> {
		const data = encoder.encode(`${JSON.stringify(message)}\n`);
		await this.stdin.write(data);
	}

	addSSEController(controller: ReadableStreamDefaultController): void {
		this.sseControllers.add(controller);
	}

	removeSSEController(controller: ReadableStreamDefaultController): void {
		this.sseControllers.delete(controller);
	}

	get isClosed(): boolean {
		return this.closed;
	}

	close(): void {
		this.closed = true;
		try {
			this.stdin.close();
		} catch {
			// already closed
		}
	}
}
