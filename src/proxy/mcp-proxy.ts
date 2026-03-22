import { Hono } from "hono";
import type { SessionManager } from "./session-manager";
import type { StdioBridge } from "./stdio-bridge";

async function forwardMessages(
	bridge: StdioBridge,
	messages: Array<Record<string, unknown>>,
): Promise<unknown[]> {
	const responses: unknown[] = [];
	for (const msg of messages) {
		if ("id" in msg && msg.id != null) {
			const response = await bridge.request(
				msg as { id: string | number; [key: string]: unknown },
			);
			responses.push(response);
		} else {
			await bridge.send(msg);
		}
	}
	return responses;
}

export function createMcpProxy(sessionManager: SessionManager): Hono {
	const app = new Hono();

	app.post("/:serverName/mcp", async (c) => {
		const serverName = c.req.param("serverName");
		const sessionId = c.req.header("Mcp-Session-Id");

		const body = await c.req.json();
		const messages: Array<Record<string, unknown>> = Array.isArray(body)
			? body
			: [body];
		const isBatch = Array.isArray(body);

		if (!sessionId) {
			const initMsg = messages.find((m) => m.method === "initialize");
			if (!initMsg) {
				return c.json(
					{
						error:
							"Missing Mcp-Session-Id header; first request must be initialize",
					},
					400,
				);
			}

			const { sessionId: newSessionId, bridge } =
				sessionManager.createSession(serverName);

			const responses = await forwardMessages(bridge, messages);

			if (responses.length === 0) {
				return c.body(null, 202, {
					"Mcp-Session-Id": newSessionId,
				});
			}

			const result = isBatch ? responses : responses[0];
			return c.json(result as object, 200, {
				"Mcp-Session-Id": newSessionId,
			});
		}

		const session = sessionManager.getSession(sessionId);
		if (!session) {
			return c.json({ error: "Invalid or expired session" }, 404);
		}

		const responses = await forwardMessages(session.bridge, messages);

		if (responses.length === 0) {
			return c.body(null, 202);
		}

		const result = isBatch ? responses : responses[0];
		return c.json(result as object);
	});

	app.get("/:serverName/mcp", (c) => {
		const sessionId = c.req.header("Mcp-Session-Id");
		if (!sessionId) {
			return c.json({ error: "Missing Mcp-Session-Id header" }, 400);
		}

		const session = sessionManager.getSession(sessionId);
		if (!session) {
			return c.json({ error: "Invalid or expired session" }, 404);
		}

		const encoder = new TextEncoder();
		let sseController: ReadableStreamDefaultController | undefined;
		let pingInterval: Timer | undefined;

		const stream = new ReadableStream({
			start(controller) {
				sseController = controller;
				session.bridge.addSSEController(controller);

				controller.enqueue(encoder.encode(": ping\n\n"));

				pingInterval = setInterval(() => {
					try {
						controller.enqueue(encoder.encode(": ping\n\n"));
					} catch {
						clearInterval(pingInterval);
					}
				}, 30_000);
			},
			cancel() {
				if (pingInterval) clearInterval(pingInterval);
				if (sseController) {
					session.bridge.removeSSEController(sseController);
				}
			},
		});

		return new Response(stream, {
			headers: {
				"Content-Type": "text/event-stream",
				"Cache-Control": "no-cache",
				Connection: "keep-alive",
			},
		});
	});

	app.delete("/:serverName/mcp", (c) => {
		const sessionId = c.req.header("Mcp-Session-Id");
		if (!sessionId) {
			return c.json({ error: "Missing Mcp-Session-Id header" }, 400);
		}

		sessionManager.destroySession(sessionId);
		return c.body(null, 200);
	});

	return app;
}
