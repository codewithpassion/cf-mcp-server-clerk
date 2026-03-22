# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an **MCP authentication gateway** that provides remote OAuth authentication using Clerk. It runs as a **Bun + Hono** application locally behind `cloudflared`, acting as a multi-server MCP proxy gateway. It implements OAuth 2.1 compliant authentication and proxies requests to upstream MCP servers defined in `mcp-servers.json`.

### Key Responsibilities
- Acts as an OAuth 2.1 server for MCP clients
- Acts as an OAuth 2.1 client to Clerk's OAuth service
- Proxies authenticated MCP requests to configured upstream MCP servers
- Manages subprocess lifecycles for stdio-based MCP servers
- Handles authentication state, CSRF protection, and session binding for security

## Architecture

### Module Structure

**1. Config Layer** (`src/config.ts`)
- `loadConfig()` - Loads `mcp-servers.json` + environment variables
- Returns validated `GatewayConfig` with server definitions, Clerk credentials, and cookie encryption key
- Server configs define how to spawn upstream MCP servers (command, args, env)

**2. Auth Layer** (`src/auth/`)
- `clerk-handler.ts` - Clerk OAuth flow: `/authorize`, `/callback`
- `oauth-server.ts` - OAuth server endpoints: `/register`, `/token`, `/.well-known/*`
- `oauth-middleware.ts` - Hono middleware that validates Bearer JWT tokens
- `csrf.ts` - CSRF token generation and validation
- `cookies.ts` - Signed cookie utilities for session binding
- `oauth-store.ts` - In-memory OAuth state storage (replaces Cloudflare KV)

**3. Proxy Layer** (`src/proxy/`)
- `mcp-proxy.ts` - Routes `/:serverName/mcp` to upstream MCP servers via Streamable-HTTP
- `session-manager.ts` - Manages MCP server subprocesses and sessions

**4. Entry Point** (`src/index.ts`)
- Wires all modules into a Bun HTTP server using Hono
- Registers public routes (OAuth), protected routes (MCP proxy), and health check
- Handles graceful shutdown (kills subprocesses on SIGINT/SIGTERM)

### Data Flow
1. Client connects to `/:serverName/mcp`
2. Auth middleware validates Bearer token
3. If unauthenticated, OAuth flow redirects through Clerk
4. On successful auth, gateway creates JWT with user props
5. Authenticated requests are proxied to the matching upstream MCP server
6. Gateway spawns upstream server subprocess on first connection (stdio transport)
7. Responses are streamed back to the client via Streamable-HTTP

## Security Implementation

### OAuth State Management (`src/auth/oauth-store.ts`)
- **In-Memory Storage**: OAuth state tokens stored with configurable TTL (default 600s)
- **Session Binding**: State token hashed and bound to browser session via cookie
- **CSRF Protection**: Per-form CSRF tokens with 10-minute TTL, validated on form submission
- **One-time Use**: State and CSRF tokens invalidated after use (RFC 9700 compliance)

### Access Control
- All MCP proxy routes require valid Bearer token
- User identity from Clerk available in request context for downstream authorization
- User roles set in Clerk Dashboard via `public_metadata.role` field

### Secrets Management
Environment variables (set in `.env` or shell):
- `CLERK_CLIENT_ID` - Clerk OAuth application client ID
- `CLERK_CLIENT_SECRET` - Clerk OAuth application client secret
- `CLERK_SECRET_KEY` - Clerk secret key for JWT verification (starts with `sk_`)
- `CLERK_FRONTEND_API` - Clerk frontend API URL (e.g., `https://your-subdomain.clerk.accounts.dev`)
- `COOKIE_ENCRYPTION_KEY` - Random string for signing cookies (generate: `openssl rand -hex 32`)

## Development

### Setup
1. Install Bun: https://bun.sh
2. Install dependencies: `bun install`
3. Create Clerk application at https://dashboard.clerk.com
4. Create OAuth application in Clerk Dashboard (redirect URI: `http://localhost:8788/callback`)
5. Copy `.env.example` to `.env` and fill in Clerk credentials
6. Generate `COOKIE_ENCRYPTION_KEY`: `openssl rand -hex 32`
7. Configure upstream MCP servers in `mcp-servers.json`

### mcp-servers.json Configuration
Define upstream MCP servers that this gateway proxies:
```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["path/to/server.js"],
      "env": {
        "API_KEY": "..."
      }
    }
  }
}
```

Each server becomes available at `/:serverName/mcp` (e.g., `/my-server/mcp`).

### Common Commands
- `bun run dev` (or `bun start`) - Run locally on `http://localhost:8788`
- `bun run type-check` - Check TypeScript types without emitting
- `bun run lint` - Run Biome linter

### Testing
Test locally with MCP Inspector:
```bash
bun run dev
# In another terminal:
npx @modelcontextprotocol/inspector@latest
# Enter: http://localhost:8788/<server-name>/mcp
```

Then use the Inspector to authenticate via Clerk and test tools on your upstream MCP servers.

### Adding Upstream MCP Servers
1. Add the server definition to `mcp-servers.json` under `mcpServers`
2. Specify `command`, `args`, and optional `env` for the server process
3. The gateway will spawn the process and proxy MCP traffic to it
4. Tools are defined in the upstream MCP servers, not in this gateway

### Production Deployment
1. Install `cloudflared` and configure a tunnel to the gateway port
2. Create Clerk OAuth application with production redirect URI matching the tunnel URL
3. Set environment variables for Clerk credentials and cookie encryption key
4. Run: `bun run start`

## Key Dependencies

- **@clerk/backend** - Clerk backend SDK for JWT verification
- **@modelcontextprotocol/sdk** - MCP SDK for protocol types
- **hono** - Lightweight web framework for routing
- **zod** - Schema validation

## Configuration

### Environment Variables
- `PORT` - Server port (default: 8788)
- `CLERK_CLIENT_ID` - Clerk OAuth client ID
- `CLERK_CLIENT_SECRET` - Clerk OAuth client secret
- `CLERK_SECRET_KEY` - Clerk secret key for JWT verification
- `CLERK_FRONTEND_API` - Clerk frontend API URL
- `COOKIE_ENCRYPTION_KEY` - Secret for cookie signing

### TypeScript
- Strict mode enabled
- Biome for formatting (tabs, double quotes)
- Import types with `type` keyword

## Important Security Notes

This is a **gateway/proxy** template. Before production:
- Implement rate limiting (auth attempts, proxy requests)
- Add logging and monitoring
- Validate upstream server configurations
- Consider token rotation strategies for long-lived MCP sessions
- Test OAuth attack vectors (CSRF, code reuse, state mismatches)
- Ensure `cloudflared` tunnel is properly secured

## Common Gotchas

1. **Streamable-HTTP only**: This gateway uses the Streamable-HTTP protocol (`/mcp`), not the deprecated SSE protocol
2. **Subprocess management**: The gateway spawns MCP server subprocesses; ensure graceful shutdown kills them
3. **User Roles**: Set via Clerk Dashboard -> Users -> Metadata -> Public -> `{"role": "admin"}`
4. **Clerk Frontend API**: Must include full URL with protocol (e.g., `https://your-subdomain.clerk.accounts.dev`)
5. **mcp-servers.json**: Must exist in project root with valid server configurations
6. **Bun runtime**: This project requires Bun, not Node.js
