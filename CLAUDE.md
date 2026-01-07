# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **Model Context Protocol (MCP) server** that provides remote OAuth authentication using Clerk. It's built on Cloudflare Workers and uses the `@cloudflare/workers-oauth-provider` library to implement OAuth 2.1 compliant authentication. The server can be deployed to Cloudflare Workers and exposes MCP tools via HTTP+SSE or Streamable-HTTP protocols.

### Key Responsibilities
- Acts as an OAuth 2.1 server for MCP clients
- Acts as an OAuth 2.1 client to Clerk's OAuth service
- Manages MCP tool definitions and conditional access based on authenticated user roles
- Handles authentication state, CSRF protection, and session binding for security

## Architecture

### Three-Layer Architecture

**1. OAuth Layer** (`src/clerk-handler.ts`, `src/workers-oauth-utils.ts`)
- Implements OAuth 2.1 authorization flow using `@cloudflare/workers-oauth-provider`
- Manages endpoints: `/authorize`, `/callback`, `/register`, `/token`
- Clerk acts as the upstream OAuth provider; this server acts as the OAuth server for MCP clients
- Token contains encrypted user context (userId, sessionId, email, firstName, lastName, role, metadata)

**2. MCP Server Layer** (`src/index.ts`)
- Extends `McpAgent` from the `agents` library (Durable MCP)
- Defines tools using the MCP SDK with Zod validation
- Tools receive user context via `this.props` (authenticated user info)
- Supports conditional tool availability based on user role (example: `generateImage` tool restricted to `ALLOWED_ROLES`)
- Exposes two protocol endpoints:
  - `/sse` - deprecated Server-Sent Events protocol
  - `/mcp` - current Streamable-HTTP protocol (recommended)

**3. Utility Layer** (`src/utils.ts`)
- `getUpstreamAuthorizeUrl()` - constructs OAuth authorization URLs
- `fetchUpstreamAuthToken()` - exchanges auth code for access token
- `Props` type - defines authenticated user context (userId, sessionId, email, firstName, lastName, role, metadata)

### Data Flow
1. Client connects to `/mcp` or `/sse`
2. OAuth check redirects to `/authorize`
3. User approves access → CSRF & session binding cookies created
4. Redirect to Clerk → Clerk redirects to `/callback`
5. Server exchanges code for Clerk tokens (access_token + id_token)
6. Server verifies JWT and extracts user data from claims
7. Server creates MCP token with user props
8. Client receives token and can invoke tools
9. Tools execute with user context available via `this.props`

## Security Implementation

### OAuth State Management (`src/workers-oauth-utils.ts`)
- **KV Storage**: OAuth state tokens stored in Cloudflare KV with 600s TTL
- **Session Binding**: State token hashed and bound to browser session via `__Host-CONSENTED_STATE` cookie
- **CSRF Protection**: Per-form CSRF tokens stored in `__Host-CSRF_TOKEN` cookie with 10-minute TTL, validated on form submission
- **One-time Use**: State and CSRF tokens deleted/invalidated after use (RFC 9700 compliance)
- **URL Validation**: Input URLs validated for XSS attacks using allowlist (http/https only) + HTML escaping

### Access Control
- Basic tools (`add`, `userInfo`) available to all authenticated users
- Restricted tools (e.g., `generateImage`) controlled via role-based access control
- User role from Clerk available in `this.props.role` for conditional logic
- Roles configured in `ALLOWED_ROLES` set in `src/index.ts`
- User roles set in Clerk Dashboard via `public_metadata.role` field

### Secrets Management
Wrangler secrets (do not commit):
- `CLERK_CLIENT_ID` - Clerk OAuth application client ID
- `CLERK_CLIENT_SECRET` - Clerk OAuth application client secret
- `CLERK_SECRET_KEY` - Clerk secret key for JWT verification (starts with `sk_`)
- `CLERK_FRONTEND_API` - Clerk frontend API URL (e.g., `https://your-subdomain.clerk.accounts.dev`)
- `COOKIE_ENCRYPTION_KEY` - Random string for signing cookies (generate: `openssl rand -hex 32`)

## Development

### Setup
1. Install dependencies: `npm install`
2. Create Clerk application at https://dashboard.clerk.com
3. Create OAuth application in Clerk Dashboard (redirect URI: `http://localhost:8788/callback`)
4. Copy `.env.example` to `.env` and fill in Clerk credentials
5. Generate `COOKIE_ENCRYPTION_KEY`: `openssl rand -hex 32`
6. Set user roles in Clerk Dashboard: Users → [select user] → Metadata → Public → `{"role": "admin"}`

### Common Commands
- `npm run dev` (or `npm start`) - Run locally on `http://localhost:8788`
- `npm run type-check` - Check TypeScript types without emitting
- `npm run cf-typegen` - Generate Cloudflare Worker types
- `npm run deploy` - Deploy to Cloudflare Workers

### Testing
Test locally with MCP Inspector:
```bash
npm run dev
# In another terminal:
npx @modelcontextprotocol/inspector@latest
# Enter: http://localhost:8788/sse (deprecated) or http://localhost:8788/mcp
```

Then use the Inspector to authenticate via Clerk and test tools.

### Adding New Tools
1. In `src/index.ts`, add new tools in the `init()` method using `this.server.tool()`
2. Use `this.props` to access authenticated user info: `userId`, `sessionId`, `email`, `firstName`, `lastName`, `role`, `metadata`
3. Use Zod for input validation
4. Optionally gate access by role: `if (this.props!.role && ALLOWED_ROLES.has(this.props!.role)) { ... }`

### Production Deployment
1. Create Clerk OAuth application with production redirect URI: `https://mcp-clerk-oauth.<your-subdomain>.workers.dev/callback`
2. Set secrets: `wrangler secret put CLERK_CLIENT_ID`, `CLERK_CLIENT_SECRET`, `CLERK_SECRET_KEY`, `CLERK_FRONTEND_API`, `COOKIE_ENCRYPTION_KEY`
3. Create KV namespace: `wrangler kv namespace create "OAUTH_KV"` and update `wrangler.jsonc` with ID
4. Deploy: `npm run deploy`
5. Review [Securing MCP Servers](https://github.com/cloudflare/agents/blob/main/docs/securing-mcp-servers.md)

## Key Dependencies

- **@clerk/backend** - Clerk backend SDK for JWT verification
- **@cloudflare/workers-oauth-provider** - OAuth 2.1 server implementation
- **@modelcontextprotocol/sdk** - MCP SDK for defining tools
- **agents** - Durable MCP (McpAgent class for Durable Object integration)
- **hono** - Lightweight web framework for routing
- **zod** - Schema validation for tool inputs

## Configuration

### wrangler.jsonc
- `compatibility_date: "2025-03-10"` - Cloudflare runtime version
- `compatibility_flags: ["nodejs_compat"]` - Enable Node.js compatibility
- `MCP_OBJECT` Durable Object binding - stores MCP server state
- `OAUTH_KV` KV namespace - stores OAuth state tokens
- `AI` binding - access to Cloudflare AI models (for generateImage tool)
- Dev port: 8788

### Environment Types
See `worker-configuration.d.ts` for Worker environment type definitions (auto-generated by `npm run cf-typegen`).

## Important Security Notes

This is a **demo template**. Before production:
- Implement rate limiting (auth attempts, tool invocations)
- Add logging and monitoring
- Review Cloudflare's [Securing MCP Servers guide](https://github.com/cloudflare/agents/blob/main/docs/securing-mcp-servers.md)
- Validate all user inputs in tools
- Consider token rotation strategies for long-lived MCP sessions
- Test OAuth attack vectors (CSRF, code reuse, state mismatches)

## Common Gotchas

1. **SSE vs Streamable-HTTP**: SSE (`/sse`) is deprecated; use `/mcp` for new clients
2. **KV Namespace ID**: Must be set in `wrangler.jsonc` before deployment (placeholder: `<Add-KV-ID>`)
3. **User Roles**: Set via Clerk Dashboard → Users → Metadata → Public → `{"role": "admin"}`
4. **ALLOWED_ROLES**: Default roles are `"admin"` and `"premium"` - customize in `src/index.ts`
5. **Clerk Frontend API**: Must include full URL with protocol (e.g., `https://your-subdomain.clerk.accounts.dev`)
6. **Durable Object Migrations**: New class names require migration tags in `wrangler.jsonc`
