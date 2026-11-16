# ChatDB: Cloudflare Access identity (Option A)

## Source of truth
- Host: https://cdb.mirador.cc
- Cloudflare Worker: `cdb` / Cloudflare Access self-hosted app `20c90ad1-4fc8-4368-9b86-45faf1fb8c6a`
- Issuer: `https://amida.cloudflareaccess.com`
- AUD: `f3ab938db36f57a94b3b4655c0837130675e1db6f780149903976a3e9be98bbc`
- Database: D1 `cdb`; requires `users.github_id` due to legacy schema.
- Source: `lib/access-identity.mjs` (JWT verification), `auth.ts` (D1 identity), `middleware.ts` (app gate).
- Public `workers.dev` and preview URLs disabled; Cloudflare Access limits the custom domain to the owner.

## Identity and security
1. Cloudflare Access enforces its policy at the edge and provides `Cf-Access-Jwt-Assertion`.
2. ChatDB independently verifies an RS256 JWT with the account JWKS, exact issuer and app audience, expiration, optional not-before and nonempty `sub`. Fails closed.
3. ChatDB derives `cf:<sha256(issuer + ':' + sub)>` for its internal user ID. Never link an existing GitHub account by email.
4. First successful access creates its user record in D1. Database failure returns no authenticated session.
5. No new GitHub OAuth application is necessary. Legacy NextAuth callbacks return HTTP 410.
6. `/api/signout` redirects to Cloudflare Access logout.
7. Existing application Bearer-token and MCP OAuth endpoints are unchanged. The external Access gateway still restricts access to them. **MCP/extension connectivity from external clients requires a separate Access-compatible service-token or OAuth policy and must not be assumed working.**

## Verification
- Unit: `node --test test/access-identity.test.mjs` (valid RSA signature, missing/tampered, wrong aud, wrong issuer, expiry, nbf, wrong key, deterministic user IDs).
- Cloudflare Workers Builds command executes tests **before** `npm run cf:build` and `wrangler deploy`.
- Live browser acceptance still requires the owner to authenticate via Access; an HTTP denial to unauthenticated callers proves only the edge gate.
- After owner login, check `GET /chats`, `GET /api/chats`, `GET /api/stats`, `POST /api/tokens` with owner action and verify unrelated users cannot read the data.
- The legacy upstream dependency lockfile contains older Next/OpenNext versions; the current CF build overrides pinned versions. A future lockfile migration and security audit are separate tasks.

## Rollback
- Previous known deployment: commit `6d4a5fce53871bfb8af4ee3c68a67e6041d202ae`, with the GitHub OAuth login (requiring separate OAuth secrets). Keep Access policy enabled.
- Do not weaken the Access policy, enable workers.dev, or modify existing users to roll back; rollback only the Worker version after backup and verification.
