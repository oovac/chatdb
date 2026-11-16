# Cloudflare Access rollout acceptance — 2026-11-16

TYPE: VERIFIED OBSERVATION / OPEN GATES
PROJECT: oovac/chatdb
DEPLOYED COMMIT: `9fcdbc328022eca207093033fd28b4269527503c`
CLOUDFLARE BUILD ID: `59bbcb31-5c19-4c74-ab7c-0903d3776346`
CLOUDFLARE WORKER VERSION: `6f73d057-5451-4d27-b6c4-52545923ad14`

## Verified
- Cloudflare Workers Builds completed with `status=stopped`, `build_outcome=success`.
- Build used Next.js `15.5.29`, OpenNext `1.20.16`; production compilation and TypeScript validation passed.
- Six RSA JWT test cases passed, zero failures. Tests run automatically in the Cloudflare build command before deployment.
- Worker `cdb` has D1 `cdb`, KV `cdb-kv`, Vectorize `cdb-messages`, Workers AI bindings.
- Custom domain `cdb.mirador.cc` is attached and enabled.
- Access app `20c90ad1-4fc8-4368-9b86-45faf1fb8c6a` has sole owner-email allow policy.
- Worker `workers.dev` and preview URLs are disabled.
- Anonymous external probes `/` and `/api/chats` returned `login_required`.
- D1 `users` table count at verification: **0**.

## Not yet verified
- An actual Cloudflare Access owner login reaches ChatDB `/chats` and inserts a D1 user.
- Authenticated API read, token creation and test chat ingestion/search.
- End-to-end MCP/extension connectivity through Access (requires compatible service-token or OAuth policy).
- Owner logout and return, alternative-identity denial beyond policy inspection.
- Dependency audit and persistent modern version pinning in `package-lock.json`.

## Design
- Verified Access JWT subject hashed to namespace-separated user ID.
- Trust requires RS256 signature, exact issuer and AUD, expiration, optional nbf and non-empty sub.
- No automatic cross-linking to legacy GitHub accounts based on email.
- Browser sign-in via Access, not an independent GitHub OAuth application.

## Evidence and source
- Authentication design: `docs/CLOUDFLARE_ACCESS_AUTH.md`.
- JWT tests: `test/access-identity.test.mjs`.
- Identity validation: `lib/access-identity.mjs`.
- Auth adapter: `auth.ts`; route gate: `middleware.ts`.
- Baseline before change: `6d4a5fce53871bfb8af4ee3c68a67e6041d202ae`.
