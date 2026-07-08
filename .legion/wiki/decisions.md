# Decisions

## auth-mini gateway

- Keep auth-mini external and unmodified; gateway only adapts auth-mini login/token/session behavior to nginx front-auth decisions.
- Keep nginx as the reverse proxy and WebSocket proxy; gateway does not proxy protected upstream traffic.
- Browser stores only opaque signed gateway cookies. auth-mini access/refresh tokens stay server-side in gateway sessions.
- Use a first-party callback bridge page for auth-mini fragment redirects because URL fragments are never sent to servers.
- Deny unknown users by default through email/user-id allowlists, with optional Passkey-only enforcement via JWT `amr`.
- Preserve authenticated-but-unauthorized gateway sessions so nginx can return `403` without allowing upstream access.
- Production runtime is Rust with SQLite WAL persistence, replacing the TypeScript PoC for production behavior.
- Supported production topology is one active gateway instance with durable local/mounted SQLite storage; multi-active shared SQLite is out of scope.
- Final gateway validation must include real auth-mini token issuance/refresh/logout plus nginx and protected upstream, not mock-only tests.
- Do not log access tokens, refresh tokens, signed session cookies, cookie secrets, or callback bodies in runtime or test diagnostics.
- Treat identity values crossing the nginx `auth_request` response-header boundary as untrusted and reject unsafe header bytes before forwarding.
- Production deployment docs live under `docs/`; `docs/README.md` is the docs entry point and `docs/production-deployment.md` is the operational deployment guide.
- `AUTH_MINI_ISSUER` must match auth-mini's JWT `iss` and be reachable by the gateway for `/jwks`, `/me`, refresh, and logout.
- Rollback guidance must keep a verified access-control layer in place; do not expose protected upstreams directly as a rollback shortcut.
