# Decisions

## auth-mini gateway

- Keep auth-mini external and unmodified; gateway adapts auth-mini login/token/session behavior into either nginx front-auth decisions or one fixed authenticated upstream proxy.
- `UPSTREAM_URL` is optional. Unset/empty keeps the nginx `auth_request` adapter and unmatched-route `404`; a valid fixed HTTP(S) URL enables authenticated HTTP/SSE/WebSocket proxy fallback.
- One gateway instance serves one public origin and at most one startup-configured upstream. Request Host, headers, cookies, path, or query cannot select another destination.
- Gateway-owned login, callback, auth-check, logout, and health routes always remain local before proxy fallback.
- `/auth/check` and proxy mode share one session/refresh/policy/touch decision; only their HTTP response mapping differs.
- Before proxying, remove browser cookies/authorization, caller identity, inbound forwarding, and hop-by-hop fields; preserve external Host only as app metadata and inject only verified user ID/email.
- Browser stores only opaque signed gateway cookies. auth-mini access/refresh tokens stay server-side in gateway sessions.
- Use a first-party callback bridge page for auth-mini fragment redirects because URL fragments are never sent to servers.
- Deny unknown users by default through exact email/user-id allowlists. Auth-mini is the sole authority for authentication methods; gateway authorization must not branch on JWT `amr`.
- Preserve authenticated-but-unauthorized gateway sessions so nginx can return `403` without allowing upstream access.
- Production runtime is Rust with SQLite WAL persistence, replacing the TypeScript PoC for production behavior.
- Supported production topology is one active gateway instance with durable local/mounted SQLite storage; multi-active shared SQLite is out of scope.
- Changes to auth-mini token/session contracts require real auth-mini token issuance/refresh/logout validation. Proxy transport also requires direct streaming, denial-isolation, SSE, WebSocket, and secret-boundary tests; physical deployment evidence remains an rollout gate when the external fixture is unavailable in development.
- Do not log access tokens, refresh tokens, signed session cookies, cookie secrets, or callback bodies in runtime or test diagnostics.
- Treat identity values crossing the nginx `auth_request` response-header boundary as untrusted and reject unsafe header bytes before forwarding.
- Production deployment docs live under `docs/`; `docs/README.md` is the docs entry point and `docs/production-deployment.md` is the operational deployment guide.
- `AUTH_MINI_ISSUER` must match auth-mini's JWT `iss` and be reachable by the gateway for `/jwks`, `/me`, refresh, and logout.
- Rollback guidance must keep a verified access-control layer in place; do not expose protected upstreams directly as a rollback shortcut.
- New gateway sessions use a 7-day inactivity deadline under a non-sliding 30-day absolute deadline; only successful `204` authorization checks may advance inactivity, coalesced to once per hour by default.
- Session schema v2 migration must never extend a legacy session deadline, and old binaries must remain fail-closed for identity-pending sessions.
- Temporary or indeterminate refresh failures return authentication-unavailable without revoking or clearing the local session. Only exact refresh-endpoint `session_invalidated` or unrecovered `session_superseded` responses may conditionally revoke it.
- Auth-mini HTTP clients must not follow redirects and must accept only contract-defined exact `200 OK` responses as success.
- Positive gateway cookies use absolute `Expires` deadlines; nginx must explicitly propagate auth-subrequest renewal cookies and map authentication-service failures to a non-redirecting `503`.
- Current auth-mini redirect login does not support silent SSO. Gateway documentation and behavior must not claim no-interaction SSO until auth-mini provides and verifies that capability.
