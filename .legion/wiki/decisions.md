# Decisions

## auth-mini gateway

- Keep auth-mini external and unmodified; gateway adapts auth-mini login/token/session behavior into either nginx front-auth decisions or one fixed authenticated upstream proxy.
- `UPSTREAM_URL` is optional. Unset/empty keeps the nginx `auth_request` adapter and unmatched-route `404`; a valid fixed HTTP(S) URL enables authenticated HTTP/SSE/WebSocket proxy fallback.
- `UPSTREAM_PROTOCOL` missing/empty means `auto`. HTTPS `auto` is ALPN-authoritative: selected `h2` is final, while `http/1.1` or no ALPN selects H1. Cleartext proxy mode requires explicit `http1` or `http2` because no safe in-band protocol discovery exists.
- One gateway instance serves one public origin and at most one startup-configured upstream. Configured `UpstreamBase` alone controls upstream scheme, authority, dial target, TLS identity, and pool membership; request Host, H2 authority, headers, cookies, path, or query cannot select another destination.
- Gateway-owned login, callback, auth-check, logout, and health routes always remain local before proxy fallback.
- `/auth/check` and proxy mode share one session/refresh/policy/touch decision; only their HTTP response mapping differs.
- Every HTTP/2 stream delivered to gateway service independently runs route validation, authentication, allowlist authorization, header sanitation, and capacity admission; no connection-level identity or authorization result is reused.
- Before proxying over H1 or H2, remove browser cookies/authorization, caller identity, inbound forwarding, and hop-by-hop fields; preserve validated public authority only as application metadata and inject only verified user ID/email.
- Bound proxy resources with independent startup budgets: downstream connections D=256, active upstream application exchanges/streams U=128, and blocking resolvers R=8 by default. Proxy mode requires at least 16 downstream slots beyond U.
- Hold D through the accepted HTTP/SSE/WebSocket lifetime. Hold U and stream permits through upload disposal plus response/SSE/tunnel completion; retain pooled/private physical-owner accounting through driver and transport close. Hold R and U until a resolver handle is observed complete.
- Configure Tokio blocking capacity as 64 auth workers plus R resolver workers plus 16 runtime margin; resolver saturation must not queue hidden blocking work or starve authentication.
- Validate the effective soft `RLIMIT_NOFILE` against exact adapter/proxy budgets at startup and refuse impossible configurations rather than silently shrinking limits.
- Recoverable listener errors retry with bounded backoff and globally suppressed logs. Fatal listener errors use non-waiting runtime shutdown, one sanitized event, and nonzero exit so unabortable resolver work cannot block systemd restart.
- Reject every underscore-containing request header on non-owned proxy fallback before authentication or upstream access. Gateway-owned routes and adapter fallback keep compatibility behavior.
- `TRUSTED_PROXY_CIDRS` defaults empty. Only a trusted immediate peer may supply exactly one bare client IP; forwarding metadata remains informational and cannot influence authentication, return targets, destination, TLS, or pooling.
- Panic-time logging is a static payload-free direct write; logs must never include panic payloads, locations, forwarding values, identities, cookies, tokens, or internal paths.
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
- Proxy rollout requires native Acorn/Axiom nginx, FRP, firewall, direct-peer, systemd-limit, and thread/memory evidence. Passing repository tests makes the change merge-ready, not production-rollout-ready.
- New gateway sessions use a 7-day inactivity deadline under a non-sliding 30-day absolute deadline; only successful `204` authorization checks may advance inactivity, coalesced to once per hour by default.
- Session schema v2 migration must never extend a legacy session deadline, and old binaries must remain fail-closed for identity-pending sessions.
- Temporary or indeterminate refresh failures return authentication-unavailable without revoking or clearing the local session. Only exact refresh-endpoint `session_invalidated` or unrecovered `session_superseded` responses may conditionally revoke it.
- Auth-mini HTTP clients must not follow redirects and must accept only contract-defined exact `200 OK` responses as success.
- Positive gateway cookies use absolute `Expires` deadlines; nginx must explicitly propagate auth-subrequest renewal cookies and map authentication-service failures to a non-redirecting `503`.
- Current auth-mini redirect login does not support silent SSO. Gateway documentation and behavior must not claim no-interaction SSO until auth-mini provides and verifies that capability.
