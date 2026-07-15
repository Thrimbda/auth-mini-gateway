# auth-mini-gateway

Rust/SQLite gateway that enforces auth-mini sessions either as an nginx
`auth_request` adapter or as a fixed-upstream authenticated reverse proxy.

## What It Does

- Redirects unauthenticated users to auth-mini login.
- Receives auth-mini fragment callbacks through a first-party bridge page.
- Stores auth-mini access/refresh tokens only in the server-side SQLite database.
- Keeps the browser session as an opaque, HttpOnly signed cookie.
- Verifies auth-mini access JWTs with `/jwks`.
- Refreshes expired or near-expired access tokens through auth-mini `/session/refresh`.
- Uses a 7-day idle timeout and a non-sliding 30-day absolute lifetime.
- Refreshes on protected requests and preserves the local session across temporary auth-mini failures.
- Durably revokes only on local logout/expiry or an exact auth-mini refresh rejection.
- Applies exact email/user-id allowlists independently of the IdP authentication method.
- Keeps the existing nginx `auth_request` adapter as the default mode.
- Optionally streams authenticated HTTP, SSE, and WebSocket traffic to one
  startup-configured upstream.

## Quick Start

```bash
cp .env.example .env
cargo run --bin auth-mini-gateway
```

Run local checks:

```bash
cargo test
cargo build
```

Direct proxy and fail-closed mode-switch drills:

```bash
scripts/e2e-proxy-mode.sh
scripts/e2e-mode-switch.sh
```

Both use ephemeral loopback fixtures and print no credentials. The real
auth-mini drill additionally requires the pinned external auth-mini checkout.

The gateway expects a real auth-mini server at `AUTH_MINI_ISSUER`. For local browser traffic, set `AUTH_MINI_PUBLIC_BASE_URL` to the auth-mini origin reachable from the browser.

## Configuration

- `HOST`: bind host, default `127.0.0.1`.
- `PORT`: bind port, default `3000`.
- `UPSTREAM_URL`: optional absolute `http`/`https` URL. Empty or unset selects
  adapter mode. A non-empty value selects proxy mode and may include a fixed
  base path, but must not contain credentials, a query, or a fragment.
- `GATEWAY_PUBLIC_BASE_URL`: public origin serving gateway routes through nginx.
- `AUTH_MINI_ISSUER`: auth-mini issuer used for JWT `iss` validation and for `/jwks`, `/me`, refresh, and logout; it must be reachable by the gateway.
- `AUTH_MINI_PUBLIC_BASE_URL`: browser-visible auth-mini origin; defaults to `AUTH_MINI_ISSUER`.
- `AUTH_MINI_LOGIN_URL`: optional full login URL; defaults to `${AUTH_MINI_PUBLIC_BASE_URL}/web/#/login`.
- `GATEWAY_DB`: SQLite database path.
- `GATEWAY_COOKIE_SECRET`: at least 32 random characters.
- `COOKIE_SECURE`: set `true` behind HTTPS.
- `COOKIE_SAME_SITE`: `lax`, `strict`, or `none`.
- `ALLOW_EMAILS`: comma-separated exact email allowlist, compared case-insensitively.
- `ALLOW_USER_IDS`: optional comma-separated auth-mini user id allowlist.
- `SESSION_TTL_SECONDS`: inactivity timeout, default `604800` (7 days).
- `SESSION_ABSOLUTE_TTL_SECONDS`: hard lifetime from callback, default `2592000` (30 days).
- `SESSION_TOUCH_INTERVAL_SECONDS`: successful-request touch merge interval, default `3600`.
- `LOGIN_STATE_TTL_SECONDS`: one-time login state lifetime, default `600`.
- `REFRESH_SKEW_SECONDS`: refresh access tokens this many seconds before expiry.
- `LOGOUT_REDIRECT`: default post-logout relative redirect.

## Operating modes

### Adapter mode (default)

Leave `UPSTREAM_URL` empty. The gateway serves only `/healthz`, `/login`,
`/auth/callback`, `/auth/callback/session`, `/auth/check`, and `/logout`.
Every other method/path returns the compatibility `404`. nginx calls
`/auth/check` and proxies the application only after a `204` response.

### Fixed-upstream proxy mode

Set one trusted startup value, for example:

```env
HOST=127.0.0.1
PORT=7780
UPSTREAM_URL=http://127.0.0.1:4096
```

The six gateway-owned paths still take precedence for every method. Other safe
paths use the same session, refresh, identity, and allowlist decision as
`/auth/check`: anonymous requests receive a login `302`, denied identities get
`403`, authentication uncertainty gets `503`, and only allowed requests reach
the fixed upstream. The request method, path/query, body, Host semantics,
chunking, backpressure, SSE, and authenticated WebSocket upgrades are
preserved without collecting proxy bodies.

`UPSTREAM_URL` is not a routing template. Host, forwarding headers, query
parameters, absolute-form authorities, cookies, and application redirects
cannot select another destination. Browser cookies, Authorization,
Proxy-Authorization, spoofed `X-Auth-Mini-*`, inbound forwarding fields, and
hop-by-hop headers are removed. The gateway injects only verified user ID/email
and forwarding metadata derived from the direct peer and configured public
origin. The direct peer is not necessarily the browser IP when FRP/nginx sits
in front.

The protected application must bind only to loopback. Expose the gateway—not
the application—through FRP. For OpenCode, map the gateway listener `7780`,
which proxies to OpenCode `127.0.0.1:4096`; never expose `4096` or the adapter
gateway port `3000`. Public TLS remains terminated by Acorn nginx.

## nginx adapter configuration

`examples/nginx.conf` is the adapter-mode example. It exposes public gateway
routes and keeps `/auth/check` internal through `/_auth`. Protected upstream
requests use nginx `auth_request`; denied requests do not reach upstream.
WebSocket upgrade headers are forwarded only after auth succeeds. In proxy
mode nginx/FRP sends application traffic to the gateway itself; the gateway
replaces node-local nginx only for application proxying, not Acorn public TLS.

## Docs

- [Docs overview](docs/README.md)
- [Production deployment](docs/production-deployment.md)
- [Silent SSO capability gate](docs/silent-sso-capability.md)

## Docker Compose

`examples/docker-compose.yml` builds the Rust gateway image and a small Rust protected upstream example. It expects a real auth-mini deployment reachable as `AUTH_MINI_ISSUER`; by default this is `http://auth-mini:7777`, suitable when an auth-mini service is attached to the same Compose network.

## Deployment Model

The supported production target is one active gateway instance backed by durable SQLite WAL storage. Multi-active gateway instances sharing one SQLite session database are out of scope.

Only successful `204` authorization checks can advance the idle deadline, and they never advance the absolute deadline. Positive cookies carry an absolute `Expires` value and no `Max-Age`; clear cookies carry both `Max-Age=0` and a past `Expires`.

Temporary, rate-limit, transport, timeout, and indeterminate refresh failures return `503` through nginx without clearing the session. Only exact `401 {"error":"session_invalidated"}` or `session_superseded` responses from `/session/refresh` can remotely revoke it. `/me` never has revoke authority.

Auth-mini HTTP redirects are never followed, and JWKS, `/me`, and refresh success require exact `200 OK`. Redirects and other unexpected success statuses fail closed without replaying refresh credentials or advancing local state.

## Silent SSO capability

The pinned auth-mini version does not provide a verified no-interaction top-level redirect reuse contract. The silent-SSO capability gate is **FAIL / unsupported**. This gateway does not emulate it; adding that capability requires a separate auth-mini change and browser verification.
