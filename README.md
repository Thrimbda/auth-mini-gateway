# auth-mini-gateway

Rust/SQLite gateway that adapts auth-mini sessions to nginx `auth_request` front authentication.

## What It Does

- Redirects unauthenticated users to auth-mini login.
- Receives auth-mini fragment callbacks through a first-party bridge page.
- Stores auth-mini access/refresh tokens only in the server-side SQLite database.
- Keeps the browser session as an opaque, HttpOnly signed cookie.
- Verifies auth-mini access JWTs with `/jwks`.
- Refreshes expired or near-expired access tokens through auth-mini `/session/refresh`.
- Durably revokes local sessions on logout or refresh failure.
- Applies email/user-id allowlists and optional Passkey-only policy from JWT `amr`.
- Lets nginx protect HTTP and WebSocket upstream traffic with `auth_request`.

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

The gateway expects a real auth-mini server at `AUTH_MINI_ISSUER`. For local browser traffic, set `AUTH_MINI_PUBLIC_BASE_URL` to the auth-mini origin reachable from the browser.

## Configuration

- `HOST`: bind host, default `127.0.0.1`.
- `PORT`: bind port, default `3000`.
- `GATEWAY_PUBLIC_BASE_URL`: public origin serving gateway routes through nginx.
- `AUTH_MINI_ISSUER`: internal auth-mini issuer used for `/jwks`, `/me`, refresh, and logout.
- `AUTH_MINI_PUBLIC_BASE_URL`: browser-visible auth-mini origin; defaults to `AUTH_MINI_ISSUER`.
- `AUTH_MINI_LOGIN_URL`: optional full login URL; defaults to `${AUTH_MINI_PUBLIC_BASE_URL}/web/#/login`.
- `GATEWAY_DB`: SQLite database path.
- `GATEWAY_COOKIE_SECRET`: at least 32 random characters.
- `COOKIE_SECURE`: set `true` behind HTTPS.
- `COOKIE_SAME_SITE`: `lax`, `strict`, or `none`.
- `ALLOW_EMAILS`: comma-separated exact email allowlist, compared case-insensitively.
- `ALLOW_USER_IDS`: optional comma-separated auth-mini user id allowlist.
- `REQUIRE_PASSKEY`: when `true`, requires JWT `amr` to include `webauthn`.
- `SESSION_TTL_SECONDS`: local gateway session lifetime.
- `LOGIN_STATE_TTL_SECONDS`: one-time login state lifetime.
- `REFRESH_SKEW_SECONDS`: refresh access tokens this many seconds before expiry.
- `LOGOUT_REDIRECT`: default post-logout relative redirect.

## nginx

`examples/nginx.conf` exposes public gateway routes and keeps `/auth/check` internal through `/_auth`. Protected upstream requests use nginx `auth_request`; denied requests do not reach upstream. WebSocket upgrade headers are forwarded only after auth succeeds.

## Docker Compose

`examples/docker-compose.yml` builds the Rust gateway image and a small Rust protected upstream example. It expects a real auth-mini deployment reachable as `AUTH_MINI_ISSUER`; by default this is `http://auth-mini:7777`, suitable when an auth-mini service is attached to the same Compose network.

## Deployment Model

The supported production target is one active gateway instance backed by durable SQLite WAL storage. Multi-active gateway instances sharing one SQLite session database are out of scope.
