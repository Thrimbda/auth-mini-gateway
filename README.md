# auth-mini-gateway

PoC gateway that adapts auth-mini Passkey/JWT sessions to nginx `auth_request` front authentication.

## What It Does

- Redirects unauthenticated users to auth-mini login.
- Receives auth-mini fragment callback through a tiny first-party bridge page.
- Stores auth-mini access/refresh tokens only server-side.
- Keeps the browser session as an opaque, HttpOnly signed cookie.
- Verifies auth-mini JWTs with `/jwks`.
- Refreshes auth-mini sessions when access tokens are near expiry.
- Applies email/user-id allowlists and optional Passkey-only policy.
- Provides nginx and PoC upstream examples for protected HTTP/WebSocket traffic.

## Quick Start

```bash
npm install
npm run build
cp .env.example .env
npm start
```

Run tests:

```bash
npm test
npm run typecheck
```

## Configuration

- `GATEWAY_PUBLIC_BASE_URL`: public origin serving gateway routes through nginx.
- `AUTH_MINI_ISSUER`: auth-mini issuer used for `/jwks`, `/me`, refresh, and logout.
- `AUTH_MINI_PUBLIC_BASE_URL`: browser-visible auth-mini origin; defaults to `AUTH_MINI_ISSUER`.
- `AUTH_MINI_LOGIN_URL`: optional full login URL; defaults to `${AUTH_MINI_PUBLIC_BASE_URL}/web/#/login`.
- `GATEWAY_COOKIE_SECRET`: at least 32 random characters.
- `COOKIE_SECURE`: set `true` behind HTTPS.
- `ALLOW_EMAILS`: comma-separated exact email allowlist.
- `ALLOW_USER_IDS`: optional comma-separated auth-mini user id allowlist.
- `REQUIRE_PASSKEY`: when `true`, requires JWT `amr` to include `webauthn`.
- `MAX_LOGIN_STATES`: maximum outstanding login states; defaults to `10000`.
- `MAX_SESSIONS`: maximum in-memory gateway sessions; defaults to `10000`.

## PoC Limitations

Sessions are stored in memory. Restarting the gateway logs users out, and the PoC is not suitable for multi-instance production use without a shared session store.
