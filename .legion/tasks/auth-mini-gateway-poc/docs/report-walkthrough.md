# Report Walkthrough: auth-mini-gateway PoC

## Mode

implementation

## Reviewer Summary

This change initializes the repository as a runnable TypeScript PoC gateway that adapts auth-mini browser login/JWT sessions to nginx `auth_request` front authentication.

The gateway does not proxy protected upstream traffic. nginx remains responsible for TLS, reverse proxying, upstream access, and WebSocket forwarding. The gateway only answers login/callback/logout and nginx auth-check requests.

## What Changed

- Added a Node.js/TypeScript gateway service under `src/`.
- Added opaque signed HttpOnly cookie handling and server-side in-memory gateway sessions.
- Added auth-mini JWT verification through `/jwks` with issuer, expiration, EdDSA, token type, `sub`, `sid`, and `amr` checks.
- Added auth-mini `/me`, `/session/refresh`, and `/session/logout` client behavior.
- Added one-time login state and a callback bridge page for auth-mini fragment callbacks.
- Added email/user-id allowlist and optional Passkey-only policy based on `amr`.
- Added refresh hardening for concurrent nginx auth checks and logout-vs-refresh races.
- Added TTL pruning and capacity limits for public login/session state.
- Added nginx, Docker Compose, mock auth-mini, PoC upstream, WebSocket echo, and smoke-test examples under `examples/` and `scripts/`.
- Added Vitest coverage for core auth/session/security behavior.

## Key Files

- `src/app.ts`: gateway HTTP routes and session lifecycle.
- `src/auth-mini.ts`: auth-mini JWT verification and API client.
- `src/store.ts`: in-memory login/session store with pruning and caps.
- `src/policy.ts`: allowlist and Passkey policy.
- `src/cookies.ts`: signed cookie parsing/serialization.
- `examples/nginx.conf`: nginx `auth_request` integration and WebSocket proxy settings.
- `examples/docker-compose.yml`: runnable PoC topology with upstream not published to host.
- `scripts/smoke-nginx.mjs`: composed nginx/gateway/upstream smoke verification.
- `tests/gateway.test.ts`: automated gateway regression tests.

## Evidence

- Design source: `docs/rfc.md`.
- RFC review: `docs/rfc-review.md`, PASS after adding composed nginx verification.
- Verification: `docs/test-report.md`, PASS.
- Readiness/security review: `docs/review-change.md`, PASS with no blocking findings.

## Verification Summary

- `npm test`: 1 file, 11 tests passed.
- `npm run typecheck`: passed.
- `npm run build`: passed.
- `docker compose -f examples/docker-compose.yml config`: passed.
- Compose smoke: passed, proving denied requests did not reach upstream, authorized HTTP reached upstream, authorized WebSocket reached upstream, and upstream had no host port published.

## Security Notes

- Browser stores only opaque signed gateway cookies, not auth-mini access/refresh tokens.
- Callback state is one-time and server-side.
- Token/cookie material is not logged by the implementation.
- Unknown users fail closed through allowlist policy.
- Authenticated but unauthorized users get a gateway session so nginx can return `403`, while upstream remains unreachable.
- Refresh is single-flight per gateway session and will not resurrect logged-out sessions.

## Residual Limits

- Session storage is in-memory only and intentionally not production-grade.
- The mock auth-mini service is only for PoC smoke tests.
- Before replacing OpenCode Basic Auth, deployment must verify OpenCode is not directly reachable outside nginx/gateway enforcement.
