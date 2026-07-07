# RFC: auth-mini-gateway PoC

## Status

- **Task:** `auth-mini-gateway-poc`
- **Profile:** standard RFC
- **Decision:** proposed
- **Scope:** runnable PoC gateway, nginx example, PoC upstream, tests, and handoff docs

## Context

auth-mini owns Passkey/WebAuthn, Email OTP, user records, JWT signing, refresh tokens, `/jwks`, `/me`, and session logout. nginx owns TLS, reverse proxying, WebSocket forwarding, and the decision to block or proxy each protected request. The gateway must connect those two models without becoming an upstream reverse proxy itself.

The most important integration detail is auth-mini's redirect contract: after login, tokens are returned in the callback URL fragment. Fragments are not sent in HTTP requests, so a server-only callback cannot receive the login result. The gateway therefore needs a small first-party callback page that reads the fragment in the browser, posts the token result to the gateway, then clears the address bar and redirects to a validated return target.

## Goals

- Provide a PoC gateway that nginx can call before protected upstream access.
- Keep auth-mini token material out of ordinary protected pages and long-term browser storage.
- Preserve the original requested target through login without open redirects.
- Support allowlist authorization and a configurable passkey-only policy.
- Demonstrate nginx protection with a minimal upstream and WebSocket-compatible proxy settings.

## Non-Goals

- No OIDC/OAuth provider behavior.
- No Passkey, Email OTP, user, or credential implementation in the gateway.
- No RBAC, organization model, audit backend, admin console, or multi-tenant isolation.
- No production-grade distributed session store.
- No direct OpenCode proxying in the gateway.

## Proposed Architecture

```text
Browser
  | protected request
  v
nginx -- auth subrequest --> gateway /auth/check
  | allow                         | deny 401/403
  v                               v
PoC upstream                  gateway /login -> auth-mini /web/#/login

auth-mini login -> gateway /auth/callback page
callback page JS -> gateway /auth/callback/session
gateway -> auth-mini /jwks, /me, /session/refresh, /session/logout
```

## Gateway Endpoints

- `GET /healthz`: local/container health check. No sensitive details.
- `GET /login?return_to=...`: validates a return target, creates a one-time login state, sets a short-lived state cookie, and redirects to the configured auth-mini login URL with `redirect_uri` and `state`. The login URL should default to `${AUTH_MINI_PUBLIC_BASE_URL}/web/#/login`, where `AUTH_MINI_PUBLIC_BASE_URL` defaults to `AUTH_MINI_ISSUER`.
- `GET /auth/callback`: serves a minimal no-third-party-script HTML page that reads the URL fragment, posts it to `/auth/callback/session`, clears the fragment, and redirects to the server-provided return target.
- `POST /auth/callback/session`: accepts the auth-mini login result, validates one-time state, verifies the access token with `/jwks`, fetches `/me`, checks authorization policy, creates a gateway session, sets the gateway session cookie, and returns the safe redirect target.
- `GET /auth/check`: nginx-facing endpoint. It validates the gateway cookie/session, refreshes the auth-mini session if needed, rechecks allowlist/passkey policy, and returns `204` for allowed, `401` for unauthenticated, or `403` for authenticated but unauthorized.
- `POST /logout` and `GET /logout`: invalidates the gateway session, clears cookies, attempts auth-mini `/session/logout`, and redirects to a safe configured logout target or `/`.

## Session Model

The browser stores only opaque, HttpOnly, Secure-configurable cookies:

- `amg_session`: random gateway session id, signed with `GATEWAY_COOKIE_SECRET`.
- `amg_login_state`: short-lived login state id, signed and removed after successful callback.

The gateway stores server-side records in memory for the PoC:

- gateway session id
- auth-mini `session_id`
- access token
- refresh token
- verified user id (`sub`)
- email from `/me`
- `amr`
- access token expiration
- gateway session expiration

In-memory storage is acceptable for this PoC because sessions remain revocable and expiring within one process. It must be documented as unsuitable for restarts, HA, or multi-instance production deployment.

## Token Verification And Refresh

- Verify access tokens using auth-mini `GET /jwks` and JWT EdDSA verification.
- Require issuer to match `AUTH_MINI_ISSUER`.
- Require token type/claims expected by auth-mini: `typ: access`, `sub`, `sid`, `exp`, and `amr`.
- During callback session creation, require the fragment `session_id` to match the verified JWT `sid`.
- During refresh, reject the response if the refreshed JWT `sid` no longer matches the stored auth-mini `session_id`.
- Cache JWKS through the verifier library's remote JWKS behavior rather than logging or storing private material.
- When `/auth/check` sees an expired or soon-expiring access token, call auth-mini `POST /session/refresh` with server-side `session_id` and `refresh_token`.
- After refresh, verify the new access token before updating the gateway session.
- If refresh fails, delete the gateway session, clear the cookie on the response when possible, and return `401`.

## Authorization Policy

Configuration:

- `ALLOW_EMAILS`: comma-separated exact email allowlist.
- `ALLOW_USER_IDS`: optional comma-separated auth-mini user id allowlist.
- `REQUIRE_PASSKEY`: when true, require JWT `amr` to include `webauthn` before allowing protected service access.

Default behavior:

- deny unknown users
- deny users with no email unless their user id is explicitly allowed
- deny Email OTP-only sessions when `REQUIRE_PASSKEY=true`
- permit Email OTP sessions only when `REQUIRE_PASSKEY=false` and the user is otherwise allowlisted

## Redirect And State Safety

- `return_to` accepts only relative same-origin paths by default.
- Absolute URLs are rejected unless explicitly configured in `ALLOWED_RETURN_ORIGINS`.
- One-time state is bound to a return target and short TTL.
- State is deleted on first successful or failed callback attempt.
- Callback token data must be sent in a JSON POST body and never logged.
- The callback page calls `history.replaceState` before redirecting so token fragments do not remain visible.

## nginx Integration

Use nginx `auth_request` before proxying protected traffic. Public gateway routes are defined before the protected catch-all so login/callback/logout do not recursively require auth:

```nginx
map $http_upgrade $connection_upgrade {
  default upgrade;
  '' close;
}

location = /login {
  proxy_pass http://gateway:3000/login;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
}

location = /auth/callback {
  proxy_pass http://gateway:3000/auth/callback;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
}

location = /auth/callback/session {
  proxy_pass http://gateway:3000/auth/callback/session;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
}

location = /logout {
  proxy_pass http://gateway:3000/logout;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
}

location / {
  auth_request /_auth;
  error_page 401 = /__login_redirect;
  error_page 403 = @forbidden;

  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection $connection_upgrade;
  proxy_set_header Host $host;
  proxy_set_header Cookie "";
  proxy_pass http://poc_upstream;
}

location = /_auth {
  internal;
  proxy_pass http://gateway:3000/auth/check;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header X-Original-URI $request_uri;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-Host $host;
  proxy_set_header Cookie $http_cookie;
}

location = /__login_redirect {
  internal;
  proxy_pass http://gateway:3000/login;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Original-URI $request_uri;
}

location @forbidden {
  return 403 "Forbidden\n";
}
```

The gateway routes `/login`, `/auth/callback`, `/auth/callback/session`, `/logout`, and `/healthz` must be exposed through nginx, while `/auth/check` should be reachable only as an internal auth subrequest. The PoC upstream must not be published directly in Docker Compose, proving denied requests cannot bypass nginx. Implementation should prefer a redirect helper or nginx variable escaping for `return_to` if the final config accepts characters that need URL encoding; the gateway must still reject unsafe return targets.

## Alternatives Considered

### A. Browser stores auth-mini tokens directly

- **Pros:** fewer gateway responsibilities and closer to auth-mini browser SDK examples.
- **Cons:** conflicts with the requirement that ordinary pages do not retain long-lived tokens; nginx cannot validate browser SDK state directly; harder to revoke gateway access immediately.
- **Decision:** rejected.

### B. Server-only callback endpoint

- **Pros:** simpler backend-only implementation.
- **Cons:** impossible with auth-mini's fragment callback because fragments are never sent to the server.
- **Decision:** rejected; use a minimal callback bridge page.

### C. Gateway reverse proxies upstream itself

- **Pros:** one service controls both auth and proxy behavior.
- **Cons:** violates the nginx boundary and makes WebSocket/OpenCode proxy behavior the gateway's responsibility.
- **Decision:** rejected; nginx remains the proxy and asks the gateway only for auth decisions.

### D. Signed self-contained gateway session cookie

- **Pros:** no server-side session store.
- **Cons:** token material would sit in the browser cookie, revocation is harder, and cookie size grows.
- **Decision:** rejected for PoC safety; use opaque cookie plus server-side session.

## Implementation Plan

1. Initialize a TypeScript Node project with lint/typecheck/test scripts.
2. Implement configuration parsing with safe defaults and required-secret validation.
3. Implement in-memory stores for login state and gateway sessions with TTL cleanup.
4. Implement auth-mini client wrappers for `/jwks`, `/me`, `/session/refresh`, and `/session/logout` without logging token material.
5. Implement JWT verification and policy evaluation.
6. Implement gateway routes and callback bridge page.
7. Add nginx, Docker Compose, and PoC upstream examples.
8. Add unit/integration tests with mocked auth-mini endpoints and signed test JWTs.
9. Record verification and limitations in Legion docs.

## Verification Plan

- Unit-test safe return target handling, including open redirect rejection.
- Unit-test one-time state validation and replay rejection.
- Unit-test cookie signing/tamper rejection.
- Integration-test successful callback session creation with a valid JWT and `/me` response.
- Integration-test allowlist denial after valid auth-mini login.
- Integration-test `REQUIRE_PASSKEY=true` denial for `email_otp` and allow for `webauthn`.
- Integration-test `/auth/check` refresh success updates the session and returns allow.
- Integration-test refresh failure deletes the gateway session and returns `401`.
- Integration-test logout clears gateway session and calls auth-mini logout when possible.
- Validate nginx config with `nginx -t` if nginx is available, otherwise record why it could not be run.
- Provide a composed nginx + gateway + PoC upstream smoke path in `examples/` using Docker Compose or local nginx. The upstream must expose observable request counters so the test can prove denied requests are not proxied.
- Composed smoke checks must cover:
  - unauthenticated `GET /` through nginx returns a redirect to `/login` and leaves upstream hit count unchanged;
  - authenticated but unauthorized session returns `403` and leaves upstream hit count unchanged;
  - authorized HTTP request reaches the upstream and increments its hit count;
  - authorized WebSocket upgrade reaches the upstream echo endpoint;
  - direct upstream access is not published from the Compose file, or a documented network check shows it is unreachable from outside the Compose network.
- If Docker or nginx is unavailable in the execution environment, record the exact command that was attempted, why it could not run, and the manual smoke procedure in `docs/test-report.md`; gateway automated tests still must pass.
- Run typecheck and automated tests before PR.

## Rollback And Failure Modes

- PoC rollback is removing the nginx auth_request config and returning to the existing Basic Auth setup.
- If gateway is down, nginx auth subrequests fail closed and protected upstream traffic should not be proxied.
- If auth-mini `/jwks` or refresh is unavailable, existing valid unexpired sessions may continue only if token verification can still use cached JWKS; refresh failures produce `401`.
- If the gateway restarts, in-memory sessions are lost and users must log in again.

## Security Notes

- Do not log Authorization headers, refresh tokens, access tokens, cookies, cookie secrets, or callback POST bodies.
- Return identity to upstream only through controlled headers set by nginx from auth response headers if needed; do not forward bearer tokens to upstream by default.
- Expose debug behavior only through tests or local-only runtime configuration, not public nginx routes.
- Before connecting OpenCode, verify the OpenCode service is not directly reachable from the public network and only accepts traffic through nginx.

## Open Questions

- Production persistence is intentionally deferred. A later task should choose Redis, SQLite, or another store if this moves beyond PoC.
- The exact OpenCode deployment network boundary must be checked before replacing Basic Auth.
