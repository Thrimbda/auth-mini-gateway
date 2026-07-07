# Change Review: auth-mini-gateway PoC

## Decision

**PASS**

Security lens applied: **yes**. This review re-checked the prior blockers and re-ran the auth/session/token/cookie/front-auth trust-boundary review against the updated implementation and verification evidence.

## Blocking Findings

None.

## Prior Blocker Re-check

### Concurrent refresh race deleting valid refreshed sessions

Resolved. `/auth/check` now uses a per-session single-flight refresh (`src/app.ts:239-247`) and keeps a newer current session instead of deleting it on stale refresh failure (`src/app.ts:209-225`). Regression coverage is present in `tests/gateway.test.ts:112-129`.

### Unbounded/uncleaned in-memory login state/session stores

Resolved. The in-memory store now prunes expired login states/sessions opportunistically and enforces configurable caps (`src/store.ts:13-22`, `src/store.ts:32-37`, `src/store.ts:50-64`, `src/store.ts:66-91`). Regression coverage is present in `tests/gateway.test.ts:202-223`.

### In-flight refresh resurrecting logged-out sessions

Resolved. Refresh writeback now re-reads the current session and refuses to update if the session was deleted or its refresh token changed while refresh was in flight (`src/app.ts:250-282`). Regression coverage is present in `tests/gateway.test.ts:172-200`.

## Security Lens Summary

- Gateway browser cookies remain opaque, signed, HttpOnly, SameSite-aware, and Secure-configurable (`src/cookies.ts:52-75`). Malformed cookie values fail closed (`src/cookies.ts:8-26`).
- Callback state remains one-time and server-side, with token material accepted only via the callback POST and not logged (`src/app.ts:98-158`).
- Access tokens are verified through auth-mini JWKS with issuer, expiration, EdDSA algorithm, token type, `sub`, `sid`, and `amr` checks (`src/auth-mini.ts:11-31`).
- Refresh verifies the returned session id and token claims before updating server-side session state, and refresh/logout concurrency now fails closed (`src/app.ts:209-282`).
- Authorization remains deny-by-default through email/user-id allowlists and optional passkey `amr` policy (`src/policy.ts`).
- nginx front-auth keeps `/auth/check` internal, strips browser cookies before proxying upstream, forwards only controlled identity headers, supports WebSocket upgrade, and the Compose topology does not publish the PoC upstream (`examples/nginx.conf`, `examples/docker-compose.yml`).

## Non-blocking Suggestions

- Keep `GET /logout` documented as a PoC convenience and prefer `POST /logout` in deployment examples.
- Consider validating `AUTH_MINI_LOGIN_URL` as an HTTP(S) URL during configuration parsing to catch misconfiguration earlier.
- Consider documenting that `MAX_LOGIN_STATES`/`MAX_SESSIONS` caps may evict oldest active entries under load, causing fail-closed re-login behavior.

## Scope and Design Consistency

- No out-of-scope product expansion was found. The change remains a runnable Node/TypeScript PoC gateway with nginx/upstream/mock examples and tests.
- The implementation remains aligned with the RFC: opaque gateway cookie, server-side token/session storage, callback bridge, JWT verification, refresh, allowlist/passkey policy, logout, and nginx `auth_request` boundary.

## Verification Assessment

`docs/test-report.md` reports passing gateway tests, typecheck, build, Compose config validation, and composed nginx smoke verification. The automated tests now explicitly cover all three prior blockers, and the nginx smoke still verifies denied requests do not reach upstream, authorized HTTP reaches upstream, authorized WebSocket reaches upstream, and upstream has no host port published.
