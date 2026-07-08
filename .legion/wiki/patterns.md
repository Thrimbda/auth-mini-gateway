# Patterns

## nginx front-auth verification pattern

For gateway-style auth adapters, verify the composed boundary, not only the gateway handler:

- unauthenticated request redirects before upstream hit count changes
- authenticated unauthorized request returns `403` before upstream hit count changes
- authorized HTTP request reaches upstream
- authorized WebSocket upgrade reaches upstream
- protected upstream has no direct host/public port exposure

## Refresh race hardening pattern

For server-side sessions backed by rotating refresh tokens:

- treat stale refresh failures as non-fatal if another request already advanced the session
- before writing refreshed credentials, confirm the session still exists, is not revoked, and still has the expected refresh token
- use a durable compare-and-swap update for refresh token rotation
- ensure logout-vs-refresh races fail closed by making refresh writeback fail after revocation
- add regression tests for stale refresh and logout while refresh is in flight

## Fragment callback bridge pattern

When an auth provider returns tokens in URL fragments, use a minimal first-party HTML callback page that:

- reads `window.location.hash`
- posts token material to the backend over same-origin HTTPS
- validates one-time state server-side
- clears the fragment with `history.replaceState`
- redirects only to a validated return target

## Real auth-mini E2E pattern

For gateway changes that depend on auth-mini contracts, prefer a harness that:

- launches the real auth-mini Rust binary with a temporary SQLite DB
- seeds auth-mini OTP/test data directly into that DB only for setup
- obtains real tokens through auth-mini HTTP endpoints
- runs the production gateway against auth-mini `/jwks`, `/me`, refresh, and logout
- puts nginx and an HTTP/WebSocket upstream in the composed path
- verifies restart persistence, refresh rotation, logout, refresh failure revocation, deny-by-default policy, and WebSocket upgrade
- avoids printing access tokens, refresh tokens, session cookies, cookie secrets, and callback bodies in diagnostics

## auth_request identity header pattern

When returning identity headers from a gateway to nginx `auth_request`:

- treat user id and email as untrusted even if they came from a verified token
- reject CR, LF, and control bytes before writing response headers
- deny the auth check rather than forwarding malformed identity data
