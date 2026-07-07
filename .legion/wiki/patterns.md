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

- serialize refresh per gateway session
- treat stale refresh failures as non-fatal if another request already advanced the session
- before writing refreshed credentials, confirm the session still exists and still has the expected refresh token
- add regression tests for parallel refresh and logout while refresh is in flight

## Fragment callback bridge pattern

When an auth provider returns tokens in URL fragments, use a minimal first-party HTML callback page that:

- reads `window.location.hash`
- posts token material to the backend over same-origin HTTPS
- validates one-time state server-side
- clears the fragment with `history.replaceState`
- redirects only to a validated return target
