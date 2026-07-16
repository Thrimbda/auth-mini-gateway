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

- use shared-result per-session single-flight so all requests observing the same generation consume one success or failure result
- allow a later independent request, not queued joiners, to retry after a temporary flight failure
- treat stale refresh failures as non-fatal if another request already advanced the session
- before writing refreshed credentials, confirm the session still exists, is not revoked, and still has the expected refresh token
- use a durable compare-and-swap update for refresh token rotation
- persist rotated credentials into a fail-closed identity-pending state before remote identity refresh; finalize only after a fresh matching identity response
- do not let `/me` or equivalent profile endpoints revoke refresh sessions; only the refresh endpoint owns that wire authority
- ensure logout-vs-refresh races fail closed by making refresh writeback fail after revocation
- reject redirects and unexpected success statuses at token, identity, and JWKS boundaries
- add deterministic regression tests for shared failures, stale refresh, identity pending, and logout/expiry while refresh is in flight

## Mobile session lifecycle pattern

For browsers that may be suspended without background execution:

- keep token refresh request-driven and server-side; the next protected request performs refresh when needed
- separate a sliding inactivity deadline from a non-sliding absolute deadline
- coalesce durable activity updates to bound SQLite write amplification
- derive positive Cookie expiry from the absolute server deadline rather than a response-receipt-relative positive `Max-Age`
- propagate renewal cookies through the composed nginx `auth_request` response boundary
- return non-redirecting authentication-unavailable for recoverable dependency failures so an outage does not become a login loop

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
- verifies restart persistence, refresh rotation, temporary failure recovery, exact rejection revocation, deny-by-default policy, renewal cookies, and WebSocket upgrade
- verifies old-binary compatibility and WAL-consistent backup/restore when session schema changes
- avoids printing access tokens, refresh tokens, session cookies, cookie secrets, and callback bodies in diagnostics

## auth_request identity header pattern

When returning identity headers from a gateway to nginx `auth_request`:

- treat user id and email as untrusted even if they came from a verified token
- reject CR, LF, and control bytes before writing response headers
- deny the auth check rather than forwarding malformed identity data

## Authenticated fixed-upstream proxy pattern

For a gateway that optionally becomes the protected application proxy:

- keep adapter mode as the configuration-only rollback path when no upstream is set
- classify all gateway-owned authentication routes before proxy fallback
- use one authentication decision for adapter and proxy mappings; do not duplicate refresh, policy, touch, or cookie cleanup
- derive the destination authority and TLS SNI only from startup configuration; request data may contribute only a validated path/query
- remove browser cookies, authorization, caller identity, inbound forwarding, fixed hop-by-hop fields, and all `Connection`-nominated fields before injecting verified identity
- preserve the external Host for application semantics without using it for routing or authentication
- stream request/response frames under HTTP backpressure; never collect application bodies or place them in an unbounded channel
- close candidate selection before dispatch, call `send_request` once, and never replay, retry, or downgrade selected H2 to H1 after readiness, SETTINGS, capability, GOAWAY, REFUSED_STREAM, reset, stale-generation, or send failure
- validate both sides of a WebSocket handshake before committing downstream `101`; reject nomination of required handshake fields
- cancel incomplete uploads and disable connection reuse when an upstream returns a final response before request EOS
- verify denial paths with an upstream hit counter, and verify SSE/large-body/WebSocket behavior with timing and raw-wire assertions

## HTTP/2 capability proof and retirement pattern

For RFC 8441 on a multiplexed upstream connection:

- before sender publication or application dispatch, observe the initial server SETTINGS and the client's SETTINGS ACK on the same plaintext I/O that Hyper uses; handshake completion or sender readiness alone is not proof
- keep the same byte-transparent scanner attached for the connection lifetime, retaining only fixed frame-header/setting-pair scratch and scalar counters rather than peer-sized payloads
- seed eligibility from the initial effective `SETTINGS_ENABLE_CONNECT_PROTOCOL`; initial false remains WebSocket-disabled even if a later SETTINGS says true
- linearize every H2 enqueue against the shared generation state; a later effective `1` to `0` makes the exact generation nonselectable and retires its driver without H1 downgrade, migration, or replay
- keep monotonic generation IDs and the retiring owner slot through physical transport close so stale signals cannot evict a replacement generation

## Lifetime-owned capacity pattern

For an async proxy that must bound tasks and file descriptors:

- acquire downstream capacity before `accept()` so saturation creates no accepted FD or rejection task
- model one accepted socket as one cloneable private lease that survives Hyper upgrade into the WebSocket bridge
- count active-upstream capacity per application exchange/stream, not per multiplexed H2 connection; bound physical H1 owners and live/retiring H2 generations through the combined owner slots plus active private connections
- reserve an H2 creator's sender clone and stream permit before pool publication so another exchange cannot steal the creator's capacity
- retain exchange and stream permits until both upload disposal and response EOS/error/drop are witnessed; SSE, rejected upgrades, and tunnels retain them through their real terminal cleanup
- own the complete HTTP client connection as sender, driver, and transport-drop witness; pooled/retiring slots and private/exclusive capacity remain held through physical transport close
- make DNS resolution explicit and bounded; retain resolver handle plus capacity through timeout/cancellation cleanup instead of using hidden hostname resolution
- reserve blocking execution for authentication independently from resolver capacity
- return immediate no-body-poll `503` when upstream/resolver capacity is full; never queue request bodies behind long-lived SSE/WebSocket work
- treat panic hooks, runtime shutdown, pool cleanup, and every Drop/cancellation path as part of the resource-lifetime design
- test ownership with deterministic barriers, counters, raw `Expect: 100-continue`, child-process timeouts, and repeated cancellation runs rather than host FD exhaustion

## Trusted forwarding handoff pattern

For a known nginx-to-FRP-to-gateway chain:

- default to trusting no forwarded client metadata
- authenticate trust using only the immediate socket peer and explicit CIDRs
- have the edge proxy overwrite XFF with its own observed `$remote_addr`, never append an inbound chain
- accept one strict bare IP only, remove every inbound forwarding field, and regenerate one canonical value
- keep client IP out of authentication, authorization, session, return-target, route, DNS, TLS, and pool interfaces
- verify that varying accepted XFF changes only the application metadata header and never logs the raw value
