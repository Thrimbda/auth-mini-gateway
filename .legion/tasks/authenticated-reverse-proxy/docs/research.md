# Research: Authenticated reverse proxy current state

> **Audience:** implementation and RFC reviewers deciding whether the async/proxy change can begin safely.
> **Scope:** repository state at `3e4c273` on 2026-07-15. This document records evidence; `rfc.md` owns the proposed design.

## 1. Problem restatement

The gateway is currently a synchronous Rust/SQLite `nginx auth_request` adapter. The task adds an optional, fixed-upstream authenticated reverse-proxy mode for NAT-hosted applications while preserving adapter behavior when `UPSTREAM_URL` is absent. This crosses the authentication, cookie, HTTP framing, streaming, WebSocket, and deployment trust boundaries, so it is an RFC-heavy change.

The stable contract is `.legion/tasks/authenticated-reverse-proxy/plan.md`: a single startup-validated upstream, one shared auth decision, gateway-route precedence, real streaming/backpressure, strict header and secret handling, compatibility, sanitized errors, rollback, and an 18-case automated verification matrix.

## 2. Runtime and request path today

| Area | Current behavior | Evidence |
|---|---|---|
| Process startup | Reads environment, initializes/migrates SQLite, creates a blocking auth-mini client, then starts the server. | `src/main.rs:6-11` |
| Server | `std::net::TcpListener`; one OS thread per accepted connection; exactly one request is read and one response is written per connection. | `src/server.rs:27-59` |
| HTTP parser | Handwritten parser; at most 100 header lines; only `Content-Length` bodies; fully buffers request bodies; rejects declared bodies over 64 KiB. | `src/http.rs:21-68` |
| HTTP response | Fully buffered `Vec<u8>` body, always emits `Connection: close`, and cannot stream or upgrade. | `src/http.rs:78-148` |
| Routing | Exact method/path match in one function; every unmatched request is a no-store `404`. | `src/server.rs:61-80` |
| Auth-mini HTTP | `reqwest::blocking::Client`, redirects disabled, 10-second whole-request timeout, rustls, exact status handling, and 64 KiB bounded control-plane bodies. | `Cargo.toml:13`, `src/auth_mini.rs:104-127`, `src/auth_mini.rs:129-342` |
| SQLite | Synchronous `rusqlite`; opens a connection per operation; WAL mode; current schema version 2. | `src/db.rs:11-19`, `src/db.rs:118-150`, `src/db.rs:446-479` |
| Refresh coordination | Synchronous per-session single-flight using `Mutex` and `Condvar`; joined requests block threads and consume one published outcome. | `src/flight.rs:22-199` |

Consequences:

- The present data plane cannot satisfy keep-alive, chunked request parsing, response streaming, SSE, pooling, backpressure, bodies over 64 KiB, or Hyper-style connection upgrades.
- The auth/session implementation is already concurrency-sensitive and deliberately fail-closed. Rewriting it to async at the same time would multiply regression risk.
- A new async server must not invoke blocking reqwest, SQLite, or `Condvar` waits on Tokio worker threads.

## 3. Existing route, status, and cookie contract

The route table is exact. Query strings do not affect route selection.

| Gateway-owned path | Allowed methods | Current externally relevant behavior |
|---|---|---|
| `/healthz` | `GET` | `204`, empty body. It is the only normal route not explicitly decorated with `Cache-Control: no-store`. |
| `/login` | `GET` | Valid same-origin `return_to`/`X-Original-URI`: `302` to auth-mini plus signed `amg_login_state`. Unsafe target: no-store `400 Invalid return_to`. |
| `/auth/callback` | `GET` | `200` callback bridge HTML with no-store and a restrictive CSP. |
| `/auth/callback/session` | `POST` | `400` for invalid JSON/state/callback, `401` for invalid auth-mini session, `200` JSON for allowed identity, or `403` for denied identity. Callback responses clear login state; successful token verification sets a gateway session even when policy returns `403`. |
| `/auth/check` | `GET` | `204` plus verified identity headers when allowed; `401` plus session-cookie deletion when unauthenticated; `403` without deleting the valid denied session; `503` plus `Retry-After: 5` for temporary/indeterminate auth failure. Successful due touches may renew the session cookie. |
| `/logout` | `GET`, `POST` | Local-first revoke, best-effort auth-mini logout, `302` to validated `return_to`/configured fallback, and session-cookie deletion. |
| Every other method/path combination | none | no-store `404 Not found`. Unsupported methods on the six owned paths also reach this `404`. |

Evidence: `src/server.rs:68-80`, `src/server.rs:83-156`, `src/server.rs:192-291`, `src/server.rs:538-614`, `src/server.rs:616-700`.

Cookie compatibility is security-relevant:

- Browser session: `amg_session`; login state: `amg_login_state` (`src/cookies.rs:8-9`).
- Both are opaque HMAC-SHA256 signed values; auth-mini access and refresh tokens never enter these cookies (`src/cookies.rs:13-51`, `src/server.rs:179-189`).
- Positive cookies retain `Path=/`, `HttpOnly`, configured `SameSite`, conditional `Secure`, an absolute `Expires`, and no positive `Max-Age` (`src/cookies.rs:66-90`).
- Clear cookies retain both `Max-Age=0` and a 1970 `Expires` (`src/cookies.rs:32-37`).
- The session cookie's positive expiry comes from the authoritative SQLite idle/absolute deadline, including touch renewals (`src/server.rs:264-288`, `src/db.rs:367-415`).

## 4. Authentication, session, identity, and policy boundary

`handle_auth_check` currently contains the effective authorization decision and HTTP response mapping in one function (`src/server.rs:192-291`). Its decision sequence is:

1. Verify the signed gateway cookie. Missing or invalid becomes unauthenticated and clears the cookie.
2. Look up an active SQLite session. Revoked, idle-expired, or absolute-expired becomes unauthenticated.
3. If access is near expiry or identity is Pending, join/lead one per-session refresh flight.
4. Persist rotated tokens as Pending before fetching `/me`; only a fresh matching identity can finalize Ready.
5. Exact refresh rejection can conditionally revoke; temporary or indeterminate results return `503` and preserve the session.
6. Evaluate exact email/user-id allowlists. Authentication method (`amr`) is not an authorization input.
7. Reject unsafe identity header bytes.
8. Touch a Ready session only when due, capped by the absolute deadline.
9. Return verified user ID and optional email; never return access/refresh tokens.

Evidence:

- Refresh and Pending state machine: `src/server.rs:293-536`, `src/db.rs:306-415`.
- Durable state and compatibility invariants: `src/db.rs:43-117`, `src/db.rs:600-668`.
- JWT verifies EdDSA, `kid`, issuer, `typ=access`, expiry, subject, session ID, and `amr`: `src/jwt.rs:29-108`.
- Policy is deny-by-default and allows exact email (case-insensitive) or user ID: `src/policy.rs:14-26`.
- Identity response-header safety is checked before writing: `src/server.rs:257-262`, `src/server.rs:672-689`, `src/http.rs:218-243`.

The shared-decision refactor must preserve this ordering. In particular, denied sessions are retained but are not touched; auth outages are not converted to login redirects; `/me` has no revoke authority; and refresh flights must continue publishing one result to all same-generation joiners.

## 5. Existing test evidence

`cargo test` was run in the target worktree on 2026-07-15: **46 passed, 0 failed**. The unit suite covers JWT/auth-mini wire classification, no-redirect behavior, exact refresh rejection, Pending recovery, single-flight races, logout/expiry races, SQLite migration and deadlines, cookie shape, policy, return targets, and identity-header safety. Tests are inline under `src/*.rs`; there is no current `tests/` integration-test directory.

The repository also has three composed drills:

- `scripts/e2e-real-auth-mini.sh` launches the pinned real auth-mini, gateway, nginx, and HTTP/WebSocket upstream; verifies login, refresh, outage isolation, denial, logout, restart persistence, touch cookies, delayed responses, and WebSocket echo.
- `scripts/e2e-old-binary-compat.sh` runs the actual old binary against schema v2 and proves Ready/Pending/NULL compatibility behavior.
- `scripts/e2e-wal-backup-restore.sh` proves a WAL-consistent backup is restorable and accepted by the real gateway.

Current gaps are exactly the new data-plane risks: no direct gateway proxy, no request/response streaming fixture, no body over 64 KiB, no chunked parser path, no SSE, no Hyper connection pool, no response multi-value sanitation test, and no direct two-sided Hyper upgrade test.

## 6. Deployment and historical decisions

The current documented topology is Browser → public nginx → `auth_request` gateway + protected upstream. Nginx owns HTTP/WebSocket proxying and strips browser cookies before the app (`README.md:56-58`, `docs/production-deployment.md:227-301`, `examples/nginx.conf:46-78`).

Historical decisions explicitly say the gateway does not proxy and nginx remains the reverse proxy (`.legion/wiki/decisions.md:5-7`, `docs/README.md:18-27`). This task intentionally supersedes that decision **only when `UPSTREAM_URL` is configured**. Adapter mode remains the default and rollback path.

Other historical decisions remain authoritative:

- Browser holds only opaque gateway cookies; tokens stay in SQLite.
- One active gateway and durable SQLite WAL are the supported topology.
- Exact allowlists, request-driven refresh, Pending identity, exact refresh-rejection authority, no redirect-following, absolute cookie expiry, and real auth-mini E2E remain release gates.
- A rollback must retain an access-control layer and must not expose the protected app directly.

Evidence: `.legion/wiki/decisions.md:7-24`, `.legion/wiki/patterns.md:13-68`, `.legion/wiki/tasks/harden-mobile-session-lifecycle.md:13-43`.

Documentation conflicts that implementation must resolve:

- `README.md` describes only nginx adapter mode.
- `.env.example` has no `UPSTREAM_URL`.
- `docs/production-deployment.md` has no direct proxy topology and says nginx must own WebSocket transport.
- `docs/README.md:25` says direct upstream proxying is intentionally excluded.
- The required OpenCode NAT topology (FRP/public gateway port `7780` → fixed loopback OpenCode `4096`) is absent.

## 7. Protocol and dependency findings

The manifest has no direct async server/proxy dependencies. Hyper, Tokio, and hyper-util are present only transitively through reqwest in the current lockfile; production code cannot rely on transitive crates (`Cargo.toml:7-22`).

Current Hyper documentation establishes the needed primitives:

- Hyper request/response bodies implement a polled streaming `Body`; unpolled data applies connection backpressure instead of requiring full buffering.
- HTTP/1.1 keep-alive is connection-managed; `Connection: close` disables it.
- Hyper HTTP/1 supports `on_upgrade`, and Hyper/hyper-util server connections must be served with upgrades enabled.
- A low-level Hyper client exposes responses and upgrades without reqwest's higher-level transformations.
- Hyper 1.10.1 applies framing precedence and can normalize raw CL/TE evidence before service/client code sees a typed message. A post-Hyper `HeaderMap` therefore cannot support claims about every original raw field instance.
- Observing upstream response heads before Hyper—especially after TLS and across 1xx/101/pooling—would require a second protocol guard. The bounded design rejects that hidden scope: Hyper remains the parser/framer, framing headers are never copied across, and raw tests verify observable anti-desynchronization properties.
- hyper-util legacy client source has a retryable stale-connection path that can return a request message for replay. That is incompatible with a blanket no-retry contract for streamed non-idempotent bodies.

Sources consulted through Context7 on 2026-07-15:

- <https://docs.rs/hyper/latest/hyper/body/index.html>
- <https://docs.rs/hyper/latest/hyper/upgrade/index.html>
- <https://docs.rs/hyper/latest/hyper/client/conn/http1/index.html>
- <https://docs.rs/hyper-util/latest/hyper_util/server/conn/auto/struct.Http2Builder.html#method.serve_connection_with_upgrades>
- <https://docs.rs/hyper/1.10.1/src/hyper/proto/h1/role.rs.html>
- <https://docs.rs/hyper-util/latest/src/hyper_util/client/legacy/client.rs.html>

A mature direct implementation therefore requires explicit Tokio + Hyper 1.x + hyper-util I/O adapters + http-body-util + hyper-rustls dependencies and a small pool around low-level Hyper HTTP/1 senders. No custom request/response parser is added. The hyper-util legacy pooled client and a reqwest body bridge are not selected because no-replay, WebSocket upgrades, exact multi-value end-to-end headers, and hop-by-hop control require lower-level ownership.

## 8. Risks and pitfalls established by the code

1. **Duplicate auth logic would drift.** `/auth/check` currently owns refresh, policy, touch, cookie cleanup, and identity output in one function.
2. **Blocking on Tokio workers would stall every stream.** reqwest, SQLite, and flight waiters are synchronous.
3. **A naive router fallback could proxy unsupported methods on gateway-owned paths.** Current semantics require `404`, never upstream access.
4. **A naive URL join can replace a configured base path or accept attacker authority.** Only the original raw path/query may vary.
5. **Copying `Connection` is insufficient.** Every field named by every `Connection` value is hop-by-hop and must also be removed.
6. **Removing all hop-by-hop headers breaks WebSocket.** `Connection: upgrade` and `Upgrade: websocket` must be deliberately reintroduced only for the validated upgrade path.
7. **Hash-map header conversion loses repeated values.** `Set-Cookie`, `Warning`, `Link`, and request duplicates require append semantics.
8. **Collecting before auth or proxying breaks large uploads and backpressure.** Proxy handlers must never call `collect()` on their data-plane body.
9. **A response can fail after headers are committed.** Mid-body and post-`101` failures cannot be replaced with an HTTP `502`; the only safe behavior is stream/tunnel termination plus a secret-free event.
10. **Forwarded metadata is untrusted.** It cannot affect auth, policy, upstream selection, or TLS destination.
11. **Session touch precedes the upstream request.** Renewal metadata must survive normal responses, `101`, and pre-header `500/502`, and must retain the decision-time absolute expiry.
12. **Existing WebSockets are handshake-authorized.** Logout cannot retroactively terminate an established upgraded tunnel; this matches the present nginx model.
13. **Normalized headers are insufficient raw evidence.** Do not claim exact raw CL/TE rejection after Hyper; instead drop all cross-proxy framing metadata and raw-test no desynchronization/injection or duplicate dispatch.
14. **A convenience pool can replay.** No-retry must be embodied by one low-level `send_request` call, not asserted around a client with retryable errors.

## 9. Resolved unknowns and residuals

No contract question blocks RFC review. The RFC resolves the design choices as follows:

- Use exact path ownership across all methods; unsupported methods on owned paths remain local `404`.
- Preserve required fallback GET/POST/PUT/PATCH/DELETE; the clarified stable contract explicitly excludes generic CONNECT tunneling, so fallback CONNECT fails closed only after owned-path precedence.
- Keep the auth/session engine synchronous behind a bounded `spawn_blocking` boundary rather than simultaneously rewriting its state machine.
- Use direct Hyper HTTP/1.1 parsing/framing, a low-level one-attempt client pool, fresh cross-proxy framing, and explicit upgrade handling—without a custom protocol parser.
- Reject unsafe proxy return targets before authentication with no cookie/session side effects; use the same order for ordinary and WebSocket fallback.
- Permit `100 Continue` only when a selected local collector or authenticated proxy path actually polls the body; final handler/application status may still be `400`.
- Regenerate forwarded metadata from trusted local facts; do not trust an inbound forwarding chain.
- Permit an optional fixed upstream base path and prefix it using deterministic raw path/query composition.
- Treat `UPSTREAM_URL` as one trusted startup-only operator value under the user-specified syntax contract; production separately proves the application is loopback-only and FRP exposes only the gateway.

Accepted residuals, not blockers:

- The first design forwards the direct socket peer as `X-Forwarded-For`; it does not claim the browser IP across arbitrary Nginx/FRP chains without a future trusted-proxy configuration.
- Wire chunk boundaries are not preserved; HTTP semantics, body bytes, streaming, and backpressure are preserved while Hyper may reframe chunks.
- After downstream headers or a `101` are committed, a later upstream failure can only close the stream/tunnel.
- Restart/rollback closes in-flight HTTP streams, SSE, and WebSockets; clients must reconnect.
- The minimal first implementation closes body-bearing downstream requests after their response so unread body bytes are never reused as another request.

## 10. Evidence index

- Contract: `.legion/tasks/authenticated-reverse-proxy/plan.md`
- Runtime/routes/auth: `src/main.rs`, `src/server.rs`, `src/http.rs`
- Config: `src/config.rs`
- Auth-mini/JWT: `src/auth_mini.rs`, `src/jwt.rs`
- Sessions/SQLite/single-flight: `src/db.rs`, `src/flight.rs`
- Cookies/policy: `src/cookies.rs`, `src/policy.rs`
- Dependencies: `Cargo.toml`, `Cargo.lock`
- Tests/deployment: `scripts/`, `examples/`, `README.md`, `.env.example`, `docs/production-deployment.md`, `docs/README.md`
- Historical current truth: `.legion/wiki/decisions.md`, `.legion/wiki/patterns.md`, `.legion/wiki/tasks/harden-mobile-session-lifecycle.md`
