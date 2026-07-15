# RFC: Optional authenticated fixed-upstream reverse proxy

> **Profile:** RFC Heavy / authentication and protocol boundary
> **Status:** Ready for re-review after release-gate scope correction. Runtime/security decisions are unchanged; mandatory acceptance now matches the stable user contract.
> **Created / updated:** 2026-07-15
> **Design source of truth:** this document
> **Evidence:** `research.md`

## Executive summary

- Add `UPSTREAM_URL` as an optional startup-only setting. Missing/empty means the existing nginx `auth_request` adapter; a valid absolute `http`/`https` URL enables proxy fallback.
- Keep the six exact gateway-owned paths local for every method. Existing allowed methods retain their statuses/cookies; unsupported methods remain local `404` and are never proxied.
- Extract the current session/refresh/policy/touch sequence into one body-independent `AuthDecision` used by both `/auth/check` and proxy fallback.
- Reuse and harden the existing return-target validator before authentication/login-state creation. Unsafe origin/absolute-derived paths return cookie-neutral no-store `400`; fallback CONNECT/authority/asterisk forms follow the explicit `405/400` mode rules; none can redirect or reach upstream.
- Keep the proven synchronous auth/SQLite/single-flight state machine in a bounded Tokio `spawn_blocking` island with 64 active and 64 queued admissions. Owned active permits move into the closure; overload is a cookie-neutral `503`.
- Replace the handwritten one-request server with Tokio + Hyper HTTP/1.1. Use a small fixed-origin pool around low-level Hyper HTTP/1 senders plus a hyper-rustls connector.
- Make Hyper the sole HTTP/1 syntax, body-decoding, and message-framing authority. Never copy request or response framing headers across the proxy; filter trailer frames while Hyper generates fresh framing.
- Compose the upstream URI only from the validated fixed scheme/authority/base-path and the inbound raw path/query. Host and forwarding fields cannot select the upstream.
- Strip browser cookies, authorization, spoofed identity, inbound forwarding, standard hop-by-hop, and `Connection`-nominated fields. Inject only verified user ID/email and regenerated metadata.
- Stream request and response `Body` frames without collecting. Hyper supplies chunked reframing and pull-based backpressure. Explicit unread-body rules close downstream connections on denial or early final responses rather than claiming unsafe reuse.
- Use a small fixed-origin pool around low-level `hyper::client::conn::http1`; each inbound request calls `send_request` at most once, including on stale pooled connections.
- On non-owned fallback only, handle WebSocket as a deliberate HTTP/1.1 exception after safe-target and strict GET/version/key/empty-body validation plus upstream accept/subprotocol/extension checks, then bridge both upgraded byte streams with documented half-close semantics.
- Ordinary pre-header connect/TLS/send failures are fixed no-store `502`; parser-level malformed raw input may safely close without a promised custom status. Internal gateway failures are fixed `500`; auth dependency uncertainty remains existing `503` without cookie deletion.
- Roll out and roll back under public maintenance deny, switching FRP between proxy gateway `7780` and standby adapter nginx `7781`; the adapter gateway uses `3000` and OpenCode remains loopback `4096`. No two gateway processes share SQLite.
- Release is blocked by the four required Cargo commands, preservation of existing tests, and the exact 18 user outcomes in §16. Expanded protocol permutations and composed deployment drills remain valuable hardening evidence but are not silently promoted into a larger acceptance contract.

## 1. Context and decision drivers

The current gateway is a correct but blocking front-auth adapter. NAT-hosted OpenCode cannot safely expose its own port, and the existing public nginx cannot directly reach the loopback application. The gateway must therefore become the authenticated data-plane hop while keeping the existing adapter as default and rollback.

This is not a generic reverse proxy. It has one configured upstream, one public origin, one authentication policy, and six local control routes. The primary decision drivers are:

1. no authorization bypass during route fallback;
2. no identity/session/token spoofing or leakage;
3. no dynamic upstream selection or request-smuggling ambiguity;
4. real streaming for long OpenCode requests, uploads, SSE, and WebSocket;
5. compatibility with existing route/status/cookie/session semantics;
6. an executable rollback that remains fail-closed.

## 2. Goals

1. Add optional, startup-validated `UPSTREAM_URL` and leave adapter behavior active when absent.
2. Make non-owned routes in proxy mode pass exactly the same auth/session/policy/touch decision as `/auth/check`.
3. Preserve method, raw path/query, request body bytes, external Host, safe forwarding context, end-to-end headers, upstream status, and response body bytes subject to explicit security filtering.
4. Support HTTP/1.1 persistent downstream connections, pooled persistent upstream connections, chunked transfer semantics, SSE, bodies above 64 KiB, cancellation, and backpressure without full buffering.
5. Support authenticated WebSocket handshake and opaque bidirectional transport.
6. Produce sanitized, stable failures and secret-free observability.
7. Preserve the SQLite schema, session/cookie formats, refresh state machine, allowlist policy, and adapter rollback.

## 3. Non-goals

- Multiple upstreams, host/path routing tables, service discovery, load balancing, or user-controlled targets.
- Public TLS termination in the gateway; Acorn nginx remains the public TLS endpoint.
- Changing auth-mini, JWT claims, login UI, OTP/Passkey behavior, cookie formats, session schema, allowlists, or authentication methods.
- Forwarding browser cookies or bearer credentials to the protected app.
- Re-authenticating individual WebSocket frames or terminating existing upgraded sessions on later logout.
- Generic HTTP tunneling. `CONNECT` and authority-form request targets fail closed; “preserve method” applies to supported origin-form and absolute-form fallback requests, not to adding a CONNECT tunnel.
- Preserving literal HTTP/1 chunk boundaries; an intermediary may legally reframe while preserving bytes and streaming.
- Trusting arbitrary `Forwarded`/`X-Forwarded-*` chains. Original browser-IP attribution needs a separate trusted-proxy contract.
- HTTP/2 to the fixed upstream in this change. HTTP/1.1 is deliberate for uniform framing and upgrade semantics.

## 4. Hard constraints and invariants

### 4.1 Authentication and compatibility

- The current `handle_auth_check` ordering is authoritative. Policy cannot run on stale/Pending identity; touch cannot occur on denial; uncertain auth failure cannot clear a session.
- `/auth/check` and proxy mode call one shared decision function. Response mapping may differ; lookup/refresh/policy/touch may not.
- Gateway-owned paths are classified before proxy fallback and can never reach the upstream.
- Adapter mode retains existing exact methods, statuses, bodies at the semantic level, identity headers, cache controls, redirects, cookie multiplicity/attributes, refresh outcomes, logout behavior, and unknown-route `404`.
- No SQLite migration and no cookie/token format change.

### 4.2 Data plane

- Proxy request/response bodies are never collected into `Vec`, `Bytes`, JSON, or a channel backlog.
- A local callback body remains bounded to 64 KiB; that control-plane exception is not shared with proxy bodies.
- Hyper is the only syntax/body-framing parser on both sides. If it rejects malformed or ambiguous raw input before delivering a request/response, the gateway promises safe connection rejection/close, not a custom status.
- On supported non-owned origin/absolute fallback, preserve required GET/POST/PUT/PATCH/DELETE exactly. Generic CONNECT is excluded by the stable contract and fails `405` after owned-path precedence.
- Never copy inbound `Content-Length`, `Transfer-Encoding`, or `Trailer` to the upstream, and never copy the corresponding upstream fields downstream. Body wrappers report fresh framing information to Hyper and drop trailer frames in both directions.
- Upstream selection uses only startup configuration. Method, Host, path, query, headers, cookies, and identity cannot alter scheme/authority/port.
- Hyper owns HTTP framing. The proxy does not copy `Transfer-Encoding`, `Connection`, or `Content-Length` blindly and does not handcraft chunk frames.
- Each fallback request invokes low-level HTTP/1 `SendRequest::send_request` exactly once. Stale pooled-connection errors are returned as `502`; the request is never replayed on a fresh connection.

### 4.3 Security and operations

- No access token, refresh token, signed cookie, callback body, authorization header, verified identity value, or cookie secret is logged.
- HTTPS upstream certificate validation is mandatory; there is no insecure mode.
- `UPSTREAM_URL` is read only at startup. Mode changes require process restart and are visible in startup logs.
- `UPSTREAM_URL` is trusted operator configuration subject exactly to the accepted syntax checks. No request input, DNS routing layer, target map, redirect, or retry can change it. Production acceptance separately requires the application to bind loopback and FRP to expose only the gateway.
- `/healthz` remains liveness-only. It does not contact auth-mini or the upstream and therefore cannot amplify dependency outages.

## 5. Options considered

### Option A — Extend the handwritten `TcpListener` server

**Pros**

- Small dependency change.
- Existing local response code remains familiar.

**Cons**

- Requires implementing persistent HTTP/1 parsing, chunking, `Expect`, header limits, upgrades, pooling, TLS, cancellation, and backpressure.
- High request-smuggling and protocol-compliance risk.
- Recreates functionality already maintained by Hyper.

**Decision:** reject. The current parser is intentionally too limited for the accepted transport contract.

### Option B — Axum router/server plus a Hyper proxy client

**Pros**

- Mature routing/extractors and convenient local handlers.
- Hyper-compatible bodies and upgrades.

**Cons**

- Axum's default method-mismatch behavior (`405`) and fallback layering can obscure the required local `404` and route-precedence contract.
- The gateway still needs low-level Hyper header/body/upgrade handling, so the framework does not remove the hard part.
- Adds another behavioral layer during a compatibility-sensitive migration.

**Decision:** viable, but not selected.

### Option C — Direct Tokio + Hyper server, low-level HTTP/1 connection pool, and synchronous auth island

**Pros**

- Direct control over semantic dispatch, multi-value end-to-end headers, streaming bodies, connection upgrades, and error commitment points while Hyper owns syntax/framing.
- Mature HTTP parser and connection state machine.
- A small fixed-origin pool owns low-level Hyper HTTP/1 senders, making one-attempt/no-replay behavior explicit; hyper-rustls provides validated HTTPS.
- Preserves the proven auth/session implementation rather than rewriting protocol and auth concurrency together.

**Cons**

- More explicit service/body plumbing than Axum.
- The repository owns a small amount of pool lifecycle code and must return a connection only after the response body completes.
- Synchronous auth waiters occupy bounded blocking threads, requiring explicit admission limits.
- Requires disciplined conversion between local full bodies and upstream streaming bodies.

**Decision:** select.

### Option D — reqwest as the reverse-proxy client

**Pros**

- Already a dependency; familiar TLS and pooling.

**Cons**

- Higher-level request/response transformation makes exact framing and repeated-header control less transparent.
- Two-sided raw upgrade handling is not the right abstraction for a WebSocket reverse proxy.
- Body stream adapters add complexity without reducing the need for Hyper server primitives.

**Decision:** reject for the data plane; retain blocking reqwest for the auth-mini control plane in this task.

## 6. Proposed architecture

```text
                         ┌─────────────────────────────┐
Browser / Acorn nginx ──▶│ Tokio TCP + Hyper HTTP/1.1 │
                         └──────────────┬──────────────┘
                                        │ exact path classification
                    ┌───────────────────┴────────────────────┐
                    │                                        │
             gateway-owned route                       fallback route
                    │                                        │
          local handler / shared auth             shared AuthDecision
                    │                                        │
                    └──────── bounded blocking island ────────┘
                                  │
                         SQLite + auth-mini + flight
                                                           allow only
                                                               │
                                                 sanitize/compose request
                                                               │
                                        pooled Hyper HTTP/1.1 + rustls
                                                               │
                                                fixed UPSTREAM_URL
```

### 6.1 Runtime and state

`main` becomes Tokio multi-thread runtime startup. It still performs configuration validation and `Store::initialize` before accepting traffic. `AppState` contains:

- immutable `Arc<Config>`;
- `Arc<Store>`;
- `Arc<dyn AuthMini>` using the current blocking client;
- shared `FlightCoordinator`;
- `AuthExecutor` with bounded admission, a Tokio work semaphore, and blocking entry points;
- optional immutable `Proxy` containing the parsed upstream base, connector/client factory, and a fixed-origin idle HTTP/1 connection pool.

The server accepts a Tokio `TcpListener`, captures the direct peer `SocketAddr`, and serves it directly with Hyper HTTP/1 plus upgrades enabled. Hyper owns request-line/header syntax, CL/TE interpretation, body decoding, informational responses, and connection framing. HTTP/1.1 keep-alive is used only when the request body has been fully consumed; every denial or early-final path with an unread body explicitly sends `Connection: close`.

The blocking lane has **64 active slots and 64 queued slots**:

1. A non-blocking `try_acquire_owned` on a 128-permit admission semaphore bounds active plus queued operations. Failure immediately returns the existing no-store authentication-unavailable `503` with `Retry-After: 5`, no cookie mutation, no redirect, and no upstream access.
2. While holding admission, the task awaits one of 64 work permits. Cancellation here releases admission and starts no blocking work.
3. Once admitted to work, both `OwnedSemaphorePermit`s are moved into the `spawn_blocking` closure. Dropping/canceling the async join handle cannot release either permit while the closure continues. Normal return or panic unwinding drops both permits.
4. The permit is released as soon as the auth/control-plane operation returns; it is never held during upstream HTTP, SSE, or WebSocket transport.

Overload is intentionally cookie-neutral because the session has not been classified: it must never clear a potentially valid session or turn saturation into a login redirect. `/auth/check`, proxy auth, `/login`, callback session creation, and `/logout` use the same overload response.

Why retain the blocking island:

- SQLite, blocking reqwest, and `Condvar` never execute on a Tokio worker.
- Existing refresh CAS, Pending transitions, and exact failure classes remain intact.
- `spawn_blocking` work is not canceled after it starts. A disconnected client cannot interrupt a committed token rotation between persistence steps; the state machine reaches and publishes a terminal flight outcome.
- The active and admission semaphores bound threads, remote calls, and unread queued requests. Same-session joiners can block inside the lane, but the first request is the flight leader and retains one active slot until it publishes; queued joiners cannot displace it. Deterministic saturation tests prove leader progress, `WaitForClose` progress, cancellation, panic release, and different-session saturation.

All blocking call sites are enumerated and must be mechanically audited:

- startup-only `Config::from_env` and `Store::initialize` run before Tokio accepts traffic and are the only allowed exceptions;
- `/login`: SQLite prune/create login state;
- `/auth/callback/session`: consume state, JWKS/initial JWT verification, `/me`, SQLite create session;
- `/auth/check` and proxy fallback: every SQLite lookup/CAS/touch/prune, auth-mini JWKS/refresh/`/me`, and every `FlightCoordinator` `Mutex`/`Condvar` wait;
- `/logout`: SQLite snapshot/revoke and best-effort blocking auth-mini logout.

Cookie parsing/HMAC, URL validation, policy comparison, and fixed response construction are bounded CPU operations, but calls that compose them with a listed blocking operation stay inside the same closure. No blocking reqwest, rusqlite, or flight method may be called from another module without an `AuthExecutor` entry point.

A future fully async auth client/coordinator may remove this island, but it is not coupled to the protocol migration.

### 6.2 Proposed module boundaries

| Module | Responsibility |
|---|---|
| `src/config.rs` | Parse/validate optional `UPSTREAM_URL` into an immutable `UpstreamBase`; retain all existing validation. |
| `src/server.rs` | Tokio listener, Hyper connection lifecycle, peer context, `AppState`, top-level sanitized error boundary. |
| `src/routes.rs` (new) | First semantic exact-path dispatch, fallback target/upgrade classification, current login/callback/logout/health handlers, adapter response mapping, local body-limit compatibility. |
| `src/authorization.rs` (new) | `AuthDecision`, verified identity, renewal/cleanup metadata, and the existing lookup/refresh/policy/touch sequence. Synchronous core plus async bounded wrapper. |
| `src/proxy.rs` (new) | URI/return-target composition, request/response header sanitation, fresh-framing body adapters, low-level fixed-origin pool, proxy errors, and upgrade bridge. |
| `src/http.rs` | Hyper response/body aliases, fixed local responses, bounded callback collection; remove the handwritten socket parser/writer after parity tests exist. |
| `src/auth_mini.rs`, `src/db.rs`, `src/flight.rs`, `src/jwt.rs`, `src/cookies.rs`, `src/policy.rs` | Preserve semantics; adapt call sites/types only where required. |

Tests should be outside production modules where protocol fixtures are large: `tests/proxy_integration.rs` plus small unit tests beside config/authorization/proxy helpers.

## 7. Configuration and fixed URI composition

### 7.1 `UPSTREAM_URL` contract

`UPSTREAM_URL` missing or exactly empty means `None` and adapter mode. Any non-empty value must pass all checks at startup:

1. parse as an absolute URL;
2. scheme is exactly `http` or `https`;
3. host/authority exists;
4. username is empty and password is absent;
5. query is absent, including an empty `?` delimiter;
6. fragment is absent, including an empty `#` delimiter;
7. URL is a hierarchical base URL;
8. its path can be represented as a valid HTTP path prefix.

Invalid configuration terminates startup with a variable-specific message that does not print the value. Validation does **not** make a network request; a temporarily down application must not stop the gateway from starting. Reachability failures become runtime `502`.

The URL may contain a fixed path prefix. The syntax validator deliberately does not add a host allowlist beyond the accepted user contract: this is startup-only, trusted operator configuration, not an SSRF input. There is no request-selected target, DNS routing table, redirect-following target, hidden second upstream, or runtime reconfiguration. If the configured host is a name, the ordinary connector resolves that one operator-selected name only.

Production acceptance is narrower than syntax acceptance: the protected application must listen only on loopback, the deployed value must resolve/connect to that loopback listener, and FRP/firewall checks must prove that only the gateway listener is exposed. The OpenCode deployment uses the literal `http://127.0.0.1:4096`; no production claim is accepted with a remotely reachable application target.

Examples:

| Configured base | Incoming target | Upstream target |
|---|---|---|
| `http://127.0.0.1:4096` | `/api?q=1&q=2` | `http://127.0.0.1:4096/api?q=1&q=2` |
| `https://app.internal/base/` | `/events?raw=%2F` | `https://app.internal/base/events?raw=%2F` |
| `http://127.0.0.1:4096/root` | `/` | `http://127.0.0.1:4096/root/` |

### 7.2 Composition algorithm

At startup store scheme, authority, and a path prefix with trailing slashes removed (`/` becomes no prefix). After Hyper has delivered a syntactically valid request, semantic dispatch order is fixed:

1. If the URI has a path equal to one of the six gateway-owned paths, dispatch immediately to the existing local method table. No fallback target, return-target, generic Upgrade, WebSocket, CONNECT, or proxy-Expect classifier can preempt it.
2. If adapter mode is active, every non-owned request is the existing no-store `404`; no proxy-only classifier runs.
3. In proxy mode only, classify the non-owned fallback request-target form below.
4. For origin/absolute fallback, derive and validate the browser return target. Unsafe is fixed `400` before authentication with no cookie mutation.
5. Classify generic Upgrade/WebSocket structure, then run shared authentication, then proxy only `Allow`.

This ordering means `CONNECT /healthz` and malformed `Upgrade: anything` on `GET /healthz` still enter the owned route: unsupported method is local `404`; valid GET is local `204`.

| Request-target form | Rule |
|---|---|
| origin-form `/path?query` | Supported on non-owned fallback for GET and required POST/PUT/PATCH/DELETE (and other non-CONNECT methods Hyper represents); use exact raw path/query after safety validation. |
| absolute-form `http://attacker.example/path?query` | Same supported methods; ignore supplied scheme/authority completely and derive only raw path/query. Require `http`/`https` syntax and an explicit origin path, then run the same validator. |
| authority-form `host:port` | Fallback CONNECT returns fixed no-store `405 Method not allowed`; authority-form with any other method is fixed no-store `400 Bad request`. |
| asterisk-form `*` | In proxy mode, `OPTIONS *` and every other asterisk-form fallback return fixed no-store `400 Bad request`. In adapter mode they retain fallback `404`. |

On a non-owned proxy fallback, `CONNECT` is always `405` regardless of target form. The clarified stable contract requires method preservation for GET/POST/PUT/PATCH/DELETE and explicitly excludes generic CONNECT tunneling. WebSocket remains the one explicit upgrade.

For a supported target:

1. Extract the complete raw origin path and optional raw query. An absolute-form authority never survives this step.
2. Validate the same-origin browser return representation using the existing `normalize_return_to` contract, extended once and reused by direct `/login` and proxy login. The shared validator rejects:
   - leading network paths (`//`);
   - any literal backslash or case-insensitive percent-encoded backslash (`%5c`) that a browser URL parser could treat as a separator;
   - ASCII control/DEL bytes and their percent-encoded representations;
   - CR/LF, malformed percent encoding, or a non-leading-slash origin path;
   - an absolute target whose derived path/query fails any of these checks.
3. Only after the validator returns safe may the complete original derived path/query (duplicate keys, order, empty values, and safe percent escapes included) be stored as login `return_to` or used for upstream composition. No URL `join`, query parse/rebuild, or percent decode/re-encode occurs on this safe value.
4. Concatenate `base_prefix + incoming_path`, retain the raw query suffix, and build the upstream origin-form URI. TCP/TLS destination comes from the stored upstream authority, not from this URI string or Host.

Return-target safety is classified before authentication/admission for ordinary and WebSocket fallback through this same function. Unsafe always returns exact no-store `400 Bad request` with **no `Set-Cookie`**, no session lookup/refresh/touch, no login state, no auth-mini redirect, and no application upstream contact. The request body remains unread and the response carries `Connection: close` when Hyper reports a body may remain.

The configured base path is a routing prefix, not a filesystem security sandbox; the immutable configured authority is the SSRF boundary. A failure of a startup-proven internal composition invariant is a sanitized `500`, but no legal authority/asterisk/CONNECT form is allowed to reach that branch.

## 8. Exact route precedence and local compatibility

Whenever Hyper delivers a URI with a path, exact path ownership is the first semantic dispatch. These paths are always gateway-owned:

```text
/healthz
/login
/auth/callback
/auth/callback/session
/auth/check
/logout
```

For an owned path, the existing method table applies. Any other method returns the existing local no-store `404`; it does not fall through. CONNECT, authority/asterisk handling, unsafe-return checks, generic Upgrade rejection, and WebSocket validation are fallback-only and cannot alter an owned result. A query does not change ownership. Paths such as `/login/` or `/auth/custom` are not aliases and are fallback paths; in adapter mode they are `404`, while in proxy mode they require auth and may reach the fixed app.

### 8.1 Compatibility matrix

| Condition | Adapter response that must remain |
|---|---|
| `GET /healthz` | `204`, no dependency check |
| valid `GET /login` | `302`, no-store, auth-mini `Location`, one positive `amg_login_state` |
| unsafe login target | `400 Invalid return_to`, no-store |
| `GET /auth/callback` | existing HTML/CSP/no-store |
| invalid callback JSON/state/data | `400`, no-store, clear `amg_login_state` |
| invalid callback auth-mini token/session | `401`, no-store, clear login state |
| allowed callback | `200` JSON, clear login state + positive `amg_session` |
| denied callback | `403`, clear login state + positive `amg_session`; session remains usable if policy changes |
| auth check allowed | `204`, no-store, verified identity headers, optional positive session renewal |
| auth check unauthenticated | `401 Unauthenticated`, no-store, clear session cookie |
| auth check forbidden/unsafe identity | `403 Forbidden`, no-store, no clear and no touch |
| auth check temporary/indeterminate | `503`, no-store, `Retry-After: 5`, no clear |
| `GET`/`POST /logout` | local-first revoke, `302`, no-store, clear session cookie |
| unmatched route in adapter mode | `404 Not found`, no-store |

Cookie names, signing, percent encoding, attributes, absolute `Expires`, lack of positive `Max-Age`, and dual-signal deletion remain unchanged.

## 9. One shared authentication decision

### 9.1 Interface

The body-independent synchronous core returns data, not an HTTP response:

```text
AuthDecision
  Allow {
    identity: VerifiedIdentity { user_id, email },
    session_renewal: Option<SetCookieValue>
  }
  Unauthenticated {
    clear_session: SetCookieValue
  }
  Forbidden
  Unavailable {
    retry_after_seconds: 5
  }
```

`VerifiedIdentity` is constructible only after Ready-state refresh/recovery, policy allow, safe-header validation, and successful touch/CAS handling. It carries no access token, refresh token, auth session ID, or `amr`.

The core preserves the current eight-attempt CAS loop and all current flight outcome mappings. SQLite/temporary/indeterminate auth failures remain `Unavailable`, while an unexpected blocking task panic/join failure is an internal error handled as `500` at the async boundary.

### 9.2 `/auth/check` mapping

- `Allow` → existing `204`, identity headers, optional renewal cookie.
- `Unauthenticated` → existing `401` and clear cookie.
- `Forbidden` → existing `403`, no cookie change.
- `Unavailable` → existing `503` + `Retry-After: 5`, no cookie change.

### 9.3 Proxy mapping

- `Allow` → sanitize and stream to the fixed upstream. Append renewal to every eventual response, including upstream errors, proxy `500/502`, SSE headers, and `101`.
- `Unauthenticated` → target safety has already passed without touching session state. Do not poll/forward the request body. Create login state and return the same direct auth-mini `302` as `/login`, with **both** the shared session clear and new login-state cookie. Missing, malformed, expired, revoked, and exactly rejected sessions all take this path.
- `Forbidden` → no-store `403 Forbidden`; never contact upstream; retain the valid session and do not touch it.
- `Unavailable` → existing no-store `503` + `Retry-After: 5`; never redirect, clear, or contact upstream.

If login-state creation fails after `Unauthenticated`, return sanitized `500` and still attach the session-clear cookie. Redirect status remains `302` for compatibility, including unauthenticated non-GET requests; bodies are not replayed after login.

An `AuthExecutor` admission failure is not an `AuthDecision`: for a safe fallback target it maps to cookie-neutral no-store `503` + `Retry-After: 5` for both mappers. It never redirects, clears, touches, or reaches upstream. Unsafe targets never attempt admission.

### 9.4 Timing and cancellation

Hyper parses `Expect` and emits `100 Continue` when the application first polls the request body. The gateway never forwards `Expect` upstream. The implementable state machine is:

- After Hyper syntax parsing, exact owned-path/method dispatch occurs first. For non-owned proxy fallback, target-form/return-target/Upgrade/WebSocket checks occur next. None of these steps polls the body, so they cannot trigger `100`.
- Accept exactly one case-insensitive `Expect: 100-continue` on HTTP/1.1 when Hyper reports a possible body. Repeated/mixed/other expectations, HTTP/1.0 Expect, or Expect with no body return no-store `417 Expectation failed` before polling and close.
- Gateway-owned and adapter-fallback compatibility collectors may poll a valid body after route/method selection. Their first poll may emit `100`; the eventual handler can legitimately return `204`, `404`, or `400` (for example invalid callback JSON/state) after the body arrives.
- On safe proxy fallback, shared authentication completes before body polling. Redirect, forbidden, auth-unavailable, overload, invalid Upgrade/WebSocket, unsafe target, and other early denial paths do not emit `100` and close if a body remains unread.
- On proxy `Allow`, remove `Expect`, start the one upstream attempt, and poll the streaming body. The first poll may emit downstream `100`. The application may later return any final status, including `400`; that does not violate the pre-poll security property.
- If the upstream sends a final response before end-of-stream, stop polling/drop the body, preserve that final response after sanitation, and force downstream `Connection: close`. Unexpected upstream informational `100` is consumed by Hyper and is not independently relayed.

For every early-final path, Hyper's body/end-stream state determines whether bytes remain. If so, do not drain and force close; if the local collector or proxy upload reached clean end-of-stream, normal response semantics apply (body-bearing downstream connections still close under the conservative first-version rule). A malformed/truncated body closes without attempting a second response.

During a slow refresh, Hyper/socket flow control bounds unread body data rather than buffering the whole body in application memory.

Touch and renewal expiry are fixed at decision time, before upstream I/O. A slow response cannot shift `Expires`. Once a blocking refresh starts, client cancellation does not abort it; durable token rotation and flight publication complete. After `Allow` returns, the blocking permit is released before proxy transport begins.

## 10. HTTP stack and body model

### 10.1 Dependencies

Add direct, compatible stable releases and commit their lockfile resolution:

- `tokio` 1.x: multi-thread runtime, net, sync, I/O, macros, signal;
- `hyper` 1.x: HTTP/1 client/server and upgrade primitives;
- `hyper-util` 0.1.x: Tokio I/O adapters only; do not use its legacy retrying pooled client;
- `http-body-util` 0.1.x and `bytes` 1.x: body erasure, fixed local bodies, bounded callback collection, frame adapters;
- `hyper-rustls` 0.27.x: HTTP/HTTPS connector with validated platform/native roots and HTTP/1 enabled;
- `rustls` 0.23.x plus `rustls-native-certs`: explicit production root-store construction and the injectable trusted-root seam; no custom verifier;
- `tracing`/`tracing-subscriber`: structured secret-free stderr events.

Keep reqwest `blocking`, rusqlite, and current crypto dependencies in this task. Do not add Axum, a reverse-proxy convenience crate, an async SQLite abstraction, or a WebSocket frame parser to production dependencies.

### 10.2 Hyper framing authority

There is no custom raw request/response parser or decrypted upstream-I/O guard. Hyper is the mature HTTP stack and sole authority for request-line/status-line syntax, header parsing, CL/TE precedence, chunk decoding, informational responses, close-delimited bodies, `101` buffered bytes, and parser-level connection reuse.

The gateway's framing contract begins only after Hyper delivers a typed request/response:

- If Hyper rejects ambiguous/malformed downstream input before service dispatch, no upstream application request exists. The connection is rejected/closed using Hyper behavior; the RFC does not promise a custom `400` or cookie.
- If Hyper rejects an upstream response before delivering it, the one request attempt fails and both connections are safely terminated. The implementation may emit sanitized `502` only when Hyper surfaces an ordinary pre-commit client error and the downstream remains safely writable; the raw-parser test contract does not require that status.
- The gateway never copies `Content-Length`, `Transfer-Encoding`, or `Trailer` across either proxy direction. It streams data frames through a wrapper that reports an unknown size for body-capable messages, so Hyper emits fresh legal framing. For no-body methods/statuses and `101`, Hyper's typed semantics remain authoritative.
- Every trailer frame is consumed and dropped; the wrapper continues polling to normal end-of-stream. Declared `Trailer` fields are stripped. This exact behavior is identical request-to-upstream and response-to-client.
- Parser upgrades are gated by raw-socket adversarial tests for observable safety rather than assertions about hidden raw metadata: no request desynchronization, no second request/response injection, no leaked CL/TE/Trailer, and at most one upstream application dispatch.

Configure Hyper's documented `max_headers(100)`, `header_read_timeout(10s)` with a Tokio timer, and `ignore_invalid_headers(false)`. These are parser configuration, not a second parser; raw malformed-input tests still assert observable safety rather than a particular parser-generated status body.

### 10.3 Low-level upstream client and no-retry pool

Do not use hyper-util legacy `Client`: its retryable stale-connection path can return the request for replay. Instead implement a fixed-origin pool of at most eight idle low-level `hyper::client::conn::http1::SendRequest` leases:

1. Checkout one idle lease or create one connection through the immutable HTTP/HTTPS connector. Connector selection, DNS (if the operator configured a name), TCP, and TLS handshake are wrapped in one 10-second deadline.
2. Poll `SendRequest::ready` once. A stale/closed pooled lease is discarded and the current request fails `502`; it is not retried on a fresh connection.
3. Call `send_request` exactly once. This invocation is the request attempt. Any error before, during, or after first body write is final for that request and maps according to §13; no method or body is cloneable/replayable by the pool.
4. A lease returns to the idle pool only after Hyper and the trailer-dropping wrapper reach clean end-of-stream, readiness succeeds, idle capacity is available, and the response was not an upgrade or close-delimited/`Connection: close`. Dropping/canceling/truncating a body drops the lease and connection.
5. An upgraded lease is permanently removed and owned by the tunnel.

The connector/client factory takes a `rustls::RootCertStore` at construction. Production construction has one path and loads validated platform/native roots; there is no insecure flag or accept-all verifier. Tests can inject an ephemeral trusted CA through the factory seam while production configuration cannot.

TLS SNI/certificate validation uses the configured upstream host. The HTTP `Host` sent to the application remains the original external Host; these are deliberately different concerns. No whole-request, response-body, SSE idle, or WebSocket idle timeout is imposed. There is no decompression, compression, redirect following, or response-status rewriting.

### 10.4 Body types and non-buffering

The proxy moves the inbound Hyper body into the upstream request through a thin `Body` wrapper:

- data frames are passed as `Bytes` without aggregation;
- polling the upstream client polls the downstream body, providing pull-based backpressure;
- request and response trailer frames are consumed and dropped rather than forwarded; declared `Trailer` fields are stripped; after a trailer the wrapper continues to a normal end-of-stream;
- body errors propagate to the transport and are classified without including details in responses/logs.

The upstream response body is similarly returned as a streaming body and is polled only as the downstream can accept data. There are no unbounded channels. For requests/responses without a known length, Hyper chooses legal HTTP/1.1 chunked framing. It may combine or split chunks; only ordered bytes and streaming semantics are contractual.

Only `/auth/callback/session` uses bounded collection, with the existing 64 KiB maximum across all frames. Oversize/invalid callback input remains `400`. Other local routes do not share the proxy body path.

Dropping a downstream request or response drops the corresponding Hyper body/future and closes or cancels upstream work. A dropped upgraded connection terminates bidirectional copy. A body-bearing downstream connection is explicitly closed after its response in this first implementation; this conservative rule makes every early-final/unread-body path deterministic. Bodyless HTTP/1.1 requests and pooled upstream connections still provide the required keep-alive/connection reuse.

## 11. Request URI, Host, forwarding, and header policy

### 11.1 Request sanitation algorithm

Operate on Hyper `HeaderMap` values; never convert to a single-value map.

0. Operate only on a request Hyper delivered. Parser-rejected raw input never enters semantic dispatch.
1. Capture the parsed original `Host`. A semantic missing/ambiguous Host detected after delivery becomes no-store `400` and close.
2. Read every `Connection` field and parse every comma-separated token as a header name. A malformed token is `400` rather than a sanitation bypass.
3. Remove all headers named by those tokens.
4. Remove the fixed hop-by-hop set from every normal request:
   - `Connection`
   - `Keep-Alive`
   - `Proxy-Connection`
   - `Proxy-Authenticate`
   - `Proxy-Authorization`
   - `TE`
   - `Trailer`
   - `Transfer-Encoding`
   - `Upgrade`
5. Remove secret/spoofing inputs:
   - `Cookie`
   - `Authorization`
   - every `X-Auth-Mini-*` field
   - `Forwarded`
   - every `X-Forwarded-*` field
   - `Expect` (consumed by the gateway state machine in §9.4)
6. Preserve all remaining end-to-end fields and their repeated values with append semantics.
7. Set `Host` to the captured external Host.
8. Inject exactly one `X-Auth-Mini-User-Id` and optional one `X-Auth-Mini-Email` from `VerifiedIdentity`.
9. Generate safe forwarding metadata:
   - `X-Forwarded-For`: direct accepted socket peer IP only;
   - `X-Forwarded-Proto`: scheme from validated `GATEWAY_PUBLIC_BASE_URL`;
   - `X-Forwarded-Host`: captured external Host.

No forwarding field participates in authentication, policy, return-target validation, URI authority, DNS, TLS SNI, or pool selection. The protected app may use it only as informational metadata. Acorn nginx should canonicalize public Host before sending traffic.

Remove `Content-Length`, `Transfer-Encoding`, and `Trailer` for every proxied request. The data-only body wrapper reports unknown size for a body-capable request and drops trailer frames while continuing to normal end-of-stream; Hyper generates the new upstream framing. No inbound framing header or trailer metadata is reused.

### 11.2 No browser secrets upstream

The gateway sends no browser Cookie header, no Authorization/Proxy-Authorization, no signed gateway cookie, and no auth-mini access/refresh token. Callback token payloads cannot hit fallback because `/auth/callback/session` is owned before dispatch. Application payloads remain opaque; the gateway cannot infer arbitrary secrets intentionally placed in a path, query, body, or nonstandard field.

### 11.3 Response sanitation

For every upstream response:

1. Operate only on a response Hyper delivered. A parser error before delivery is an upstream request failure, not raw metadata available to the gateway.
2. Parse delivered `Connection` values and remove every valid nominated field. If a delivered value cannot be safely tokenized, fail before downstream commitment with sanitized `502` and close that upstream connection.
3. Remove the fixed hop-by-hop set and unconditionally remove `Content-Length`, `Transfer-Encoding`, and `Trailer`.
4. Wrap body data with unknown size for body-capable responses, consume/drop trailer frames, and let Hyper generate fresh downstream framing. For HEAD, no-body statuses, and `101`, use Hyper's typed no-body/upgrade semantics.
5. Remove response `X-Auth-Mini-*` fields so the upstream cannot impersonate gateway metadata to the browser.
6. Preserve status and all remaining end-to-end header instances. Never comma-join `Set-Cookie`, `Warning`, or `Link`.
7. Filter each application `Set-Cookie` independently using §11.4.
8. Append, never replace, the optional gateway session-renewal `Set-Cookie`.

Upstream `3xx`, `4xx`, and `5xx` statuses remain unchanged. In particular, an application's `500` is not a gateway `500`. `Location` is not rewritten; preserving external Host/X-Forwarded metadata lets a correctly configured app generate public URLs.

For `HEAD`, `1xx`, `204`, and `304`, apply Hyper's typed status/method body rules. A downstream `101` never contains `Content-Length`, `Transfer-Encoding`, or `Trailer`; delivered instances are stripped, while any parser-level malformed framing that prevented response delivery is handled by Hyper/connection failure rather than a custom raw guard.

### 11.4 Fail-closed `Set-Cookie` filtering and order

Each `Set-Cookie` field is parsed separately; fields are never comma-split or combined.

1. Strip leading SP/HTAB OWS, take bytes through the first `;`, and require one non-empty RFC token cookie-name immediately followed by `=`. OWS around the name or `=` is not accepted. HeaderValue has already excluded CR/LF.
2. Cookie names are case-sensitive. Drop valid exact `amg_session` and `amg_login_state`. A valid `amg_session2`, `AMG_SESSION`, or other near miss is non-reserved and is preserved.
3. Drop every malformed field rather than forwarding something browsers may parse differently. This conservatively drops malformed reserved-looking variants such as `amg_session =x`; values are never logged.
4. Preserve valid non-reserved fields byte-for-byte and in their original per-name order as separate instances.

Ordering is deterministic:

- sanitized application cookies remain first in upstream order;
- a prior `Allow` renewal is appended last;
- unauthenticated login responses emit session-clear first and login-state second;
- callback responses retain their current login-state-clear then positive-session order;
- generated `500/502` have no application cookies and append only prior shared metadata: session clear for a failed unauthenticated login-state operation, or renewal for a post-Allow failure.

## 12. WebSocket upgrade design

WebSocket validation applies only to a non-owned proxy fallback after exact owned-path dispatch and safe-target validation. Owned paths ignore generic/malformed Upgrade semantics and retain their existing method-table result. On fallback, WebSocket is the only tunneled upgrade: any Upgrade intent that is not a valid WebSocket candidate is fixed local no-store `400`, closes, and has zero upstream hits.

After the fallback target is proven safe (with no authentication yet), the client handshake must satisfy all structural items below before auth/upstream dispatch:

- method exactly `GET`, HTTP version exactly 1.1, and origin/absolute target form from §7.2;
- token parsing across all repeated `Connection` fields contains `upgrade`, and all repeated `Upgrade` fields resolve to exactly one case-insensitive `websocket` token with no other protocol;
- exactly one `Sec-WebSocket-Version` field/value equal to `13`;
- exactly one `Sec-WebSocket-Key`; after OWS trimming it is canonical standard Base64 that decodes to exactly 16 bytes and re-encodes to the same value;
- Hyper reports an exact zero-length/end-stream body. A delivered nonzero/unknown body (including chunked framing) is rejected; framing headers are never forwarded;
- every offered subprotocol is a valid token; duplicates are rejected; extension fields are syntactically valid comma-separated extension names/parameters.

Failure is local `400`, no cookie mutation, no login state/auth-mini redirect/upstream, and no `100`. Because an accepted WebSocket body is known empty, the response can close without a drain.

### 12.1 Handshake flow

1. After owned-route dispatch and target safety, validate the structural handshake, then complete the shared `AuthDecision`. Only a valid, safe, `Allow` fallback handshake can continue.
2. Before moving the inbound request, obtain `client_on_upgrade = hyper::upgrade::on(&mut request)`.
3. Run normal request sanitation, including removal of every caller-provided hop-by-hop and connection-nominated field.
4. Re-add canonical `Connection: upgrade` and `Upgrade: websocket`. Preserve the one validated key/version, valid offered subprotocols/extensions, and Origin after normal secret filtering.
5. Force the upstream request to HTTP/1.1 and send it through the shared client.
6. If upstream returns a non-`101`, sanitize and stream it as an ordinary response; do not upgrade downstream.
7. If upstream returns `101`, require all of the following before downstream commitment; any failure is fixed no-store `502`:
   - valid `Connection: upgrade` and exactly one `Upgrade: websocket`;
   - Hyper delivered an upgrade response; any delivered CL/TE/Trailer fields are stripped and never used downstream;
   - exactly one `Sec-WebSocket-Accept` equal to Base64(SHA-1(client-key + RFC 6455 GUID));
   - zero or one selected `Sec-WebSocket-Protocol`, and if present it exactly matches one client-offered token;
   - every selected extension name was offered by the client. The gateway checks syntax and offered-name subset but deliberately delegates extension-parameter semantics to the two RFC 6455 endpoints because it does not transform frames. The browser remains an independent semantic validator.
8. Obtain `upstream_on_upgrade = hyper::upgrade::on(&mut upstream_response)` before converting the response.
9. Sanitize the `101`, remove all ordinary body-framing fields, deliberately re-add canonical Connection/Upgrade, preserve the verified Accept/selected protocol/extensions and other end-to-end fields, and append session renewal.
10. Return `101` to the client and spawn a tunnel task. Await both `OnUpgrade` futures, wrap both `Upgraded` streams in Tokio I/O adapters, and run `tokio::io::copy_bidirectional`.

`copy_bidirectional` uses bounded buffers and awaits writes, so slow clients/upstreams exert backpressure. Hyper `Upgraded` preserves bytes already read past each HTTP head; the tunnel must wrap and copy those buffers before reading the underlying socket. Frames are opaque; the gateway does not unmask, parse, inspect, log, or mutate application traffic. The upgraded connection is removed from the HTTP pool.

Termination uses **TCP half-close**, matching `copy_bidirectional` rather than claiming first-EOF cancellation:

- EOF from one reader flushes pending bytes, shuts down the opposite writer half, and continues copying the other direction until its EOF;
- a non-EOF I/O error, task cancellation/process shutdown, or failure of either `OnUpgrade` drops both streams immediately;
- if one `OnUpgrade` resolves and the other fails, drop the resolved side; after committed `101` the client observes connection close, not a second HTTP response;
- no tunnel idle timeout is added.

### 12.2 Commitment boundary

An upstream Hyper parser failure before response delivery safely closes (and may yield `502` only through the ordinary pre-commit error path); a delivered `101` with invalid Accept/subprotocol/extensions is sanitized pre-commit `502`. Delivered framing headers are simply stripped and regenerated. If either upgrade future fails after downstream `101`, no valid HTTP status can replace it; apply the termination rule above. Raw tests cover both upgrade-future failures, pre-read buffered bytes, each half-close direction, cancellation, and post-`101` close.

Authorization occurs only at handshake, matching existing nginx behavior. A later logout prevents new requests/upgrades but does not kill an established socket.

## 13. Failure behavior

Generated responses are exact UTF-8 text with no trailing newline and `Content-Type: text/plain; charset=utf-8`:

- `400 Bad request`
- `405 Method not allowed`
- `417 Expectation failed`
- `500 Internal server error`
- `502 Bad gateway`
- existing `503 Authentication service temporarily unavailable` plus `Retry-After: 5`

All gateway-generated responses after Hyper delivers a request are `Cache-Control: no-store`. `400/405/417` and every response with an unread body carry `Connection: close`. Parser-level rejections before request/response delivery are owned by Hyper and promise only safe rejection/close, not these exact bodies.

“Prior cookie metadata” exists only after a completed shared decision: `Unauthenticated` owns one clear value; `Allow` may own one renewal; `Forbidden`, `Unavailable`, and admission overload own none. The table is authoritative:

| Phase / owner | Failure or outcome | Exact action | Prior cookie handling |
|---|---|---|---|
| Hyper downstream parser, pre-service | malformed/ambiguous request syntax or framing rejected before Request delivery | Hyper rejection/connection close; status not promised; service and upstream are not invoked | none |
| owned-path dispatch | any method/header combination, including CONNECT or malformed/generic Upgrade | existing owned method table (`404` for unsupported method); no proxy classifier/upstream | existing route-specific only |
| adapter-mode non-owned dispatch | any target form/method | existing no-store `404`; no proxy classifier | none |
| proxy fallback target classifier | CONNECT | fixed `405`, close, zero login/upstream | none; auth not run |
| proxy fallback target classifier | authority form for non-CONNECT, `OPTIONS *`, or other asterisk form | fixed `400`, close, zero login/upstream | none; auth not run |
| proxy fallback target safety | unsafe same-origin/browser return target | fixed `400`, close if unread body, no login state/redirect/upstream | none; auth not run |
| fallback Upgrade/WebSocket classifier | generic/malformed Upgrade or invalid WebSocket structure | fixed `400`, close, no `100`, zero upstream | none; auth not run |
| Expect classifier after semantic route/target validation | unsupported/repeated/invalid Expect | fixed `417`, close, no body poll | none |
| local compatibility body collector | valid Expect/body is polled, then oversize/invalid JSON/state or other handler rejection | may emit `100`; then existing local `400`/status and close as required | exact route-specific cleanup after handler runs |
| blocking admission, pre-decision | 128 operations already admitted | existing `503`, no redirect/upstream | none; deliberately no clear |
| blocking closure/join, pre-decision | panic/join failure | fixed `500`; permits release via closure unwind | none |
| completed proxy decision | Unauthenticated + safe return target | direct auth-mini `302` | session clear first, new login state second |
| completed proxy decision | Forbidden/unsafe identity | existing `403`; close if unread body | none |
| completed proxy decision | auth temporary/indeterminate | existing `503`; close if unread body | none |
| login-state operation | SQLite/internal failure after Unauthenticated | fixed `500`; close if unread body | preserve session clear only |
| local callback/logout/login | existing validation/status outcome | compatibility appendix mapping | exact route-specific clear/positive order |
| post-Allow request construction | impossible URI/header/body invariant | fixed `500`; no upstream; close if unread body | append due renewal last |
| connector deadline | DNS/TCP/TLS does not complete within one 10-second deadline | fixed `502`; no retry | append due renewal last |
| pool checkout/readiness | stale/closed idle sender | fixed `502`; drop lease; no fresh connection/retry | append due renewal last |
| upstream send before headers | protocol/send error, including partial upstream request write while the downstream connection is still writable | fixed `502`; stop polling unread body and force close; no retry | append renewal last |
| client request body | malformed chunk, premature EOF, body stream error, or downstream disconnect after dispatch | drop upstream request/lease and close; never retry or synthesize a response on a broken client stream | not deliverable |
| upstream early final | valid final response arrives before request end | preserve sanitized final; stop polling body; force downstream close | append renewal last |
| Hyper upstream parser, pre-response | malformed/ambiguous response rejected before Response delivery | safely terminate; an ordinary pre-commit surfaced client error may be sanitized `502`, but raw tests do not require it; no retry | append renewal only if a `502` is actually emitted |
| delivered response sanitizer, pre-commit | delivered Connection value cannot be tokenized safely | fixed `502`; close/drop upstream; no retry | append renewal last |
| upstream ordinary response | valid `1xx` handling followed by valid final, `2xx/3xx/4xx/5xx` | preserve final status/end-to-end headers/body after sanitation | app cookies first, renewal last |
| upstream body, post-commit | response body error after downstream headers | terminate downstream body/connection; drop lease | already committed |
| either streaming body | trailer frame delivered by Hyper | consume/drop trailer and continue to normal body completion; no trailer crosses proxy | already committed if response direction |
| downstream writer, post-commit | client disconnect/write error | cancel/drop upstream body/lease | already committed or undeliverable |
| fallback WebSocket validation | malformed GET/version/key/body/protocol/extension after safe target | fixed `400`, close, zero upstream | none; auth not run |
| upstream WebSocket, pre-commit | Hyper parser failure before response | safe close; optional ordinary pre-commit `502`; drop lease | renewal only if `502` emitted |
| upstream WebSocket, pre-commit | delivered invalid `101` Upgrade/Accept/selected protocol/extension | fixed `502`; drop upgrade/lease | append renewal last |
| WebSocket, post-`101` | either OnUpgrade failure, I/O error, cancellation | close/drop both; EOF uses documented half-close | `101` metadata already committed |

Malformed upstream `Set-Cookie` is not a transport failure: §11.4 drops that individual field and preserves the rest. Fixed error bodies contain no upstream URL, DNS name, socket address, header, cookie, identity, token, SQLite detail, or library error. No failure path automatically replays a request.

## 14. Security and privacy analysis

| Threat | Control |
|---|---|
| Route-based auth bypass | Exact owned-path classification before fallback; all fallback traffic calls shared auth; route-isolation hit counters in tests. |
| Auth semantic drift | One `AuthDecision`; adapter and proxy are response mappers only; existing refresh/race tests retained. |
| SSRF/dynamic routing | Startup-only scheme/authority; request contributes only raw path/query; Host/forwarding ignored for destination. |
| Identity spoofing | Strip every inbound `X-Auth-Mini-*`; inject validated Ready-session values only after policy/touch. |
| Cookie/token exfiltration | Strip Cookie and authorization; callback route cannot fall through; never construct proxy headers from stored tokens. |
| Request smuggling / hop confusion | Hyper is the sole parser/framer; no CL/TE/Trailer crosses either direction; Connection-nominated/fixed hop fields are removed; trailer frames are dropped; raw tests prove no desynchronization/injection and at most one dispatch. |
| CONNECT/generic tunnel bypass | CONNECT/authority/asterisk forms fail closed; only the fully validated WebSocket GET upgrade can tunnel. |
| WebSocket handshake spoofing | Validate version/key/empty body, compute Accept, constrain selected subprotocol/extension names, and reject malformed `101` before commitment. |
| Forwarded-header spoofing | Delete inbound chain and regenerate from peer/config/Host; never auth on metadata. |
| Host-driven routing | Host is preserved for app semantics but never used for destination, TLS, policy, or callback origin. |
| Upstream cookie collision | Preserve app cookies but drop gateway-owned cookie names; append gateway renewal separately. |
| Upstream internal detail leakage on transport failure | Fixed `502`; no error display. End-to-end application responses remain application-owned. |
| Memory exhaustion by bodies | No proxy collection/channels; callback-only 64 KiB limit; Hyper pull-based bodies and socket backpressure. |
| Duplicate non-idempotent request | Low-level `SendRequest` called once; stale pooled sender fails `502`; no legacy-client or application retry. |
| Auth thread/queue exhaustion | 64 active + 64 queued admission; owned permits move into closure; excess gets cookie-neutral `503`; class-only saturation observability. |
| Slowloris/header abuse | Hyper is configured for 100 headers, strict invalid-header handling, and a 10-second header-read timeout; body polling and socket backpressure avoid unbounded application buffers. |
| CSRF | Existing SameSite/session behavior is unchanged. The fixed app remains responsible for CSRF on state-changing methods, as in nginx adapter mode. |
| Compromised fixed upstream | It receives verified identity and application payload, but not gateway cookies/tokens. It can still return malicious application content; upstream integrity remains an operational trust assumption. |

Privacy: user ID/email are disclosed only to the configured fixed app because that is the feature's purpose. They are not logged or added to responses. Query/path/body remain application data and therefore are not logged by the gateway.

## 15. Observability and operational behavior

Use structured stderr events. Preserve current refresh/session event names where possible and add:

- startup: `mode=adapter|proxy`, validation success; do not print full upstream URL;
- auth: decision class, blocking-lane wait duration, decision duration, flight outcome class;
- admission: active/queued/overload class; never session/cookie values;
- proxy: method, status class, duration-to-headers, completion class; omit URI/query/Host/identity;
- transport error class: `framing`, `connect`, `dns`, `tls`, `stale_pool`, `protocol`, `request_body`, `response_body`, `upgrade`; log one attempt class, never error text;
- WebSocket: handshake outcome and tunnel close class/duration, no frame sizes/content;
- sanitation: aggregate dropped reserved-cookie or malformed-connection-token count, never values.

Log-derived metrics/alerts:

- rate of auth `503`, internal `500`, proxy `502`, and malformed `400`;
- p95 auth-lane wait and in-flight saturation;
- time to upstream headers and active long-lived responses/upgrades;
- WebSocket handshake/upgrade failure rate;
- existing invalidation, Pending age/count, SQLite, and refresh-flight alerts.

Alert on sustained nonzero `500`, a material `502` increase, auth-lane saturation, or WebSocket upgrade regression. `/healthz` proves only process liveness; operators diagnose dependencies from classified events and direct loopback checks.

## 16. Verification architecture and release gate

### 16.1 Scope correction

The earlier RFC turned protocol design risks into an open-ended mandatory conformance program. Implementation and independent verification showed that this exceeded the stable user contract without improving the release decision. This revision removes that scope drift:

- Runtime security, framing authority, header sanitation, route precedence, streaming, one-attempt/no-retry, WebSocket validation, and failure semantics remain unchanged.
- Existing defense-in-depth tests remain in the repository and must not be deleted merely because they are outside the user matrix.
- The **mandatory release decision** is exactly §16.2 plus the four Cargo commands in §21. Existing tests are preserved through mandatory `cargo test`.
- Completeness of the broader permutations in §16.3 is recommended hardening, not a product blocker unless a scenario is already covered by the mandatory outcomes or a present in-repo test fails under mandatory `cargo test`.

### 16.2 Required Acceptance Matrix — exactly 18 outcomes

These are the stable mandatory automated outcomes. A focused integration harness may combine assertions in one test process, but the report must map evidence to every numbered outcome:

1. **Adapter unknown route:** with `UPSTREAM_URL` unset, an unknown route returns `404`.
2. **`/auth/check`:** proves `204` allow with verified identity headers, `401` unauthenticated, and `403` forbidden.
3. **Authenticated GET proxy:** an allowed session reaches the fixed upstream with GET and receives its response.
4. **Required mutating methods:** authenticated POST, PUT, PATCH, and DELETE preserve method, query, and body.
5. **Unauthenticated HTTP isolation:** a non-owned request returns login `302` and the upstream hit count does not change.
6. **Forbidden HTTP isolation:** a denied identity receives `403` and the upstream hit count does not change.
7. **Spoofed identity overwrite:** caller-supplied identity headers cannot survive; upstream observes only gateway-injected verified values.
8. **Gateway Cookie stripping:** the browser `Cookie` header is absent at the upstream.
9. **Verified-session identity source:** injected identity exists only for an authenticated, verified gateway session; no caller input or unauthenticated path can create it.
10. **Large streaming body:** a proxied body larger than 64 KiB is delivered correctly without the gateway's local 64 KiB callback limit/full buffering.
11. **Chunked response:** an upstream unknown-length/chunked response reaches the client correctly under Hyper-generated framing.
12. **SSE streaming:** the first SSE event reaches the client before the upstream completes the response.
13. **Authenticated WebSocket:** a verified session completes a WebSocket upgrade and bidirectional data exchange.
14. **Unauthenticated WebSocket isolation:** an unauthenticated upgrade does not reach the upstream.
15. **Unreachable upstream:** a normal pre-commit connection failure returns sanitized `502` without internal details.
16. **Gateway-owned routes remain local:** `/login`, `/auth/callback`, `/auth/callback/session`, `/logout`, and `/healthz` are handled locally and never proxied.
17. **Existing refresh/logout behavior:** all existing in-repository refresh and logout tests continue to pass.
18. **Secret-free logs:** automated capture proves logs exclude browser cookies, access/refresh tokens, callback token bodies, and `GATEWAY_COOKIE_SECRET`.

### 16.3 Extended Hardening Matrix — recommended, not an expanded acceptance contract

Keep and run available in-repository hardening tests. Add or deepen these when risk, regressions, or maintenance justify them, but do not block release solely because every permutation below has not been automated:

- adversarial raw CL/TE/duplicate-CL/chunk/trailer/pipelining corpora, asserting no desynchronization, framing-header leak, duplicate dispatch, or response injection;
- every cross-product of gateway-owned routes, unsupported methods, request bodies, `Expect`, and malformed/generic Upgrade fields beyond outcome 16;
- byte-identical `/auth/check` versus proxy decision/cookie matrices beyond the statuses and verified identity required by outcomes 2, 5, 6, and 9;
- exhaustive 64-active + 64-queued admission permutations, cancellation/panic ordering, and every single-flight alias/`WaitForClose` combination beyond existing tests;
- stale-connection and partial-write reset permutations beyond the retained one-attempt/no-retry implementation tests;
- every malformed WebSocket key/version/subprotocol/extension/framing, both half-close orders, both `OnUpgrade` failures, and post-`101` cancellation beyond outcomes 13–14;
- exhaustive parser/failure-provenance permutations and trusted-root certificate variants beyond outcome 15;
- physical or simulated Acorn/FRP `7780` ↔ node-nginx `7781` port switching, public maintenance deny, and connection-drain drills.

A failing hardening test that is already part of `cargo test` is still a mandatory Cargo-test failure. The scope correction means only that absence of every additional permutation is not itself a release blocker.

### 16.4 Composed and environment-dependent evidence

Repository scripts should run when their documented prerequisites are available and their results should be recorded:

- `scripts/e2e-proxy-mode.sh`
- `scripts/e2e-mode-switch.sh`
- `scripts/e2e-old-binary-compat.sh`
- `scripts/e2e-wal-backup-restore.sh`
- `scripts/e2e-real-auth-mini.sh`

The externally pinned real-auth-mini run is valuable composed evidence, not a mandatory product gate in an environment without the expected external checkout/commit. A missing or mismatched `AUTH_MINI_RUST_DIR` is recorded as an environment limitation; it is not a gateway failure when mandatory `cargo test` proves all existing in-repository refresh/logout coverage and all §16.2 outcomes pass. If prerequisites are present and a script exposes a product defect, record and fix the defect rather than relabeling it as an environment skip. No script or test diagnostic may print secrets.

## 17. Rollout, migration, and rollback

### 17.1 Data migration

None. Schema remains v2; cookie and session rows are unchanged. Existing sessions can be used in either mode. `UPSTREAM_URL` is process configuration only.

### 17.2 Safe rollout

1. Land the async runtime and shared decision with `UPSTREAM_URL` absent. Pass the four mandatory Cargo commands and required adapter/auth outcomes. Run composed nginx/auth-mini compatibility scripts when their prerequisites exist; record unavailable external fixtures per §16.4 rather than converting them into a new product gate.
2. Build/release once and retain the previous image/binary, node-local nginx adapter config, FRP config, DB backup, and cookie secret. Validate but do not yet expose these listeners:
   - OpenCode: `127.0.0.1:4096` only;
   - proxy gateway: `127.0.0.1:7780`, `UPSTREAM_URL=http://127.0.0.1:4096`;
   - adapter gateway (when active): `127.0.0.1:3000`, `UPSTREAM_URL` unset;
   - node-local adapter nginx: `127.0.0.1:7781`, `auth_request` to `3000`, app proxy to `4096`.
3. The single-active SQLite rule means proxy gateway and adapter gateway are never live together. To move adapter → proxy, enable a public Acorn maintenance deny (`503`) before stopping the adapter gateway. Node-local nginx may remain listening but cannot authorize while its gateway is stopped.
4. Stop adapter gateway `3000`; start proxy gateway `7780` with the same DB/secret; verify locally on `7780`: health, owned routes, safe redirect, denial hit isolation, HTTP/SSE/WebSocket, Host/header stripping, and `502` behavior.
5. Change the one FRP target from node-local nginx `127.0.0.1:7781` to proxy gateway `127.0.0.1:7780`. FRP must have no target for `3000` or `4096`.
6. Verify through the public/FRP path while maintenance deny is still available, then remove deny and monitor §15. Keep the `7781` nginx config and previous binary for rollback.

The two mutually exclusive service topologies are:

```text
Proxy mode:
Browser -> Acorn nginx :443 -> FRP target 127.0.0.1:7780
        -> gateway proxy :7780 -> OpenCode 127.0.0.1:4096

Adapter mode:
Browser -> Acorn nginx :443 -> FRP target 127.0.0.1:7781
        -> node nginx :7781
             -> auth_request gateway adapter 127.0.0.1:3000
             -> OpenCode 127.0.0.1:4096 after allow

auth-mini-gateway -> auth-mini issuer (JWKS / me / refresh / logout)
```

### 17.3 Rollback triggers

- Any gateway-owned route reaches the upstream.
- Cookie/token/identity spoofing or leakage.
- Adapter compatibility regression.
- Sustained `500/502`, refresh/session regression, body buffering/memory growth, SSE delay, or WebSocket failure.
- OpenCode port `4096` becomes publicly reachable.

### 17.4 Executable rollback

1. Enable Acorn maintenance deny before changing any node listener or FRP target. Confirm requests cannot reach either gateway/application path.
2. Stop proxy gateway `7780`. Record that active HTTP uploads/downloads, SSE, and WebSockets close. Only after it exits and releases SQLite may another gateway process start.
3. Start the new adapter-mode binary or previous binary on `127.0.0.1:3000` with the same schema-v2 DB and cookie secret and with `UPSTREAM_URL` absent. Wait for `/healthz`.
4. Start/reload retained node-local nginx on `127.0.0.1:7781`; it uses `/auth/check` at `3000` and proxies allowed requests to `127.0.0.1:4096`.
5. Before public switch, run local hit-counter checks through `7781`: anonymous redirects without app hit, denied `403` without app hit, allowed HTTP and WebSocket hit, auth `503` does not hit. Verify `3000` and `4096` have no FRP/public exposure.
6. Switch the single FRP target from `127.0.0.1:7780` to `127.0.0.1:7781`; verify through FRP while maintenance deny remains available, then remove deny.
7. If adapter start/verification fails, keep maintenance deny and either restart the previously verified proxy on `7780` after stopping adapter `3000`, or remain denied. Never point FRP at `4096` as a recovery shortcut.

An old binary ignores the unknown environment variable and serves adapter routes only; if accidentally started while traffic still targets it as a proxy, application paths fail closed with `404` rather than exposing OpenCode. Service restoration still requires the adapter nginx path. Existing schema-v2 Pending/Ready rollback rules remain unchanged.

When prerequisites permit, `scripts/e2e-mode-switch.sh` should exercise both directions with the same temporary schema-v2 DB/secret, public-deny simulation, explicit process-exit ordering, FRP-target simulation, hit counters, and connection-closure assertions. Any observed process overlap or direct route to `4096` is a defect, but completeness or availability of this composed drill remains §16.3/§16.4 evidence rather than an additional mandatory release outcome.

## 18. Documentation changes

Implementation must update, as one reviewed unit:

- `README.md`: describe both modes, selection rule, fixed-upstream/security behavior, streaming/WS capabilities, and verification.
- `.env.example`: add commented/empty `UPSTREAM_URL=` with validation examples and adapter-default explanation.
- `docs/production-deployment.md`: provide separate adapter and proxy topologies; exact proxy `7780`, adapter gateway `3000`, node nginx `7781`, and OpenCode loopback `4096` listeners; Acorn maintenance deny and FRP switch order; Host/forwarded behavior; cookie/token stripping; SSE/WebSocket; health; rollout/rollback/troubleshooting.
- `docs/README.md`: remove the obsolete statement that direct proxying is excluded and link both modes.
- `examples/`: retain nginx adapter example and either add a proxy-mode compose profile or state clearly that the gateway replaces nginx only for application proxying, not public TLS.

Docs must state that `UPSTREAM_URL` is trusted startup-only operator configuration with exactly one target—not a routing template—and the production topology requires the app to listen only on loopback and FRP to expose only `7780` or `7781`, never `3000`/`4096`. They must also warn that upstream app cookies are not sent on requests, generic Authorization is stripped, forwarded client IP is the direct peer only, and established WebSockets survive session logout until disconnected.

## 19. Milestones and design gates

### Milestone 1 — Async adapter parity

- Add runtime/body abstractions and shared `AuthDecision`; keep proxy disabled.
- Evidence target: existing in-repository tests remain passing and required outcomes 1, 2, 16, and 17 pass. Keeping blocking auth/SQLite off Tokio workers remains a runtime design invariant reviewed in implementation, not a nineteenth acceptance outcome.
- Rollback impact: binary-only; schema unchanged.

### Milestone 2 — Fixed HTTP streaming proxy

- Add config validation, URI/header policy, pooled HTTP/HTTPS client, non-buffering body transport, sanitized errors, and automated evidence for the required non-WebSocket proxy outcomes.
- Evidence target: required HTTP outcomes 3–12, 15, and 18 pass while Milestone 1 remains green. Extended framing/no-retry/saturation evidence is retained or recorded separately, not expanded into new user outcomes.
- Rollback impact: unset `UPSTREAM_URL`.

### Milestone 3 — WebSocket, deployment, and full verification

- Add two-sided upgrade bridge, observability, and documentation; collect composed proxy evidence when its prerequisites exist.
- Release gate: required outcomes 13–14 complete the exact 18-outcome matrix, all four Cargo commands pass, and existing tests are preserved. Review evaluates that evidence and the unchanged security design but must not silently add automated outcomes. Environment-dependent script results are recorded per §16.4 without treating missing external prerequisites as product failure.
- Rollback impact: active tunnels close; adapter remains available.

## 20. Open questions and accepted residuals

### Blocking open questions

None. Any review finding that changes auth outcomes, header trust, upgrade commitment, or rollback returns the RFC to Draft.

### Accepted residuals

1. `X-Forwarded-For` initially represents the direct gateway peer, not a claimed browser address across an unconfigured trust chain.
2. Chunk framing and header order across different names are not preserved; repeated values and HTTP semantics are.
3. A mid-body or post-`101` failure cannot become a new `502`; connection termination is the protocol-correct signal.
4. WebSocket authorization is handshake-time only.
5. Body-bearing downstream requests close after their response in the first implementation, even after successful complete upload. This is a deliberate minimal framing-hardening tradeoff; bodyless HTTP/1.1 keep-alive and upstream pooling remain supported.
6. Parser-level malformed/ambiguous raw input may produce a Hyper response or only a safe connection close; exact gateway error bodies begin only after Hyper delivers a typed request/response.
7. HTTP trailers are intentionally discarded in both directions; data frames complete normally and trailer metadata is not part of the proxy contract.

## 21. Verification commands

Required implementation gate:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release --bin auth-mini-gateway
```

`cargo test` is mandatory and must preserve all existing in-repository tests in addition to proving the §16.2 acceptance mapping. The scripts listed in §16.4 are separate recommended/composed evidence and run when prerequisites exist; they are not hidden fifth-or-later mandatory commands.

Deployment smoke examples to document, not run against production from CI:

```bash
curl -i https://app.example.com/healthz
curl -i https://app.example.com/
curl -i -X POST --data-binary @large.bin https://app.example.com/upload
curl -N https://app.example.com/events
```

The test report must record the four commands, commit, the 18-outcome evidence map, pass/fail, and any extended/script evidence attempted. Environment limitations—especially a missing external auth-mini checkout—must be explicit without being reported as product failure. No report may print secret values.

## 22. Compatibility appendix: current wire semantics and intentional hardening

This appendix distinguishes required compatibility from parser behavior that this security change intentionally tightens.

### 22.1 Header/query extraction retained

| Input | Required behavior |
|---|---|
| repeated `Cookie` fields | The shared extractor used by `/auth/check` and proxy mode reads the first field in wire order, matching current `Request::header`; later Cookie fields do not rescue an invalid/missing session. Within that field, the first exact `amg_session` pair wins. An undecodable first value is invalid and produces the normal shared clear. No Cookie is proxied. |
| multiple `amg_session` pairs in first Cookie field | First exact pair wins, matching current left-to-right cookie parser. |
| repeated `X-Original-URI` on `/login` | First field in wire order, matching current header lookup. Unsafe/non-UTF-8 value is `400 Invalid return_to`. |
| query `return_to` plus `X-Original-URI` | Query wins, as today. |
| duplicate query `return_to` | Last successfully percent-decoded query pair wins because the current parser overwrites the HashMap entry; a malformed pair is ignored. This applies to direct `/login`, not proxy raw path/query storage. |
| duplicate ordinary query keys in proxy target | Not parsed; raw ordering/duplicates are preserved after safety validation. |

Raw compatibility tests pin first/last behavior so a future HeaderMap/query extractor cannot change it accidentally.

### 22.2 Local body limit and dispatch retained

- The current parser reads every declared CL body before route dispatch and rejects `Content-Length > 65536`. Preserve that status boundary for all gateway-owned paths and every adapter-mode fallback after Hyper delivery: a known CL body up to 64 KiB is collected before the selected local handler/`404`; known over-limit or decoded overrun is no-store `400`.
- Consequently `GET /healthz` with a small declared body remains `204`; an unsupported owned method with a small body remains `404`; an adapter unknown route with a small body remains `404`. The body is consumed for status compatibility, but the conservative framing rule still closes every body-bearing connection; current code also closes every response.
- `/auth/callback/session` parses the collected bytes exactly as today and does not add a Content-Type requirement.
- Proxy-mode non-owned fallback is the only unbounded streaming body path. It does not use the local 64 KiB collector.
- Current code does not decode chunked local bodies. To retain local statuses/callback mapping, a Hyper-delivered local/adapter request carrying TE is not polled: local dispatch receives an empty body and the downstream connection closes. Thus health/unknown/logout keep their route result and callback remains invalid-JSON `400` with its existing login-state cleanup. Proxy fallback, by contrast, streams Hyper-decoded chunked data after Allow.

### 22.3 Route/status/header/cookie mapping retained

| Route/outcome | Required mapping |
|---|---|
| `GET /healthz` | `204`; retain absence of explicit `Cache-Control: no-store`. |
| `/login` valid/invalid | Existing `302` + positive login-state cookie, or no-store `400 Invalid return_to`; shared validator gains backslash/control hardening for both direct and proxy login. |
| callback page | Existing HTML, CSP, no-store. |
| callback invalid JSON/state/data | `400`, no-store, login-state clear. |
| callback invalid auth-mini session | `401`, no-store, login-state clear. |
| callback allowed | `200` JSON, no-store, login-state clear first, positive session second. |
| callback denied | `403`, same two cookies/order; retained valid session. |
| auth allowed/unauth/denied/unavailable | Existing `204` identity/optional renewal; `401` clear; `403` no clear/touch; `503` Retry-After/no clear. |
| logout GET/POST | Existing local-first revoke, best-effort remote logout, `302`, session clear. |
| unsupported method on owned path | Local `404`, never `405`/proxy; body rule above applies. |
| generic/malformed Upgrade on owned path | Ignored by proxy fallback logic; the existing owned method-table status remains (`204` for GET health, `404` for unsupported method, etc.). |
| unknown adapter path | Local no-store `404`. |

Positive and clear cookie bytes/attributes remain generated by current cookie helpers. Hyper may add protocol-standard `Date`, use keep-alive, suppress forbidden HEAD/1xx body framing, and choose legal chunk boundaries; those are not changes to gateway route semantics.

### 22.4 Intentional security-positive parser changes

The following current handwritten-parser behaviors are not compatibility promises and are deliberately replaced:

- use Hyper as sole syntax/framing authority; parser-level malformed/ambiguous input may close without the old fixed `400`, and tests assert safety rather than parser text;
- configure Hyper's 100-header limit, strict invalid-header mode, and 10-second header timeout;
- after owned-path precedence, reject proxy-fallback CONNECT/authority/asterisk forms rather than composing or tunneling them;
- restrict generic Upgrade/WebSocket validation to non-owned proxy fallback;
- allow a valid owned/adapter body collector to emit `100 Continue`, while proxy fallback cannot emit it until target validation and Allow;
- reject unsafe network/backslash/control return targets before authentication with no cookie mutation;
- close on unread request bodies and all body-bearing proxy requests instead of treating unread bytes as reusable connection input;
- never reuse CL/TE/Trailer across either direction; drop trailer frames and let Hyper generate fresh framing;
- validate delivered WebSocket `101` Accept/subprotocol/extensions before downstream commitment;
- permit bodyless HTTP/1.1 keep-alive instead of always emitting `Connection: close`.

These behaviors remain part of the runtime design and retained defense-in-depth suite. Their broad permutation coverage belongs to §16.3; only assertions that map to the stable §16.2 outcomes are mandatory acceptance blockers.

## 23. References

- Plan: `.legion/tasks/authenticated-reverse-proxy/plan.md`
- Research: `.legion/tasks/authenticated-reverse-proxy/docs/research.md`
- Adversarial findings resolved here: `.legion/tasks/authenticated-reverse-proxy/docs/review-rfc.md`
- Current runtime/auth/session: `src/server.rs`, `src/http.rs`, `src/auth_mini.rs`, `src/db.rs`, `src/flight.rs`
- Current config/cookies/policy/JWT: `src/config.rs`, `src/cookies.rs`, `src/policy.rs`, `src/jwt.rs`
- Current deployment and tests: `README.md`, `.env.example`, `docs/production-deployment.md`, `examples/`, `scripts/`
- Historical decisions: `.legion/wiki/decisions.md`, `.legion/wiki/patterns.md`, `.legion/wiki/tasks/harden-mobile-session-lifecycle.md`
- Hyper streaming bodies: <https://docs.rs/hyper/latest/hyper/body/index.html>
- Hyper upgrades: <https://docs.rs/hyper/latest/hyper/upgrade/index.html>
- Hyper HTTP/1 client connection: <https://docs.rs/hyper/latest/hyper/client/conn/http1/index.html>
- hyper-util server upgrades: <https://docs.rs/hyper-util/latest/hyper_util/server/conn/auto/struct.Http2Builder.html#method.serve_connection_with_upgrades>
- Hyper 1.10.1 request/response framing source consulted for normalization behavior: <https://docs.rs/hyper/1.10.1/src/hyper/proto/h1/role.rs.html>
