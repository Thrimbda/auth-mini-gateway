# RFC: HTTP/2 downstream and fixed-upstream proxying

> **Profile:** RFC Heavy
> **Status:** Approved - `review-rfc` and `review-change` PASS
> **Created / updated:** 2026-07-16

## Executive summary

- Add HTTP/1.1 and HTTP/2 prior-knowledge service on the existing cleartext listener and authenticate every valid, service-delivered HTTP/2 stream independently.
- Add `UPSTREAM_PROTOCOL=auto|http1|http2`. Missing/empty means `auto`.
- HTTPS accepts `auto` and defaults to it. Cleartext proxy mode rejects `auto`, including the omitted default, at startup.
- HTTPS `auto` offers ALPN `[h2,http/1.1]`; selected `h2` is authoritative. No-ALPN or `http/1.1` selects HTTP/1.1. Forced HTTP/2 and explicit h2c fail closed.
- Before publishing an HTTP/2 sender, a bounded plaintext-I/O observer on the **same connection** must prove initial SETTINGS/ACK, then continue frame-boundary scanning for later revocation of `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
- Keep one combined eight-owner pool: exclusive HTTP/1 owners and shared HTTP/2 generations. `U` remains one permit per application exchange/stream, not per TCP connection.
- A fresh H2 creator reserves its sender clone and stream permit before pool publication; WebSocket capability is checked only after candidate selection and can never downgrade selected H2 to H1.
- The downstream 10-second initial race is removed after the first complete request head, then the same connection future continues without that deadline.
- For H2 CONNECT whose Content-Length parses as one consistent value greater than zero, pinned Hyper calls `send_reset(INTERNAL_ERROR)` internally and immediately completes the connection; EOF/close is guaranteed, wire RST delivery is optional, and the request reaches neither auth nor upstream.
- Build HTTP/2 scheme/authority only from `UpstreamBase`; never allow downstream Host, authority, URI, forwarding data, or credentials to affect routing, TLS, or pooling.
- Support all four RFC 6455/RFC 8441 WebSocket bridges, but no ordinary CONNECT or other extended protocol.
- Do not retry, replay, or change protocol after the one `send_request` call.
- Preserve the current FD formula, streaming/backpressure, strict TLS identity, per-stream auth, header sanitation, and full-lifetime D/U ownership.
- Roll back upstream HTTP/2 by setting `UPSTREAM_PROTOCOL=http1` and restarting; downstream HTTP/2 remains enabled. A downstream parser/stream/RFC 8441 regression requires old-binary rollback. No data migration or capability cache exists.

## 1. Context and evidence

The current implementation is HTTP/1.1-only: `src/server.rs` uses `http1::Builder`, `src/proxy.rs` uses `http1::handshake`, rewrites every request to HTTP/1.1, and pools one exclusive sender/driver owner per exchange. The current D/U/R and FD invariants are already explicit:

```text
D = accepted downstream TCP connections
U = authenticated application exchanges
R = blocking domain resolutions
proxy FD budget = D + U + 8 pooled owners + 1 listener + 512 reserve
```

Relevant evidence is indexed in `docs/research.md`. In particular:

- `hyper_util::server::conn::auto::Builder` supports HTTP/1 plus HTTP/2 prior knowledge and HTTP/1 upgrades, but its 24-byte protocol detector has no timeout.
- Hyper HTTP/2 `SendRequest` is cloneable. Its `ready()` only proves that the dispatch channel is open; the client handshake does not wait for the server's initial SETTINGS.
- A polled Hyper HTTP/2 `Connection` exposes the effective extended-CONNECT setting during initial proof, but pinned h2 0.4.14 accepts later `SETTINGS_ENABLE_CONNECT_PROTOCOL` changes without failing the connection; live eligibility therefore cannot rely on Hyper or an immutable snapshot alone.
- hyper-rustls/Rustls expose authoritative TLS ALPN while retaining normal root, SNI, and certificate checks.
- Hyper maps successful HTTP/2 CONNECT streams to `Upgraded`, allowing the existing opaque bidirectional bridge to remain the tunnel data path.
- Hyper 1.10.1 intercepts an H2 CONNECT only after `content_length_parse_all` yields one syntactically valid, consistent value greater than zero. It calls `send_reset(INTERNAL_ERROR)` internally and immediately completes the serving connection; a queued reset might not flush before EOF. Gateway validation/auth cannot observe this form.
- RFC 9113 does not define safe in-band discovery for a cleartext origin. The user therefore resolved cleartext selection as explicit prior knowledge only.

No current-library blocker remains. The pre-service CONNECT rejection is compatible with the stable contract because it is fail-closed with zero upstream dispatch, the contract specifies no exact status for malformed protocol frames, and replacing/patching Hyper is prohibited. The same-connection SETTINGS proof plus ongoing bounded monitor remains implementable with the pinned APIs and needs no new direct dependency.

## 2. Goals

1. Serve downstream HTTP/1.1 and HTTP/2 prior knowledge on one listener, including HTTP/1 upgrades and RFC 8441.
2. Select an actual upstream protocol before application dispatch without probing, replay, or protocol fallback.
3. Multiplex HTTP/2 safely while retaining fixed-origin routing, per-stream authentication, backpressure, and bounded resources.
4. Make authority, cookie, hop-header, identity, forwarding, and tunnel translation deterministic across all four protocol combinations.
5. Preserve existing HTTP/1 behavior, E2Es, TLS verification, and executable rollback.

## 3. Non-goals

- HTTP/3, QUIC, WebTransport, generic CONNECT, arbitrary tunnels, h2c Upgrade discovery, or application-request probing.
- Dynamic/multi-origin routing, gRPC-specific policy, request replay, GOAWAY retry, or cross-connection capability caching.
- Production rollout, infrastructure changes, new persistent state, or unrelated auth/session/DNS/TLS refactors.

## 4. Hard constraints

- Only Cargo feature activation is allowed: add Hyper HTTP/2, hyper-rustls HTTP/2, and hyper-util `server-auto` support. Do not add a direct crate unless implementation proves these APIs insufficient and returns to design review.
- Keep the first successful TCP connection authoritative: TLS, ALPN, HTTP handshake, SETTINGS, and send failures never advance to another resolved address.
- A request body is neither polled nor moved into a send future until protocol/owner selection and any HTTP/2 SETTINGS gate have succeeded.
- Exactly one upstream `send_request` call is allowed for an admitted exchange.
- A gateway-observed downstream stream or upstream stream failure never aborts a shared HTTP/2 connection. The reviewed later-SETTINGS revocation is a connection-level capability violation, not a stream failure, and intentionally retires that generation. Hyper protocol-layer failures remain outside gateway control; the accepted pinned case is CONNECT whose Content-Length parses consistently to a value greater than zero, for which connection completion prevents a sibling guarantee.
- Existing root loading, SNI derivation, hostname/IP SAN verification, D/U/R ordering, and sanitized process exits remain unchanged.

## 5. Definitions

- **Configured mode:** `auto`, `http1`, or `http2` from startup configuration.
- **Actual protocol:** HTTP/1.1 or HTTP/2 proven by the live connection (ALPN or explicit cleartext prior knowledge plus handshake).
- **Generation:** one physical HTTP/2 connection, its master sender, driver/transport-close witness, immutable initial SETTINGS snapshot, shared live capability/driver gate, local stream semaphore, and monotonic ID.
- **Application exchange:** one ordinary request/response stream, SSE stream, or WebSocket tunnel. It owns exactly one U permit.
- **Dispatch boundary:** the sole call to protocol-specific `send_request`; failures after this boundary are never retried.

## 6. Proposed design

### 6.1 Configuration and Cargo features

Add one enum-valued environment variable:

| Setting | Exact semantics |
|---|---|
| `UPSTREAM_PROTOCOL` missing or empty | `auto` |
| `auto` | Legal for HTTPS; illegal for cleartext proxy mode |
| `http1` | Force HTTP/1.1; send no HTTP/2 preface or discovery traffic |
| `http2` | Force HTTP/2; HTTPS requires ALPN `h2`, cleartext uses h2 prior knowledge |
| Any other spelling, case, whitespace, or alias | Startup error `upstream_protocol_invalid` |

Validation occurs after `UPSTREAM_URL` parsing:

- Adapter mode has no upstream and accepts any valid enum value without using it. This keeps adapter/binary rollback possible when the variable remains set.
- `http://...` plus effective `auto` is a startup error `upstream_protocol_cleartext_auto`. This includes an omitted or empty variable.
- `https://...` plus omitted/empty uses `auto`.
- Errors retain only the fixed class in `SanitizedExit`; they never echo the environment value or URL.

Cargo changes are limited to existing dependencies:

```text
hyper:         add feature http2
hyper-rustls:  add feature http2
hyper-util:    add feature server-auto (retaining tokio)
```

Any lockfile additions caused transitively by those existing optional features are mechanical; there is no new direct dependency. Existing `rand`, `base64`, `sha1`, `bytes`, Tokio, and standard-library APIs cover the observer and WebSocket translations.

### 6.2 Downstream server, limits, and per-stream admission

Replace the per-socket HTTP/1 builder with `hyper_util::server::conn::auto::Builder<TokioExecutor>` and `serve_connection_with_upgrades`:

- HTTP/1: retain keep-alive, `max_headers(100)`, invalid-header rejection, the Tokio timer, and the 10-second header-read timeout.
- HTTP/2: explicitly set `max_header_list_size(16_384)`, a finite `max_concurrent_streams`, and `enable_connect_protocol()`.
- D remains acquired before `accept()` and owned until the physical downstream socket and all upgrade clones end.

The auto detector must not create a slow-preface gap, and the initial deadline must never become a connection-lifetime timeout. Implement it as one explicit phase race:

1. Create a latched per-connection `first_complete_head` signal. The `Service::call`/`service_fn` closure sets it synchronously before constructing or returning the async handler future; Hyper invokes that closure only after a complete H1 or H2 request head exists.
2. Pin the single `serve_connection_with_upgrades` future and race **that same future**, the latched signal, and the 10-second sleep.
3. Connection completion wins normally. If the signal wins, drop the initial sleep and continue awaiting the same pinned connection future with no initial deadline. If the sleep wins, recheck the latch to resolve a simultaneous signal; close only when it is still unset.
4. Never wrap the whole connection future in `timeout`, never restart the connection future, and never start a second ten-second window. HTTP/1 still retains its builder's per-header timeout after this initial phase.

Thus a 23-byte matching HTTP/2 preface followed by an HTTP/1 mismatch cannot gain another window, while timely keep-alive, SSE, and upgraded streams can outlive the initial deadline.

HTTP/2 introduces request concurrency not counted by D. Add no capacity environment variable; derive global stream admission from existing limits:

- Adapter mode: at most D active downstream HTTP/2 streams.
- Proxy mode: at most U non-owned/proxy HTTP/2 streams and at most `D-U` gateway-owned HTTP/2 streams. Existing validation guarantees the latter is at least 16.
- Advertise a finite per-connection maximum of `min(D, u32::MAX)`; the two global semaphores enforce the aggregate/class limits across connections.
- Acquire the appropriate downstream stream lease at service entry with no waiter. Saturation returns the existing fixed service-capacity `503`; on HTTP/2 it emits no `Connection` header and affects only that stream.
- Hold the stream lease through both request and response halves, or through the complete tunnel. Proxy traffic cannot consume the gateway-owned reserve.

Route classification, syntax checks, cookie extraction, auth, allowlist evaluation, and U admission run independently for every valid HTTP/2 request delivered to `Service::call`. No identity or auth result is stored on the connection. Mixed allowed, anonymous, forbidden, gateway-observed malformed, and gateway-owned streams on one TCP connection remain isolated.

**Pinned Hyper pre-service boundary:** this exception applies only when Hyper 1.10.1's `content_length_parse_all` accepts the H2 CONNECT Content-Length field set as one syntactically valid, consistent value `n > 0` (including consistently repeated values). Hyper then calls `send_reset(INTERNAL_ERROR)` internally and immediately completes the connection-serving future. The stable external result is connection completion/EOF; `RST_STREAM(INTERNAL_ERROR)` is observable only if the queued frame is flushed and is not guaranteed on wire. The gateway cannot emit its fixed `400`, run auth, acquire service-level stream/U leases, or guarantee sibling survival for this form. Required behavior is zero gateway auth and zero upstream dispatch; no gateway HTTP status is promised.

Conflicting, syntactically malformed, or otherwise unparseable Content-Length fields do not enter this branch. They remain pinned Hyper protocol-layer handling and are not reclassified by this RFC. Patching Hyper or replacing the H2 server stack solely to intercept either class is outside dependency/scope constraints. All handshake forms delivered to service retain gateway validation and sibling-isolation requirements.

### 6.3 Upstream transport and authoritative protocol selection

Resolution, TCP, and TLS retain one shared absolute 10-second connect deadline and the existing first-TCP-success rule.

| Origin / mode | Offer or wire action | Authoritative result |
|---|---|---|
| HTTPS `auto` | ALPN `[h2,http/1.1]` | `h2` -> HTTP/2 gate; `http/1.1` or no ALPN -> HTTP/1.1; anything else -> `502` |
| HTTPS `http1` | Existing HTTP/1-only TLS path; never offer h2 | HTTP/1.1; no HTTP/2 handshake |
| HTTPS `http2` | ALPN `[h2]` | Only selected `h2` succeeds; no/other ALPN -> `502` |
| Cleartext `http1` | HTTP/1 handshake directly | HTTP/1.1; zero probe/preface bytes |
| Cleartext `http2` | HTTP/2 prior-knowledge preface directly | HTTP/2 only after the SETTINGS gate |
| Cleartext `auto` | No runtime action | Rejected at startup |

For HTTPS `auto`, ALPN `h2` is final: HTTP/2 handshake, SETTINGS, timeout, or connection failure returns `502` and never attempts HTTP/1. Forced HTTP/2 behaves the same. No ALPN and explicit `http/1.1` are normal HTTP/1 selections only in `auto`, not error fallback.

The connector URI and Rustls server name continue to come only from canonical `UpstreamBase`; resolved addresses, inbound authority, Host, and forwarding fields cannot rewrite SNI or certificate identity.

### 6.4 Same-connection HTTP/2 SETTINGS proof

Hyper's HTTP/2 handshake returns before server SETTINGS. `SendRequest::ready()` is therefore insufficient. Every new HTTP/2 connection uses this gate before the sender is cloned, pooled, or otherwise exposed:

1. Inspect TLS ALPN, if any, then wrap the resulting **plaintext HTTP I/O** (outside TLS) in `H2ProofIo`; the same wrapped I/O is handed to Hyper's HTTP/2 handshake.
2. Keep the returned `SendRequest` private. Poll the returned Hyper `Connection` while Hyper's codec drives this same transport. No request exists, so no application stream/body can be emitted.
3. The inbound observer requires the first server frame to be a non-ACK SETTINGS frame on stream 0. It parses the nine-byte frame header, requires the initial payload to be at most 16,384 bytes and divisible by six, and consumes each setting through one fixed six-byte pair scratch rather than retaining the whole payload. Known fields are checked exactly: server-sent ENABLE_PUSH is illegal; INITIAL_WINDOW_SIZE is at most `2^31-1`; MAX_FRAME_SIZE is `16_384..=16_777_215`; ENABLE_CONNECT_PROTOCOL is 0 or 1; unconstrained `u32` fields and unknown IDs are accepted. For duplicates, the last value wins. Missing ENABLE_CONNECT_PROTOCOL means false; missing MAX_CONCURRENT_STREAMS means unbounded. The observer records both initial effective values.
4. The outbound observer skips the exact client connection preface and parses frame boundaries until it sees Hyper's complete zero-length stream-0 SETTINGS frame with ACK set. Seeing bytes merely read from the peer is not enough.
5. The wrapper handles arbitrary read/write fragmentation and coalescing. `poll_write_vectored` accounts only the first `n` bytes actually accepted across slices in order; `poll_write` uses the same parser. Pending/error and partial writes never advance unseen bytes, so non-vectored TLS writes are equally valid.
6. After the ACK observation, require the Hyper connection still pending/live and the sender not closed. If the accepted initial snapshot is true and the shared state remains `LiveEnabled`, require Hyper's `is_extended_connect_protocol_enabled()` to be true. An initial false snapshot remains `LiveDisabled` even if a coalesced later SETTINGS has already made Hyper's current accessor true; ordinary H2 remains allowed, but that accessor change never upgrades gateway eligibility. Any observed revocation is terminal. Use the observer's initial MAX_CONCURRENT_STREAMS snapshot for the generation limit.
7. Race the gate against Hyper connection completion and the original absolute connect deadline. Completion, malformed input, a required enabled-state mismatch, revocation, EOF, or timeout drops the private sender and retires this same connection; it returns `502` without a request or fallback.
8. Derive the generation limit `L = min(U, 100, initial peer max-send-streams)`. While the sender and generation are still private, clone the sender for the creating exchange and acquire one local stream permit from the new `L`-permit semaphore. This reservation fixes the creator's H2 candidate before any pool visibility.
9. If `L == 0`, sender cloning/liveness fails, or the private permit reservation cannot succeed, publish nothing; fail with pre-dispatch `502` and retire this same connection with no owner, address, or protocol fallback.
10. Only after the creator owns both clone and permit may the generation become pool-visible. The published semaphore exposes exactly `L-1` remaining permits. If no owner slot is free, keep the generation private to the creator and retire it after that exchange. Continue the still-same Hyper connection driver in its owned task.

The fixed-cursor parser starts with the initial proof and, after proof, the same plaintext I/O wrapper transitions—not detaches—to ongoing inbound frame scanning. It must consume any later frames coalesced after the initial SETTINGS in that same read rather than discarding the remainder. Hyper remains the protocol stack and receives the same bytes; the observer only maintains framing/capability evidence.

Ongoing parsing is allocation-independent from peer frame size:

- Keep a fixed 9-byte frame-header scratch, a `u32` remaining-payload counter (the wire length is 24-bit), and, only while inside a non-ACK stream-0 SETTINGS frame whose length is divisible by six, one fixed 6-byte setting-pair scratch plus the last ID `0x8` value seen in that frame.
- Parse every newly read plaintext slice before returning it to Hyper. Arbitrary fragmentation and coalescing advance those fixed cursors. For every non-SETTINGS frame—including a legal payload up to `16_777_215` bytes—decrement/skip the remaining count without copying payload bytes. For SETTINGS, interpret pairs incrementally and apply only the frame's final ENABLE_CONNECT_PROTOCOL value when the whole frame is observed. ACK, malformed, wrong-stream, invalid-value, and other protocol semantics remain Hyper's responsibility.
- Never allocate a buffer proportional to payload length, retain DATA/HEADERS bytes, decode HPACK, or alter the byte stream. The ongoing scanner's retained wire data is at most 15 bytes plus scalar counters/state.

The observer and generation share `Arc<GenerationControl>` created before handshake and containing the exact monotonic generation ID, the existing atomic selectability bit, a short-held `std::sync::Mutex<GenerationState>`, and a Tokio `watch` retirement signal. The state machine is `Proving | LiveDisabled | LiveEnabled | Revoked | Retiring | Closed`:

- Initial snapshot false installs `LiveDisabled`; later `1` is deliberately ignored for eligibility, so ordinary H2 remains usable but RFC 8441 stays disabled.
- Initial snapshot true installs `LiveEnabled`. A later complete SETTINGS whose effective ID `0x8` value is `0` atomically changes `LiveEnabled -> Revoked`. This RFC does not rely on h2 0.4.14 to reject the illegal 1->0 transition.
- Revocation stores the existing selectability bit false while holding the gate, then releases it and publishes the persistent `watch` retirement signal. No pool lock, await, callback, or driver join occurs while holding the state mutex. The supervisor selects that signal against the owned Hyper connection future, changes only the matching generation ID to a retiring slot, drops the master sender/connection future, and completes existing transport-close accounting. The I/O wrapper also returns a fixed connection error on subsequent reads/writes once revoked so Hyper's codec cannot keep the physical connection live indefinitely.
- If revocation is observed before creator publication, the creator's final publication check sees `Revoked`, publishes nothing, and retires the same connection pre-dispatch. A stale observer/notification can never evict a replacement because retirement is exact-ID.

The connection-level retirement intentionally fails any in-flight ordinary requests, WebSockets, and siblings on that generation. None is migrated, replayed, retried on H1, or moved to another generation. Their existing U/body/stream cleanup rules still apply. There is no detached origin capability cache and no probe/actual-connection TOCTOU.

### 6.5 Combined eight-owner pool and physical accounting

Use one pool with exactly eight owner slots shared by both protocols:

| Entry | Checkout/use |
|---|---|
| HTTP/1 idle owner | Remove exclusively; one sender/driver and one exchange |
| HTTP/2 live generation | Keep in the pool; clone its sender and acquire one generation stream permit |
| Retiring generation/owner | Not selectable, but still occupies its slot until driver/transport closure is observed |

Candidate selection and request-specific capability validation are separate, ordered phases:

1. Configured `http1` selects only an exclusive H1 owner/connection. Configured `http2` selects only H2. In HTTPS `auto`, reserve a live H2 sender clone and immediately available stream permit first; only when no H2 candidate was selected may selection reserve an idle H1 owner, then create a fresh connection. An H2 entry with no permit is not selected and creates no waiter.
2. Once a pooled or fresh H2 candidate is reserved, the actual protocol is fixed for that exchange. WebSocket eligibility is derived from the shared live gate, initialized by the immutable snapshot and rechecked at the enqueue linearization point in §6.6. `LiveDisabled`, `Revoked`, or later retirement returns pre-dispatch `502`, releases/cleans only that exchange reservation, and **must not inspect or fall through to an idle H1 owner**. A `LiveDisabled` generation remains usable for ordinary H2 traffic; a fresh generation remains pooled only if creator-safe publication and the shared-state check both succeed.
3. A fresh connection's ALPN/explicit mode plus the creator reservation in §6.4 fixes its candidate. HTTPS-auto ALPN h2 remains authoritative even when the setting is absent; there is no fresh H1 fallback.

Therefore H1 may carry a WebSocket only when H1 was selected before any H2 candidate (or mode is explicitly `http1`), never as a capability downgrade from selected H2.

Each HTTP/2 generation has a fixed local semaphore of:

```text
min(U, 100, initial peer max-send-streams)
```

The constant 100 is a finite implementation cap and matches Hyper's conservative pre-SETTINGS send-stream assumption. A peer initial limit of zero prevents creator reservation, so that same unpublished connection retires with pre-dispatch `502`. Later peer reductions are still enforced by Hyper and never trigger replay. U remains the lower global bound across all generations, so no new capacity setting is needed.

On a pool miss, the creating exchange already owns U. After a fresh HTTP/2 gate succeeds, it first reserves its own sender clone and stream permit, then checks the shared generation state and inserts only the remaining capacity while it is still live. Preserve the current no-await ordering: the private Hyper connection is not polled between this check, pool insertion, and driver spawn, so later bytes cannot create a publication race and state/pool locks need not be nested. Any revocation already coalesced into the initial proof read is recorded and prevents publication. Publication can never let a second exchange steal the creator's permit or expose an already revoked generation. If no owner slot is free, the connection remains private to that exchange and retires after it; it does not evict a live owner. This permits bounded connection races without an unbounded queue.

Every generation receives a monotonic ID. Driver completion or a closed sender marks that ID non-selectable and replaces only the exact matching pool entry with a retiring placeholder. Late errors from an old stream may not remove or mutate a replacement generation. A stream-level reset/error never aborts or retires the shared driver; only connection-level closure makes the generation unavailable to future streams. Existing siblings continue until their own EOS/error.

The FD proof remains unchanged:

```text
P = pool-owned live/retiring physical connections <= 8
A = unpooled or exclusive active physical connections <= U
upstream physical connections <= P + A <= 8 + U
required FDs = D + U + 8 + 1 + 512
```

A retiring pooled connection keeps its slot until transport close. An unpooled/HTTP1-active connection keeps its accounting U through driver/transport close. Moving a connection into a pool slot is atomic before changing accounting. Shared HTTP/2 streams add U and stream permits, not FDs.

### 6.6 Dispatch, streaming, and lease lifetime

U is acquired after `Allow` and before pool selection, exactly as today. Selection yields one private enum:

```text
H1 { exclusive owner }
H2 { generation ID, sender clone, local stream permit, initial SETTINGS snapshot, shared GenerationControl }
```

Build and sanitize the complete protocol-specific request and carry a typed `Ordinary | ExtendedConnect` dispatch kind before taking the generation mutex. The sole H2 enqueue is then a synchronous linearization section:

1. Lock the selected generation's `GenerationState` immediately before dispatch. Ordinary H2 is allowed in `LiveDisabled` or `LiveEnabled`; WebSocket Extended CONNECT is allowed only in `LiveEnabled`. `Revoked | Retiring | Closed` rejects every new dispatch.
2. While still holding that same mutex, emit the dispatch-selection event and call Hyper's synchronous `send_request(request)` exactly once. This call only enqueues/returns its response future; do not await or poll the body while locked.
3. Release the mutex before awaiting the response future or performing any body, upgrade, cleanup, pool, or driver work. Mutex poisoning is fail-closed and triggers exact-generation retirement.

This mutex is the candidate-versus-revocation linearization primitive. If the observer's 1->0 transition locks first, the WebSocket path returns pre-dispatch `502` with no H1 fallthrough or send. If enqueue locks first, that one stream is enqueued before revocation; the later transition retires the whole generation, and the stream/siblings fail normally with no retry or migration. A selected candidate that otherwise fails capability or liveness cannot reopen selection. GOAWAY, REFUSED_STREAM, reset, stale close, SETTINGS revocation, ALPN, handshake, or send failure never selects another owner, connection, address, or protocol.

Bodies remain frame-streamed through Hyper flow control; there is no collection, speculative read, or application buffer. Trailers retain current drop behavior. Use a two-half exchange latch that owns U plus downstream/upstream stream permits and protocol owner state:

- **Request half done:** upstream upload reached EOS, or early-final/cancellation has caused the wrapped body and Hyper body-pipe ownership to be dropped.
- **Response half done:** the downstream-facing response body reached EOS, errored, or was dropped after canceling its one upstream stream.
- Release U/stream permits, or park an HTTP/1 owner, only after both bits are terminal.
- A clean HTTP/1 exchange is reusable only after both halves finish. Early-final HTTP/1 remains non-reusable and closes the downstream when unread bytes remain.
- Early-final HTTP/2 cancels only that upload/stream; the generation driver and siblings remain alive.
- SSE keeps the response half and all leases until EOS/drop.
- Cancellation-safe cleanup relays unchanged ownership; it never returns permits before body/driver observation.

This closes the HTTP/2-specific gap where response headers can arrive while Hyper still owns the request body task.

### 6.7 URI, authority, Cookie, and header rules

At ingress derive a non-routing `PublicAuthority`:

- HTTP/1 requires exactly one Host, retaining current behavior.
- Ordinary HTTP/2 requires URI `:scheme` (`http` or `https`), `:authority`, and a slash-leading path/query. A regular Host is optional only when its bytes exactly match `:authority`; mismatch/repetition is `400`. The URI authority is the public authority.
- RFC 8441 requires `:scheme`, `:authority`, and slash-leading `:path`, and forbids a regular Host.
- These values may affect only validation, return path, preserved HTTP/1 Host, and regenerated `X-Forwarded-Host`; they never affect DNS/TCP/TLS/pool selection.

Protocol-specific upstream targets are exact:

- HTTP/1: origin-form composed path, HTTP/1.1, and the current external/public Host.
- HTTP/2: full URI scheme and authority from configured `UpstreamBase`, composed path, HTTP/2, and no regular Host. Hyper emits the corresponding pseudo-fields.

For HTTP/2 ingress, combine repeated Cookie fields in wire order with `"; "` only for gateway auth. An opaque/malformed value is `400`. Remove every Cookie field before upstream forwarding. HTTP/1 cookie behavior remains compatible.

For every protocol pair, remove connection-nominated fields and fixed hop fields; Cookie, Authorization, Proxy-Authorization, Forwarded, X-Real-IP, Expect, all inbound `X-Forwarded-*`, and all inbound `X-Auth-Mini-*`. Reinject only verified identity and canonical `X-Forwarded-For`, configured public proto, and `PublicAuthority` as `X-Forwarded-Host`. Responses continue to remove hop fields, forged identity, gateway cookies, unsafe framing, and H1-only fields when the downstream is HTTP/2. Generated HTTP/2 errors/responses never contain `Connection`, `Upgrade`, `Keep-Alive`, `Transfer-Encoding`, or proxy hop fields.

### 6.8 RFC 6455 / RFC 8441 WebSocket handling

For CONNECT requests delivered to gateway service, classify before authentication/upstream contact:

- HTTP/1 CONNECT and HTTP/2 CONNECT without `:protocol` are ordinary CONNECT -> fixed `405`.
- Any extended protocol other than exact `websocket` -> fixed `405`.
- A gateway-observed malformed WebSocket handshake -> fixed `400`. A consistently parsed `Content-Length > 0` H2 CONNECT never reaches this classifier and follows the pinned Hyper boundary in §6.2; conflicting/malformed field parsing remains Hyper protocol handling.
- Only a valid WebSocket proceeds to normal per-stream authentication and U admission.

Inbound HTTP/1 validation remains strict: GET/HTTP/1.1, one `Upgrade: websocket`, Connection token `upgrade`, empty body, exact version `13`, one canonical 16-byte base64 key, valid offered protocols/extensions, and no nominated handshake fields.

Inbound HTTP/2 validation for service-delivered requests requires CONNECT/HTTP/2, Hyper's single `Protocol("websocket")`, scheme/authority/path, exact version `13`, empty request body, absent-or-zero Content-Length, and valid offered protocols/extensions. Host, Connection, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Accept, transfer coding, and other H1 handshake/hop fields are forbidden. Origin and validated Sec-WebSocket-Protocol/Extensions remain end-to-end opening-handshake fields. A syntactically valid, consistently parsed non-zero Content-Length is rejected by the pinned Hyper branch before this validator; conflicting/malformed fields remain Hyper protocol handling.

Translation/response rules are:

| Downstream -> upstream | Upstream request | Required upstream success | Downstream success |
|---|---|---|---|
| h1 -> h1 | GET Upgrade; reuse client key | Exact `101`, valid Upgrade/Connection/Accept | Exact `101`; validated accept and selections |
| h1 -> h2 | CONNECT + `Protocol("websocket")`; no H1 hop/key fields | Exact `200`; no H1 hop/accept fields | Synthesize exact `101` and Accept from the original client key |
| h2 -> h1 | GET Upgrade; generate 16 random bytes with `OsRng` and a canonical key | Exact `101`; validate Accept against generated key | Exact `200`; strip Connection/Upgrade/Key/Accept |
| h2 -> h2 | CONNECT + `Protocol("websocket")`; no H1 hop/key fields | Exact `200`; no H1 hop/accept fields | Exact `200`; no H1 hop/key fields |

An H2 upstream request is legal only when that exact, already-selected generation is `LiveEnabled` at the synchronous enqueue linearization point; the immutable initial snapshot seeds that state but is not the sole check. Any other state is `502` with no H1 fallthrough. Randomness failure in h2->h1 is a pre-dispatch fixed `500`. Successful responses may select at most one offered subprotocol; selected extension names/syntax must be valid and offered. Any status/header/selection mismatch is `502` before a tunnel is exposed.

For all four paths, obtain both Hyper `OnUpgrade` handles before returning success, spawn one guarded opaque `copy_bidirectional` bridge, and retain D, U, downstream H2 stream admission, upstream H2 stream permit, and any exclusive owner through complete tunnel EOF/error/cancellation. Drop upgraded stream I/O before leases. An H2 tunnel reset affects only its stream, never sibling streams or the generation driver.

Hyper creates upstream `Upgraded` I/O for an H2 CONNECT `200` before gateway validation of regular response fields. Immediately move its `OnUpgrade` plus U and every applicable stream lease (both downstream and upstream for h2->h2) into a rejected-upgrade guard before validating those fields. If the `200` is malformed (forbidden H1 field, invalid subprotocol/extension, or other handshake mismatch), return `502`, but let cancellation-safe cleanup await/take and drop/reset that upgraded I/O before releasing any lease. This cleanup is stream-local: it does not mark the generation stale, abort the shared driver, or disturb siblings.

### 6.9 Executable error and fallback semantics

| Point | Result | Retry/fallback and ownership |
|---|---|---|
| Invalid protocol config / cleartext auto | Sanitized startup failure | No listener or traffic |
| Downstream H2 stream admission, U, or R saturation | Existing fixed `503` + `Retry-After: 5` | No upstream dispatch/body poll; no H1 hop header on H2 |
| H2 CONNECT with Content-Length consistently parsed as `n > 0` | Hyper internally calls `send_reset(INTERNAL_ERROR)` then immediately completes the connection; required EOF/close, optional wire RST, no gateway HTTP status | Before service/auth/U/upstream; sibling survival is not guaranteed |
| Gateway-observed invalid target/header/authority/Cookie/WS | `400`; unsupported CONNECT/protocol `405` | Before upstream; existing auth ordering as specified above |
| DNS/TCP/TLS/forced-ALPN/H2 handshake or SETTINGS gate failure | `502` | Zero `send_request`; no protocol/address fallback after first TCP success |
| Selected H2 lacks RFC 8441 setting | `502` | Zero upstream stream; candidate selection stays closed and idle H1 is untouched |
| Ready/liveness failure before dispatch | `502` | Zero `send_request`; retire exact owner/generation only |
| Later SETTINGS revokes accepted ENABLE_CONNECT_PROTOCOL `1->0` | Pre-enqueue WebSocket gets `502`; otherwise connection-level failure | Atomically make exact generation non-selectable, cancel/retire driver, fail in-flight siblings normally; no H1 fallback, migration, or replay |
| Send/GOAWAY/REFUSED_STREAM/reset after dispatch, before response head | `502` | Exactly one send; no replay/fallback; invalidate future use only if connection-level |
| Failure after a downstream response head/body began | End/reset only that downstream stream/connection | Never synthesize a second response; leases finish cleanup |
| Invalid H1 `101` tunnel response | `502` | No downstream tunnel; retire the exclusive H1 owner |
| Malformed H2 `200` tunnel response | `502` | Rejected-upgrade guard drops only that upgraded stream before U/stream-lease release; generation and siblings remain live |
| Gateway-observed or upstream HTTP/2 stream failure | Stream error | Siblings continue; generation retires only on connection-level closure; excludes the pinned pre-service Hyper rejection |

Existing renewal-cookie behavior remains where a generated response is still deliverable. Error logs use allowlisted classes only and never include raw library errors, URLs, authorities, request data, or credentials.

## 7. Alternatives considered

### A. Same-connection bounded SETTINGS/ACK observer — selected

- Proves Hyper processed the initial peer SETTINGS before sender publication.
- Uses the real connection, preserves TLS/ALPN identity, and avoids request replay or TOCTOU.
- Costs one fixed-cursor live wire observer, a short-held generation gate, and an explicit retirement witness.

### B. Trust Hyper handshake or `SendRequest::ready()`

- Simpler, but both can succeed before peer SETTINGS. It would permit application dispatch before h2 proof and cannot safely snapshot RFC 8441 capability. Rejected.

### C. Probe one connection and send on another

- Keeps the application body off the probe but introduces backend/connection TOCTOU and a detached capability cache. Rejected.

### D. Optimistic cleartext auto or h2c Upgrade discovery

- The preface is not side-effect-free discovery, and OPTIONS/Upgrade is an application request. Both violate the resolved contract and RFC 9113 prior-knowledge model. Rejected.

### E. Add a direct h2 transport/dependency

- Could expose lower-level SETTINGS state or override the pre-service consistently parsed non-zero-length CONNECT behavior, but duplicates Hyper translation/upgrade handling and expands ownership/security scope. The stable contract does not require that override, so patching/replacing the stack remains rejected; a future exact-status, guaranteed wire reset, or sibling-survival requirement for that wire form would return to design review.

## 8. Migration, rollout, and rollback

### Migration

No database, cookie, session, or wire-persistent migration exists. The only compatibility change is intentional: an existing cleartext `UPSTREAM_URL` deployment must add `UPSTREAM_PROTOCOL=http1` (rollback-compatible) or explicit `http2`; omission now fails startup.

### Rollout

1. Land feature/config/downstream support with startup and protocol-fixture tests.
2. Land same-connection proof/ongoing observer, protocol-aware pool, streaming/lifetime, and no-replay tests.
3. Land authority/header and all WebSocket translations, then run full regression/E2E gates.
4. Do not enable production in this task. A later rollout should first pin current cleartext deployments to explicit `http1`, then opt selected HTTPS origins into `auto` or explicit h2c only with fixture proof.

### Rollback

- Trigger on unexplained 502/stream-reset increase, sibling-stream loss outside the pinned pre-service rejection or explicit later-SETTINGS retirement, auth/header regression, tunnel failure, or resource/FD deviation.
- **Upstream-only rollback:** set `UPSTREAM_PROTOCOL=http1`, restart, and verify connection/dispatch protocol logs plus HTTP/upload/SSE/WebSocket smoke tests. This sends no upstream h2 traffic and clears all in-memory generations, but it deliberately leaves downstream auto-H1/H2 serving, stream admission, and RFC 8441 parsing enabled.
- **Full downstream rollback:** for downstream auto-detection, slow-preface, stream-partition, RFC 8441 regressions, or operational rejection of the pinned pre-service CONNECT connection-close behavior, deploy the previous HTTP/1-only binary using the existing maintenance/old-binary procedure. The old binary ignores `UPSTREAM_PROTOCOL`, disables the new downstream parser and H2 streams, and uses its existing upstream H1 path. `UPSTREAM_PROTOCOL=http1` alone cannot change this downstream Hyper behavior.
- Adapter rollback remains the separate `UPSTREAM_URL`-unset maintenance path.
- No data repair, cache invalidation, or session change is required.

## 9. Observability

Emit one secret-free event after each physical upstream connection is selected and, for h2, passes the SETTINGS gate:

```text
event=upstream_protocol_selected
configured=auto|http1|http2
transport=tls|cleartext
protocol=http1|http2
source=alpn|forced
generation=<numeric local id, h2 only>
extended_connect=true|false   # h2 only
```

Immediately before the sole `send_request` call, emit exactly one per-attempt event:

```text
event=upstream_dispatch_selected
protocol=http1|http2
generation_present=true|false
generation=<numeric H2 generation id, or 0 for H1>
```

This event identifies the actual pooled/fresh protocol used by each dispatch without method, path, authority, identity, or request correlation data. No event is emitted when capability/liveness fails before dispatch.

Failure events may include only `stage=dns|tcp|tls|alpn|http_handshake|settings|dispatch|stream|driver`, actual protocol if known, and fixed outcome/class. Do not log URL, authority, IP, SNI text, ALPN bytes, method/path, headers, cookies, tokens, identity, WebSocket key, or body data. Existing capacity and driver-retirement events remain. No metrics subsystem or alert configuration is added in this repository; rollout analysis uses event counts and fixture assertions.

## 10. Security and privacy

- **Authentication/authorization:** every valid H2 stream delivered to gateway service executes the same independent auth and allowlist path. The pinned consistently parsed `Content-Length > 0` CONNECT form is rejected earlier by Hyper with zero auth; denied/malformed/capacity-rejected traffic cannot contact upstream.
- **SSRF/routing:** only immutable `UpstreamBase` controls scheme, authority, dial target, TLS identity, and pool membership.
- **Replay:** one dispatch call; no stale, GOAWAY, REFUSED_STREAM, SETTINGS-revocation, protocol, or address retry after dispatch. The shared gate linearizes revocation against WebSocket enqueue.
- **TLS:** native/injected roots, SNI, DNS/IP SAN checks, and first-TCP-success behavior remain strict.
- **Header/identity leakage:** browser credentials, cookies, forwarding claims, and forged identity are removed for both protocols; pseudo-fields are rebuilt rather than forwarded.
- **Resource exhaustion:** finite header lists, downstream stream partitions, per-generation upstream stream limits, global U, combined eight-owner pool, bounded SETTINGS parser, and existing deadlines/FD checks apply.
- **Tunnel scope:** only validated WebSocket RFC 8441 is admitted; authority never becomes a CONNECT destination. D/U/stream leases cover the full tunnel.
- **Secrets:** generated WebSocket keys are ephemeral, connection-local, and never logged or persisted. No new personal data is retained.

## 11. Verification strategy

### Focused unit/component evidence

- Exact config table, value-neutral startup classes, HTTPS omitted default, and cleartext omitted/empty `auto` rejection.
- Cargo feature compilation with no new direct dependency.
- Auto listener actual H1/H2 versions, H1 Upgrade, advertised extended CONNECT, 100-header/16-KiB limits, finite stream admission partitions, and fragmented/near-preface/header deadline failures. With an injectable short deadline, timely H1 and H2 first heads must disarm the initial race; H1 keep-alive/WebSocket Upgrade and H2 SSE/RFC 8441 WebSocket streams remain usable beyond twice that original deadline on the same connection future.
- A raw-frame/HPACK H2 fixture must bypass Hyper client's CONNECT validation. On one connection, a valid Extended CONNECT on stream 1 with no Content-Length is the control: it reaches `Service::call`/gateway classification and receives an H2 response while the connection remains open. On a fresh connection, the same valid block plus syntactically consistent `content-length: 1` must leave `Service::call`/auth hooks at zero, leave U/service-stream admission untouched, emit zero upstream hits/dispatch logs, and require connection-future completion plus EOF/close. A stream reset is optional; if observed, it must be stream 1 with `INTERNAL_ERROR`. The test requires neither a reset frame, fixed `400`, nor sibling survival.
- SETTINGS observer: fragmented/coalesced input, split and non-vectored/vectored partial writes, malformed/oversized/wrong-first frames, duplicate/unknown settings, ACK proof, timeout/EOF, and connection-completion races. Assert no application HEADERS/DATA before the initial gate.
- Ongoing scanner: feed later SETTINGS `1->0` with every split across the 9-byte header and 6-byte setting pair, coalesce it with adjacent frames, and precede it with a large legal non-SETTINGS payload delivered in chunks. Assert effective-last-value handling, fixed scratch/counter memory with no payload-sized allocation, and continued byte transparency to Hyper.
- Pool/generation state transitions, exact-ID stale invalidation, retiring-slot accounting, gateway-observed/upstream per-stream sibling survival, and the unchanged `D+U+8+1+512` FD formula. The pre-service Hyper rejection is tested separately and excluded from sibling assertions.
- Creator publication race: an initial peer max-stream value of one, barriers around reservation/publication, and two exchanges prove the creator owns its sender clone/only permit before visibility; the second exchange cannot acquire that generation or alter the creator's dispatch/fallback outcome.
- Candidate/capability order: a mixed auto pool containing an extended-CONNECT-ineligible H2 generation plus idle H1 selects/reserves H2, returns pre-dispatch `502`, leaves H1 untouched, and makes zero upstream dispatch calls.
- Later-revocation ordering uses barriers on the shared gate: (a) update-before-candidate marks generation G revoked, the WebSocket gets pre-dispatch `502`, idle H1 is untouched, and zero dispatch occurs; (b) candidate-before-update enqueues exactly once on G, then revocation retires G and fails that stream/controlled siblings without H1 fallthrough, migration, or replay.
- Pooled exact-ID retirement: a fragmented later `1->0` makes G immediately non-selectable, installs/keeps its retiring slot through transport close, and cannot remove replacement G+1 when stale completion/notification arrives. Initial-false plus later-1 remains ordinary-H2-capable but WebSocket-ineligible.
- Two-half latch tests prove U and both H2 stream permits remain until upload cleanup **and** response/tunnel EOS, including early final and cancellation.
- Malformed H2 CONNECT `200` cleanup is held behind a deterministic hook: U and both stream leases remain held until its `Upgraded` I/O drops/resets, while a sibling completes and the same generation remains reusable without another TCP connection.

### Protocol integration matrix

- Actual h1->h1, h1->h2, h2->h1, and h2->h2 preserve the required GET/POST/PUT/PATCH/DELETE methods and path/query. Use representative POST/PATCH cases for fixed/large/chunked-or-DATA upload, early-final, backpressure, and cancellation, and representative GET for streamed response/SSE; do not multiply every method by every streaming case.
- One downstream H2 TCP connection carrying parallel allowed, anonymous, forbidden, gateway-observed malformed, and gateway-owned streams; only allowed streams dispatch and those service-level outcomes preserve siblings. The consistently parsed non-zero-length CONNECT fixture is separate because Hyper closes it before service.
- One upstream H2 TCP connection multiplexing concurrent exchanges; exact U saturation/release, peer/local stream limits, and stream-local reset with live siblings. A later capability revocation is separately proven connection-level: all G siblings fail/clean up, but none migrate or replay and unrelated generations remain live.
- HTTPS auto h2, auto h1, auto no-ALPN h1, forced h1, forced h2 success, forced h2 ALPN failure, h2 SETTINGS failure, strict root/SNI/DNS-SAN/IP-SAN behavior, and no h2-to-h1 fallback.
- Cleartext explicit h1 emits no preface/probe; explicit h2c success and HTTP/1/malformed/timeout failure; cleartext auto startup rejection.
- POST/PATCH/streaming fixtures inject stale close, GOAWAY, REFUSED_STREAM, and reset before/after dispatch and prove at most one upstream dispatch and one body poll sequence.
- H2 split Cookie authentication; H1 Host compatibility; H2 authority/Host mismatch rejection; fixed H2 upstream pseudo-authority; credential, identity, forwarding, hop, response, and gateway-cookie sanitation.
- All WebSocket bridges h1->h1, h1->h2, h2->h1, h2->h2 with bytes in both directions; generated key and synthesized accept; exact upstream 101/200; setting absent; gateway-observed malformed protocol/scheme/path/version/key/headers; subprotocol/extensions; ordinary CONNECT; full D/U/stream lifetime. The pinned pre-service Content-Length branch is verified for fail-closed required EOF/connection close and zero upstream, with wire RST optional.
- Connection-selection and per-dispatch protocol logs have exact cardinality/protocol/generation fields and exclude injected cookie/token/key/authority markers.

### Regression gates

Run formatting, strict Clippy for all targets/features, full tests, and release build. Run all existing E2Es: `scripts/e2e-proxy-mode.sh`, `scripts/e2e-mode-switch.sh`, `scripts/e2e-old-binary-compat.sh`, and `scripts/e2e-wal-backup-restore.sh`; run `scripts/e2e-real-auth-mini.sh` when its pinned external fixture is available. Existing HTTP/1 integration outcomes remain mandatory, not replaced by the new matrix.

## 12. Milestones

1. **Protocol/config foundation:** Cargo features, enum validation, downstream auto serving, finite limits/admission, the first-head-only deadline race, and H1/H2 fixtures. Acceptance: startup/protocol, raw valid-control plus pinned pre-service CONNECT required-EOF/optional-reset evidence, and post-deadline keep-alive/SSE/Upgrade tests plus the existing H1 suite pass.
2. **Upstream ordinary traffic:** ALPN/h2c selection, initial SETTINGS proof plus ongoing monotonicity observer, creator-before-publication reservation, race-linearized candidate selection, combined pool, exact-generation retirement, two-half streaming ownership, required four-way method/representative-stream matrix, TLS, multiplexing, and no replay. Acceptance: peer-limit-one, later-SETTINGS ordering/exact-ID/bounded-parser, mixed-pool downgrade, capacity/FD/sibling, and existing streaming tests pass.
3. **Authority and tunnels:** protocol-specific URI/header rules, split Cookie auth, all four WebSocket translations, rejected-H2-upgrade cleanup, connection/dispatch secret-free logging, docs, full regression and E2Es. Acceptance: security matrix and required repository gates pass before `review-change`.

Each milestone must compile and run its focused tests; none may temporarily dispatch before SETTINGS proof or add fallback/replay.

## 13. Open questions

None blocking. Known pinned-library limitation: when H2 CONNECT Content-Length is syntactically valid and consistently parses as `n > 0`, Hyper calls internal `send_reset(INTERNAL_ERROR)` and completes before gateway service. Required external behavior is EOF/connection close, zero auth, and zero upstream; wire reset delivery, exact `400`, and sibling survival are unavailable. Conflicting/malformed Content-Length parsing remains Hyper protocol handling and is not part of this classification. This is accepted only because the stable contract requires fail-closed/no-upstream behavior, not an exact malformed-frame status or reset. If exact status, guaranteed reset, or sibling survival for this pre-service form becomes mandatory, the design is blocked and must use a reviewed Hyper patch/replacement rather than weakening other validation.

Any implementation finding that the continuous observer cannot preserve frame boundaries with fixed memory, that the shared gate cannot linearize enqueue against revocation, or that Hyper cannot provide the described same-connection ACK proof, gateway-observed stream isolation, or transport-close ownership must stop and return this RFC to review rather than adding a probe connection, fallback, or unreviewed transport stack.

## 14. Implementation notes

Expected areas are `src/config.rs`, `src/server.rs`, `src/proxy.rs`, capacity/FD assertions, `Cargo.toml`/lockfile feature resolution, operator docs, and `tests/proxy_integration.rs` fixtures. Keep protocol selection, request translation, pool ownership, and WebSocket translation as separate typed state transitions; do not spread boolean `is_h2` branches across auth logic.

No separate `implementation-plan.md` is warranted: the three milestones above are already the minimal extraction and a second document would duplicate them.

## 15. References

- Stable contract: `.legion/tasks/enable-http2-proxy/plan.md`
- Research: `.legion/tasks/enable-http2-proxy/docs/research.md`
- Current code: `Cargo.toml`, `src/config.rs`, `src/server.rs`, `src/proxy.rs`, `src/capacity.rs`, `src/runtime_plan.rs`
- Current integration tests: `tests/proxy_integration.rs`
- Hyper 1.10.1 and h2 0.4.14, including later SETTINGS direct assignment and `src/proto/h2/server.rs` pre-service consistently parsed `Content-Length > 0` CONNECT handling; hyper-util 0.1.20; hyper-rustls 0.27.9; Rustls/Tokio pinned source and current docs
- RFC 9113, especially cleartext prior knowledge and connection preface/SETTINGS
- RFC 8441, especially SETTINGS_ENABLE_CONNECT_PROTOCOL and WebSocket Extended CONNECT
- RFC 6455 opening-handshake validation
- Adversarial review findings: `.legion/tasks/enable-http2-proxy/docs/review-rfc.md`, `.legion/tasks/enable-http2-proxy/docs/review-change.md`
