# RFC: Harden authenticated proxy production boundaries

> **Profile:** RFC Heavy / availability, authentication, protocol, and deployment boundary
> **Status:** **Ready for another final re-review**
> **Created / updated:** 2026-07-15
> **Design source of truth:** this document
> **Evidence:** `research.md`
> **Implementation:** not started; this RFC changes no production code

## Executive summary

- Retain independent downstream `D=256` and active-upstream `U=128` defaults and all previously reviewed lifecycle/security choices.
- Add `GATEWAY_MAX_BLOCKING_RESOLVERS=8`, validated in `1..=32`, independent of arbitrary U. Effective domain resolution concurrency is `min(R,U)`.
- Use a private R semaphore with immediate `try_acquire_owned`; never create a resolver waiter. On a domain pool miss, submit `spawn_blocking` only after both U and R are owned.
- Explicitly size Tokio's shared blocking pool after Config parsing: proxy `max_blocking_threads = 64 auth + R resolver + 16 runtime margin`; adapter `64 + R + 16`. Default is 88 in either mode and hard maximum is 112.
- R saturation after `Allow` and U admission returns the same exact service-capacity `503` as U saturation, including due renewal, with no body poll, resolver submission, connect, or upstream hit.
- A resolver attempt/cleanup owns R permit + U permit + blocking JoinHandle until observed completion. Queued work is aborted/joined; started work is awaited. A stuck resolver consumes one bounded R/U pair but cannot occupy the 64 auth-worker reservation or submit replacement DNS.
- Keep FD/RLIMIT arithmetic unchanged because resolver work is a mutually exclusive U phase. Validate thread/task/memory capacity separately and record exact runtime blocking maximum.
- Extend parsed `UpstreamBase` with a crate-private typed `DialTarget` derived once from `url::Host`: `Ip(IpAddr)` or normalized `Domain`, plus explicit/default port.
- Never classify from bracketed `http::Uri::host()` at connect time. IPv4 and IPv6 literals form exact `SocketAddr` directly and consume zero R/resolver jobs; only domains enter resolver admission.
- Preserve the existing canonical scheme/authority/path prefix and pass the untouched connector URI to hyper-rustls 0.27.9. Domain names remain DNS SNI/certificate identities; IP authorities remain IP certificate identities.
- Continue SocketAddr-only TCP dialing, ordered pre-TLS address fallback, complete sender+driver ownership, atomic idle park, abort+join retirement, cancellation relays, and bridge-spawn-before-handler-`101`.
- All previous nginx, auth-cookie, accept, saturation, XFF, RLIMIT, FRP, no-replay, streaming, and rollback resolutions remain unchanged.
- Auth isolation and every IPv4/IPv6/domain form are now deterministic. Status is **Ready for another final re-review**; implementation remains gated.

## 1. Context and evidence

The authenticated reverse proxy shipped at revision `1919be9` and its closeout landed at `abe0aae`. It established correct shared authentication, fixed destination selection, streaming HTTP/SSE, low-level one-attempt pooling, WebSocket upgrades, and strict credential/header sanitation. Its final verification passed the four Cargo gates, 55 unit tests, 13 integration tests, and the 18 accepted proxy outcomes.

Production review found four resource/lifecycle gaps and five trust/operations gaps:

1. every accepted downstream connection creates an unbounded task;
2. pool size bounds only idle upstream senders, not active exchanges;
3. the first surfaced listener accept error exits the server;
4. a downstream permit held in the Hyper connection task would be released when an HTTP upgrade hands the socket to a spawned bridge;
5. underscore header aliases are not rejected;
6. unauthenticated fallback has a second independent blocking admission;
7. inbound XFF cannot be accepted from an explicitly authenticated peer;
8. current docs omit the Acorn `18081` FRP remote listener and provide only adapter-mode nginx;
9. FD limits, capacity guidance, overload semantics, and secret-safe signals are absent.

Primary evidence is in `research.md`. The established proxy RFC and security review remain authoritative unless this document explicitly narrows or extends them.

### 1.1 Adversarial-review resolution map

| `review-rfc.md` blocker/note | Normative resolution |
|---|---|
| Resolver blocking isolation | §§4-7, 9, 14, 16-17, 20, 24: R default/cap, immediate admission, exact Tokio blocking formula, R+U+handle ownership, auth-isolation tests |
| Typed IPv4/IPv6/domain classification | §§4-6, 9, 14, 20: `url::Host` at config parse, explicit/default port, zero-resolver IP paths, unchanged URI/TLS identity |
| Explicit hostname resolver ownership | §§4-7, 9, 14, 16-17, 20, 24: owned blocking resolver handle, bounded cleanup, SocketAddr-only dialing, SNI-preserving connector, barriers/accounting |
| Complete driver/FD ownership | §§4, 9, 14, 20: complete sender+JoinHandle owner, guarded terminal state machine, cancellation relay, driver barriers/counters |
| nginx rollback inheritance | §§11, 15, 19, 20: hardened on/on, rollback off/on, native validation/reload/raw probe, artifact assertions |
| Post-decision auth panic cookies | §§12, 14, 20: inner `catch_unwind`, clear-only `LoginInternal`, phase tests |
| Accept log flood/raw fatal output | §§10, 17, 20: separate states, exact global schedule, sanitized exit, stderr/cardinality tests |
| Immediate saturation proof | §§9.1, 20: raw `Expect: 100-continue` transport test with exact response/no-body/no-hit/control assertions |
| Executable RLIMIT | §§7, 15.4, 20: checked mode budgets, injected effective soft limit, startup refusal, systemctl/host evidence |
| Hardening notes | §§8.2, 13, 15.3, 20: no `mem::forget` overclaim, mapped/opaque XFF, frp v0.64.0+, explicit TLS serverName |

## 2. Goals

1. Bound downstream sockets/tasks and active upstream work through all HTTP/upgrade lifetimes.
2. Bound domain resolver execution independently of U and reserve the complete fixed 64-worker auth lane under valid resolver configuration.
3. Submit no resolver waiter or blocking job when R is saturated; keep cancellation/timeout ownership exact after submission.
4. Classify IPv4, bracketed IPv6, and normalized domains once from typed URL parsing, including explicit/default ports.
5. Dial only `SocketAddr` values while preserving canonical configured authority for Host and TLS identity.
6. Keep control routes usable while application streams or resolver jobs fill their own budgets.
7. Preserve reviewed accept, header, login-cookie, trusted-forwarding, deployment, RLIMIT, no-replay, streaming, and rollback contracts.

## 3. Non-goals

- Per-user, per-IP, per-route, or distributed rate limiting.
- Fair queuing between downstream clients or reserved accept sockets dedicated to particular paths.
- Dynamic limits, runtime reload, adaptive admission, or autoscaling.
- A general `Forwarded`/XFF trust-chain parser, Cloudflare trust, PROXY protocol, or recursive proxy discovery.
- Using client IP for gateway authentication, authorization, allowlists, CSRF, return targets, routing, DNS, TLS, or pooling.
- Multiple upstreams, HTTP/2 upstream, CONNECT, generic upgrade tunneling, or request replay.
- Rewriting the auth/session state machine, changing auth-mini, SQLite schema, cookies, JWTs, or allowlists.
- Graceful process draining; restart continues to close in-flight HTTP streams, SSE, and WebSockets.
- Building a metrics service; structured logs remain the available observability substrate.

## 4. Definitions and invariants

- **D/U/R:** downstream permits, active-upstream permits, and blocking-resolver permits. Defaults `256/128/8`; R hard maximum `32`.
- **Auth blocking lane:** existing `AUTH_BLOCKING_WORKERS=64` work permits.
- **Runtime blocking margin:** fixed `16` Tokio blocking threads reserved beyond all 64 auth and R resolver workers.
- **Dial host:** crate-private `DialHost::Ip(IpAddr)` or `DialHost::Domain(Box<str>)`, derived from `url::Host` during `UPSTREAM_URL` parsing.
- **Dial target:** `{ host: DialHost, port: u16 }`, stored alongside unchanged canonical scheme/authority/path prefix.
- **Resolution attempt:** domain-only guard owning U + R + blocking resolver JoinHandle until handle observation.
- **Resolver cleanup:** bounded continuation owning the same U/R/handle after timeout/cancellation.
- **Complete owner / retirement / idle / bridge:** unchanged sender+driver, abort+join, atomic park, and upgraded-I/O definitions.

Hard invariants:

1. Existing downstream, complete-driver, atomic-idle, and bridge ownership invariants remain unchanged.
2. Domain resolution begins only after `Allow`, U admission, pool miss, and successful immediate R admission.
3. R admission uses `try_acquire_owned`; no async R waiter exists. R failure submits no blocking job and returns the exact service-capacity `503`.
4. Every submitted resolver owns exactly one R permit, one U permit, and one observable handle. Resolution attempts plus cleanup are `<= min(R,U)`.
5. Timeout/cancellation keeps both permits through queued abort+join or started completion+join. No live resolver survives either permit's release.
6. Tokio proxy `max_blocking_threads` is exactly `64 + R + 16`; adapter is exactly `64 + R + 16`. R is capped independently of U.
7. With R resolvers blocked, all 64 auth work items still have blocking-thread capacity; resolver configuration alone cannot queue/starve the auth lane.
8. Any new production Tokio `spawn_blocking` call site requires budget review; currently only auth and explicit resolver sites are allowed. The 16-thread margin is not resolver capacity.
9. `UpstreamBase` dial classification occurs once from `url::Url::host()`. Connect code never reparses `http::Uri::host()`.
10. `Host::Ipv4/Ipv6` become exact `IpAddr` and direct `SocketAddr` with zero resolver/R use. `Host::Domain` alone may resolve.
11. Dial port comes from `port_or_known_default`; HTTP/HTTPS always yield a port. Original canonical authority is never rebuilt from the dial target.
12. TCP receives only `SocketAddr`; hyper-rustls 0.27.9 receives the unchanged connector URI for DNS/IP ServerName and certificate validation.
13. Existing auth/header/cookie/no-replay/logging/RLIMIT invariants remain unchanged; no host/address/error values enter logs.

## 5. Decisions at a glance

| Question | Decision |
|---|---|
| D/U | Existing defaults `256/128`; proxy requires `D >= U+16` |
| R setting | `GATEWAY_MAX_BLOCKING_RESOLVERS`, default `8`, valid `1..=32`, independent of U |
| Resolver admission | Private semaphore, immediate `try_acquire_owned`, no waiter/job on saturation |
| R saturation | Same exact post-Allow service `503` as U saturation; renewal if due; no body/DNS/connect/hit |
| Tokio blocking maximum | All modes `64+R+16`; configured after Config parse |
| Runtime margin | Fixed 16, unavailable to resolver permits; source-audited for other blocking call sites |
| Typed dial host | Crate-private `Ip(IpAddr)` or normalized `Domain`, derived from `url::Host` |
| Port | `port_or_known_default`; explicit and scheme-default supported |
| IP literal | Exact `SocketAddr`, no R permit or resolver job, including bracketed IPv6 |
| Domain | Own U+R+JoinHandle through completion/cleanup |
| TCP/TLS | SocketAddr-only inner connector; untouched canonical URI drives hyper-rustls ServerName |
| Multiple addresses | Sequential TCP fallback only; no TLS/HTTP fallback/replay |
| FD budget | Unchanged proxy `D+U+8+1+512`, adapter `D+1+512` |
| Thread/memory budget | Separate runtime/TasksMax/MemoryMax evidence; never inferred from RLIMIT |
| Post-handshake ownership | Existing complete owner, atomic park, abort+join, and guarded bridge |
| Status | Ready for another final re-review; implementation gated |

## 6. End-to-end request and ownership flow

```text
startup (before Tokio runtime)
  parse Config, including D/U/R and typed UpstreamBase.dial_target
  validate R in 1..=32 and FD budgets/RLIMIT
  runtime plan:
    all-mode blocking max = 64 + R + 16
  build Tokio runtime with explicit max_blocking_threads

Allow -> acquire U -> idle complete-owner checkout
  hit -> existing ActiveOwnerGuard flow
  miss -> use stored DialTarget (never reparse URI host)
    Ip(v4/v6),port -> direct SocketAddr -> connect (zero R/DNS)
    Domain(name),port -> try R immediately
      full -> release U -> exact service 503; no spawn/body/connect
      acquired -> spawn_blocking resolver
        ResolutionAttemptGuard owns U+R+handle
        success/failure -> observe join, release R
          success -> addresses + same U -> connect
          failure -> 502 -> release U
        timeout/cancel -> cleanup owns U+R+handle
          abort queued / await started -> release both
    connect only SocketAddr candidates
      original canonical connector URI retained for hyper-rustls ServerName
      -> HTTP handshake -> complete owner -> body/pool/retirement/bridge
```

Resolution occurs after the auth blocking closure has completed and released its auth work permit. R saturation is synchronous and creates no semaphore waiter, request-body poll, or Tokio blocking-queue entry.

## 7. Configuration, FD validation, and runtime blocking budget

### 7.1 Startup settings

| Variable | Default | Validation/mode behavior |
|---|---:|---|
| `GATEWAY_MAX_DOWNSTREAM_CONNECTIONS` | `256` | Existing positive/max parsing; both modes |
| `GATEWAY_MAX_ACTIVE_UPSTREAMS` | `128` | Existing positive/max parsing; proxy headroom check |
| `GATEWAY_MAX_BLOCKING_RESOLVERS` | `8` | Missing/empty -> 8; base-10 positive `usize`; `1..=32`; parsed both modes, semaphore used only proxy domains |
| `TRUSTED_PROXY_CIDRS` | empty | Existing strict CIDR parsing |

R has no required ordering relative to U. `U=512,R=8`, `U=2,R=32`, and defaults are valid when other checks pass; effective resolver concurrency is `min(U,R)`. Default 8 matches the small fixed-upstream idle pool and limits ordinary DNS bursts; hard max 32 caps the Tokio blocking ceiling at 112 regardless of U. Invalid R fails startup value-neutrally as sanitized class `blocking_resolver_limit_invalid` without echoing input, and no limit is silently adjusted.

### 7.2 Typed upstream target

`parse_upstream_url` uses the already parsed url 2.5.8 value:

```text
match parsed.host():
  Host::Ipv4(v4)   -> DialHost::Ip(IpAddr::V4(v4))
  Host::Ipv6(v6)   -> DialHost::Ip(IpAddr::V6(v6))
  Host::Domain(d)  -> DialHost::Domain(d.to_owned())
port = parsed.port_or_known_default()  # 80/443 or explicit
```

Make `UpstreamBase` construction parser-only: its scheme, authority, path prefix, and new `DialTarget` fields are private with crate-read-only accessors, so callers cannot mutate authority away from the dial/TLS identity. Store private `DialTarget { host, port }` while retaining the existing canonical parsed `scheme`, authority slice, and path prefix. As in the current URL parser, an explicitly written scheme-default port may be canonicalized out of the serialized authority; `DialTarget.port` still records the correct 80/443. No public field mutation or unconstrained constructor is allowed; the package is unpublished and integration fixtures migrate to the same parser or a validation-calling test constructor. Dial fields are never serialized or logged.

URL `Host::Domain` is normalized ASCII/IDNA. `Host::Ipv6` is already unbracketed typed data; direct `SocketAddr::new(IpAddr::V6(v6), port)` has flowinfo/scope zero. Never strip/re-add brackets manually for classification and never derive dial target from `http::Uri`.

Pinned parsing cases:

| Configured URL | Dial host | Dial port | Existing canonical authority |
|---|---|---:|---|
| `http://192.0.2.10:4096/base` | `Ip(192.0.2.10)` | 4096 | `192.0.2.10:4096` |
| `http://192.0.2.10/base` | `Ip(192.0.2.10)` | 80 | `192.0.2.10` |
| `http://[2001:db8::1]:4096/base` | `Ip(2001:db8::1)` | 4096 | `[2001:db8::1]:4096` |
| `https://[2001:db8::1]/` | `Ip(2001:db8::1)` | 443 | `[2001:db8::1]` |
| `https://ExAmPle.COM:8443/base` | `Domain(example.com)` | 8443 | `example.com:8443` |
| `https://example.com:443/` | `Domain(example.com)` | 443 | `example.com` (default-port canonicalization, unchanged behavior) |

### 7.3 Exact FD/RLIMIT budgets

Unchanged checked formulas:

```text
proxy required nofile   = D + U + 8 + 1 + 512
adapter required nofile = D + 1 + 512
```

R adds no FD term because every resolver is already one U phase; ancillary DNS descriptors remain in the 512 reserve. Defaults remain 905/769 and `LimitNOFILE=4096`. Finite soft equality/greater or infinity is accepted; overflow, retrieval failure, or too-low finite limit fails sanitized and never shrinks configured limits. Existing host-wide file-table evidence remains separate.

### 7.4 Exact Tokio blocking-thread plan

Constants:

```text
AUTH_BLOCKING_WORKERS   = 64
BLOCKING_RUNTIME_MARGIN = 16

proxy B   = 64 + R + 16  # default R=8 -> 88; max R=32 -> 112
adapter B = 64 + R + 16  # default R=8 -> 88; max R=32 -> 112
```

The single validated `Config.max_blocking_resolvers` value feeds both `RuntimePlan` and the proxy semaphore; it is never reparsed or overridden. After `Config::from_env()` and all validation, but before serving work, create `RuntimePlan` with checked arithmetic and call:

```text
Builder::new_multi_thread()
  .max_blocking_threads(B)
  .enable_all()
  .build()
```

The same formula is used in both modes; adapter mode submits no resolver jobs, so its R reservation remains unused and threads stay lazy. Do not use `#[tokio::main]` or build the runtime before Config. Tokio blocking capacity is independent of async worker threads and is created lazily. Checked-plan failure maps to `runtime_blocking_plan_invalid`; runtime build failure maps to non-source `runtime_build_failed`. Neither includes source text or falls back to Tokio defaults. Startup emits numeric `auth_workers=64`, `resolver_limit=R`, `blocking_margin=16`, and `max_blocking_threads=B`.

The 16 margin covers startup listener hostname binding/runtime/library blocking work and future audited call sites. A source-level test inventories production `spawn_blocking` calls; adding an unbudgeted site fails the gate. Resolver code cannot consume margin because R admission caps submitted resolver jobs.

### 7.5 Auth isolation proof

At worst under valid proxy configuration:

```text
R permanently blocked resolver closures
+ 64 concurrent AuthExecutor closures
+ 16 blocking-runtime margin
= B
```

Thus R resolvers cannot put any of the first 64 auth work items behind the blocking-thread ceiling. Auth can still saturate its own reviewed 64/128 limits; that is not resolver starvation.

### 7.6 Thread memory and operational evidence

`RLIMIT_NOFILE` does not validate threads or memory. Rollout separately records:

```bash
systemctl show auth-mini-gateway -p LimitNOFILE -p TasksMax -p MemoryMax
```

Let W be the effective Tokio async-worker count and B the logged blocking maximum. If finite, `TasksMax` must be at least `1 main + W + B + 32 non-Tokio/process margin`; the separate 32 covers reqwest/native TLS/NSS/background and operational headroom and is not extra resolver capacity. User/process thread limits must also exceed that value. Before cutover, run R blocked resolver fixtures plus 16 margin fixtures and 64 auth jobs and record `/proc/<pid>/status` `Threads`, `VmRSS`, and `VmSize`. If `MemoryMax` is finite, require at least 25% above measured peak RSS. Blocking threads are lazy, and no fixed per-thread RSS is claimed because stack reservation is platform-dependent. Runtime build failure or an environment that cannot pass the required 64-auth-plus-R stress gate blocks startup/cutover; the gateway never shrinks R/auth capacity silently.

## 8. Downstream admission and Hyper upgrade ownership

### 8.1 Accept-before-spawn rule

The accept loop acquires one owned downstream permit **before** calling `accept()`:

```text
permit = downstream.acquire_owned().await
match listener.accept().await
  success -> wrap permit in DownstreamLease and spawn exactly one connection task
  retryable error -> drop permit, sleep according to policy, retry
  fatal error -> drop permit, return sanitized exit; main emits one event/nonzero exit
```

When all permits are held, the loop awaits the semaphore and makes no `accept()` syscall. Pending clients remain in the kernel listen/SYN backlog; if that bounded backlog fills, clients observe connect timeout/refusal according to the OS. The gateway cannot send an HTTP `503` before accepting and parsing a connection, and it deliberately does not accept merely to spawn rejection work.

No semaphore waiter is created per client. There is only one accept-loop waiter. The permit reserved while `accept()` is pending is not reported as an active connection; the active gauge increments only after accept succeeds. Saturation begins when the loop cannot reserve the next slot after spawning the last allowed connection. Therefore downstream saturation creates no process FD, connection task, body, or unbounded rejection queue.

### 8.2 Private cloneable lease

Select a private token rather than exposing `Arc<OwnedSemaphorePermit>` directly:

```text
DownstreamLease (Clone, no public permit access)
  -> Arc<DownstreamLeaseInner>
       -> OwnedSemaphorePermit
```

Why this is safe:

- `OwnedSemaphorePermit` returns one permit on `Drop`.
- `Arc` clones share the same one permit; cloning does not acquire or duplicate capacity.
- The final strong reference drops the inner permit exactly once.
- The wrapper exposes only `Clone`, hiding permit-specific `forget`/split/merge APIs and preventing accidental extraction through normal module APIs. It cannot prevent `std::mem::forget(lease)`; privacy, narrow constructors, review, and lifecycle tests are the controls.
- Tokio permits and the private wrapper must satisfy compile-time `Send + Sync` assertions before they cross the service/bridge task boundary.
- One accepted connection therefore remains one unit even if Hyper invokes the service for multiple requests.

Ownership rules:

1. The spawned Hyper connection task retains an original lease guard until `serve_connection(...).with_upgrades()` resolves.
2. The service closure clones the token into each handler invocation. Normal request clones are request-scoped and are not moved into auth blocking work or ordinary response bodies.
3. Normal keep-alive, request upload, response streaming, and SSE remain covered by the original connection-task guard because Hyper drives them inside the connection future.
4. Only after a valid upstream `101` has been checked does the proxy move one request-scope clone into the already-created WebSocket bridge task.
5. Hyper may then fulfill downstream `OnUpgrade` and complete the original connection future; the bridge clone remains until both upgraded streams terminate.
6. Bridge completion, error, panic, or task cancellation drops both upgraded streams and the final bridge-held clone.

A channel-based “handoff” is rejected: there is a race between returning `101`, Hyper completing the connection, and the bridge receiving ownership. The cloneable private token has no gap and is correct for multiple requests because the resource being counted is the socket, not the request.

## 9. R-isolated DNS-to-upgrade ownership

### 9.1 U and R saturation responses

U admission remains after `AuthDecision::Allow` and before pool checkout. The one external **service-capacity response** used for both U and R saturation is exactly:

- `HTTP/1.1 503 Service Unavailable` as the first/final response; never `100 Continue`;
- body `Service temporarily unavailable`, exactly 31 bytes with no trailing newline;
- `Content-Type: text/plain; charset=utf-8`;
- `Cache-Control: no-store`;
- `Retry-After: 5`;
- `Content-Length: 31`;
- `Connection: close` when input may remain unread, followed by EOF;
- no request-body poll/read, application hit, `Location`, identity, Upgrade, or application header;
- only protocol-managed `Date` may additionally vary;
- no `Set-Cookie`, or exactly one already-due gateway renewal appended last.

U saturation performs no pool/R/DNS/connect work. After a pool miss **only for `DialHost::Domain`**, call `resolver_semaphore.try_acquire_owned()` synchronously. If R is full:

- release the just-held U permit;
- return the exact service-capacity response above;
- create no resolver waiter, `spawn_blocking` handle, TCP/TLS/HTTP attempt, or upstream hit.

Internally observability distinguishes `active_upstream` from `blocking_resolver`; external response does not. Idle owner hits and `DialHost::Ip` never acquire R and can proceed while R is full.

### 9.2 Configuration-time dial classification

Fresh connect reads only stored `UpstreamBase.dial_target`:

- `DialHost::Ip(ip)` -> `SocketAddr::new(ip, port)` directly, zero resolver/R operations;
- `DialHost::Domain(normalized)` -> immediate R admission, then explicit owned resolution.

Connect code is forbidden from classifying `connect_uri.host()` or bracket text. Original canonical scheme/authority/path remain separate and unchanged for URI/Host/TLS behavior.

### 9.3 Resolver submission and ownership

Only after both U and R are held in a short-lived `ResolverAdmissionGuard`, synchronously call explicit:

```text
spawn_blocking(move || {
  state = Started
  std::net::ToSocketAddrs::to_socket_addrs(&(domain.as_ref(), port))
    .map(|iter| iter.collect::<Vec<SocketAddr>>())
})
```

No await separates R acquisition, blocking submission, or returned-handle ownership. If the request ends before submission begins, only U (and any synchronously acquired R) exists and may be dropped because no resolver task/I/O was created. `ResolverAdmissionGuard` owns U+R until `spawn_blocking` returns; if submission panics before a handle exists, no resolver job survives and the process follows fail-stop startup/runtime invariant handling. The returned handle moves immediately into:

```text
ResolutionAttemptGuard {
  job: Some {
    active_permit: U,
    resolver_permit: R,
    resolver_handle,
    state: Queued|Started|Finished,
  },
  shared_connect_deadline,
}
```

There is no R waiter and no R+1 blocking submission. The guard awaits `&mut resolver_handle` under the existing shared 10-second DNS+TCP+TLS deadline.

### 9.4 Resolver terminal states

| Path | External result | Ownership transition |
|---|---|---|
| Domain success, nonempty | continue | observe join; release R; move addresses + same U + deadline into connect |
| Failure/empty/join failure | sanitized `502`, renewal if due, close if unread | observe join; release R then U; no connect |
| Timeout while queued | `502` may return | cleanup owns U+R+handle; abort queued; await canceled handle; release both |
| Timeout after start | `502` may return while cleanup runs | abort ineffective; cleanup awaits completion, discards result, releases R/U |
| Caller cancellation | no response | same queued/started cleanup; both permits retained |
| Cleanup cancellation/panic | no new response | relay unchanged U+R+handle to one non-public non-panicking/fail-stop replacement |

`ResolutionAttemptGuard::Drop` with a live job synchronously schedules cleanup and never directly drops either permit/handle. Successful join consumes into `ResolvedCandidates { addresses, active_permit, deadline }`; R is returned only after join, and connect guard forms before another await. A started stuck resolver holds one R/U pair indefinitely but cannot consume another R slot or reduce the reserved 64 auth thread capacity.

### 9.5 No hidden blocking queue

Gateway-level resolver admission has these exact counts:

```text
resolver permits held
  = synchronous pre-submit admission guards
  + request-owned resolution attempts
  + resolver-cleanup jobs
  <= R and <= U

submitted resolver handles not yet observed
  = request-owned resolution attempts + resolver-cleanup jobs
  <= resolver permits held
```

An R+1 domain attempt is rejected before `spawn_blocking`; submitted-handle count does not change. Because runtime B reserves R resolver workers in addition to 64 auth and 16 margin threads, admitted resolvers are not capacity-queued behind valid auth+resolver load. Tokio may perform ordinary scheduling/thread startup, but there is no over-admitted resolver job or unbounded application queue.

### 9.6 SocketAddr-only connector and TLS identity

Use the prior reviewed fresh, non-cloneable, one-shot `ResolvedTcpConnector` with `Option<Vec<SocketAddr>>`; it takes candidates once and calls only `TcpStream::connect(SocketAddr)` in resolver order under `timeout_at(deadline, connector.call(original_connect_uri))`.

The connector URI is built from unchanged canonical `scheme + authority`. hyper-rustls **0.27.9** derives `ServerName` from that URI before invoking the inner connector, strips IPv6 brackets, and then performs TLS:

- domain authority -> DNS ServerName/SNI and DNS SAN validation;
- IPv4/IPv6 authority -> IP ServerName and exact IP SAN validation; no DNS hostname is substituted or synthesized;
- selected dial address never rewrites authority.

TCP-connect failures may advance to the next address before TLS. First TCP success stops fallback; `TCP_NODELAY`, TLS, HTTP handshake, or send failure does not try another address or replay.

### 9.7 Complete owner, idle park, cleanup, and bridge

All previously reviewed terminal ownership remains normative:

- resolved TCP/TLS/HTTP-handshake attempt owns U and drops current future/I/O before release; no resolver/R remains;
- handshake success immediately constructs complete sender+driver owner with U;
- every non-idle ready/send/response/error/cancel/invalid-`101` path drops sender, aborts driver, awaits join, then releases U;
- reusable EOS waits readiness <=1s, pushes complete owner into the eight-entry pool, returns U with no await, then unlocks;
- cleanup cancellation relays unchanged owner+U job;
- guarded bridge task receives both upgrades, driver handle, U, and downstream lease and is spawned before handler returns `101`; driver joins after upgraded I/O transfer, and I/O drops before permits.

### 9.8 Deterministic capacity/address tests

Required resolver/auth tests:

1. R defaults to 8; 1/32 accepted; 0/33/non-numeric/overflow rejected value-neutrally.
2. Runtime formula is `64+R+16` in both modes: default 88, R32 maximum 112; R never derives from U.
3. With custom `U=16,R=2`, two started blocked resolvers submit exactly two handles; the third domain pool miss gets immediate exact `503`, creates no waiter/handle/body poll/connect, and releases its U.
4. While R resolver closures and 16 test-only margin closures remain started/blocked, 64 AuthExecutor work closures all reach a start barrier and complete; resolver release is not needed. The 64th is not queued behind DNS.
5. R saturation does not block an idle-owner hit or IP-literal direct connect when U exists.
6. Timeout/caller cancellation retains both U/R until queued cancellation or started completion is joined; R+1 cannot submit during cleanup.
7. Source/instrumentation proves submitted resolver handles equal held R jobs and no hidden hostname connect/`lookup_host`/default `HttpConnector` path exists.

Required typed-host tests:

- IPv4 explicit/default port -> exact `SocketAddrV4`, zero resolver/R;
- bracketed IPv6 explicit/default port -> exact `SocketAddrV6` with scope/flow zero, zero resolver/R;
- normalized hostname explicit/default port -> `DialHost::Domain` and one R-governed resolver;
- canonical authority/path/scheme unchanged and never reconstructed from dial target;
- HTTPS domain fixture validates hostname/SNI; HTTPS IPv4 and IPv6 fixtures require matching IP SAN, reject DNS-only certificate, and never substitute domain SNI;
- hyper-rustls 0.27.9 default resolver receives untouched domain/IP URI.

All prior resolver timeout/barrier, multi-address, complete-driver, idle, raw-saturation, and WebSocket tests remain mandatory.

## 10. Listener errors, global log suppression, and sanitized exit

### 10.1 Linux classification

Classification continues to use `raw_os_error()` with `libc` constants and `ErrorKind` fallback:

| Class | Linux errors | Action |
|---|---|---|
| `ResourceFd` | `EMFILE`, `ENFILE` | release accept reservation; resource backoff |
| `ResourceMemory` | `ENOBUFS`, `ENOMEM` | release reservation; resource backoff |
| `Transient` | `EINTR`, `ECONNABORTED`, `EAGAIN`/`EWOULDBLOCK`, `ENETDOWN`, `EPROTO`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`, `EHOSTUNREACH`, `EOPNOTSUPP`, `ENETUNREACH`, `EPERM`, `ENOSR`, `ESOCKTNOSUPPORT`, `EPROTONOSUPPORT`, `ETIMEDOUT` | release reservation; transient backoff |
| `FatalListener` | `EBADF`, `EFAULT`, `EINVAL`, `ENOTSOCK`, unknown/unclassified errno | no retry; convert to sanitized fatal exit |

### 10.2 Backoff state is class-local

`AcceptBackoff` stores only current class and same-class streak:

- transient: `10,20,40,80,160,250,250... ms`;
- either resource class: `100,200,400,800,1600,3200,5000,5000... ms`;
- changing class resets delay to the new class base;
- successful accept resets backoff;
- sleep is awaited inline; no retry task.

### 10.3 Logging state is global

A separate `AcceptFailureLogState` uses an injected monotonic clock and is never reset by class changes. It tracks global consecutive recoverable failures, first-failure time, last emission time, and suppressed-since-emission count.

Deterministic schedule:

1. Emit `accept_error` for global failure numbers `1,2,4,8,16,32`.
2. For failure number `>32`, emit only when at least 60 seconds elapsed since the previous `accept_error` event.
3. Every event includes current class, current class-local backoff, global failure count, and `suppressed_since_last`; then suppressed count resets.
4. Every non-emitted failure increments suppressed count, including alternating classes.
5. On the first successful accept after failures, emit exactly one `accept_recovered` summary with total global failures, final suppressed count, and duration; then reset both logging and backoff state.
6. A fatal error emits no additional recoverable summary. Its single process-exit event includes prior global/suppressed counts and then exits.

Thus alternating `Transient/ResourceFd/ResourceMemory` may reset delay but cannot repeatedly generate first events.

### 10.4 Sanitized fatal boundary

The accept loop consumes the original `io::Error` and returns only:

```text
SanitizedExit::ListenerFatal {
  errno_class: bad_fd | fault | invalid | not_socket | unknown,
  errno_code: Option<i32>,
  prior_recoverable_failures: u64,
  suppressed_failures: u64,
}
```

`SanitizedExit` has no `source`, stores no `io::Error`, and has no Display implementation that includes library/system text. Other startup fatals such as FD-budget overflow/too-low/unavailable are mapped into the same non-source-bearing top-level enum.

Change the process boundary from `main() -> Result` to explicit control:

1. initialize structured logging;
2. call `run()` returning `Result<(), SanitizedExit>`;
3. on error, emit exactly one `process_exit` event with allowlisted enum/numeric fields;
4. flush best-effort and call `std::process::exit(1)` (or equivalent explicit nonzero `ExitCode`);
5. never `eprintln!`, debug-format, Display-format, or return the original/source error.

Fatal accept is not logged inside the loop, preventing duplicate events.

### 10.5 Deterministic tests

Tests inject accept source, sleeper, monotonic clock, event sink, RLIMIT/startup failures, and process-boundary sink:

- exact class/backoff sequences;
- 100+ alternating-class errors with exact event cardinality at 1/2/4/8/16/32 plus 60-second gates;
- long capped runs and suppressed-count summaries;
- success recovery event and full reset;
- every fatal errno plus unknown errno;
- exactly one fatal event and nonzero exit classification;
- captured stderr contains structured allowlisted output only and excludes injected raw OS/library/source marker strings.

No test changes RLIMIT or exhausts FDs.

## 11. Underscore header-name rejection

On a Hyper-delivered, non-owned request **only when proxy mode is active**, scan unique `HeaderMap` names before any proxy fallback authentication. If any `HeaderName::as_str()` contains byte `_`, return:

- fixed `400 Bad Request`;
- body `Bad request`;
- `Content-Type: text/plain; charset=utf-8`;
- `Cache-Control: no-store`;
- `Connection: close`;
- no `Set-Cookie`, `Location`, identity, or `Retry-After`;
- no auth executor admission, DB/session touch, login state, or upstream contact.

Reject the whole request; do not strip only the ambiguous field. The rule covers identity, forwarding, ordinary, and `Connection`-nominated underscore names.

Compatibility boundary:

- gateway-owned routes are classified first and retain current behavior even with underscore fields;
- adapter-mode non-owned fallback remains the existing local `404`;
- canonical hyphenated spoofed identity/forwarding fields continue through existing sanitation: they are stripped and verified values are injected;
- mixed canonical plus underscore aliases are rejected, not partially sanitized.

Acorn proxy mode pins `underscores_in_headers on` **and** `ignore_invalid_headers on`: underscore aliases reach the hardened gateway, while other nginx-invalid names are discarded independently of inheritance. Old-binary rollback pins underscore handling off while retaining invalid-header dropping on, then validates/reloads/raw-probes before exposure.

## 12. Single admitted authentication/login operation

Keep `AuthDecision` unchanged and use one private proxy result:

```text
ProxyAuthResult
  Decision(AuthDecision other than Unauthenticated)
  LoginReady { clear_session, login_response }
  LoginInternal { clear_session }
```

The single `AuthExecutor::run` closure establishes an explicit phase boundary:

1. Call existing `auth_decision` exactly once **outside** the post-decision unwind catcher.
2. If it returns `Allow`, `Forbidden`, or `Unavailable`, return that decision unchanged.
3. If it returns `Unauthenticated { clear_session }`, retain the clear value and invoke the injected `LoginStateBuilder`/`create_login_response` inside `catch_unwind(AssertUnwindSafe(...))`.
4. `Ok(Ok(response))` -> `LoginReady`.
5. `Ok(Err(_))` (DB/construction error) or `Err(_)` (post-decision panic) -> `LoginInternal { clear_session }`.
6. Never propagate the caught payload/error text.

Exact outcomes:

- Admission overload occurs before closure execution: cookie-neutral auth-unavailable `503` + `Retry-After: 5`, no state/upstream.
- Panic/internal failure before `AuthDecision` returns escapes the closure and becomes cookie-neutral fixed `500` at the join boundary.
- Successful unauthenticated login remains `302`; session-clear first, positive login-state second.
- Post-decision DB error or panic becomes fixed `500`, exactly one session-clear cookie, no login-state cookie, no upstream.
- `AuthDecision::Unavailable` remains auth-unavailable `503` with no cookie.
- Cancellation after blocking work begins still lets the closure finish under existing owned permits; unused login state expires normally.

Tests inject a marker panic specifically after `Unauthenticated` and assert the same clear-only response as DB failure. A separate pre-decision panic test asserts cookie-neutral `500`. There is no second admission or duplicated auth logic.

## 13. Trusted proxy CIDRs and canonical client IP

### 13.1 Trust model

Trust is based only on the immediate socket peer. `TRUSTED_PROXY_CIDRS` defaults empty, so no deployment gains forwarding trust by upgrade alone.

The derivation function accepts `(direct_peer_ip, HeaderMap, TrustedProxySet)` and returns either a private `ClientIp` or `BadRequest`. It runs only for proxy fallback and before authentication, but the resulting value is not passed into the auth closure.

### 13.2 Minimal algorithm

1. Test direct peer membership against configured CIDRs. Do not consult any header to select trust.
2. If the peer is **untrusted**:
   - do not parse any XFF value, even if malformed or repeated;
   - choose `client_ip = direct_peer_ip`.
3. If the peer is **trusted**:
   - zero XFF fields: deterministically fall back to `direct_peer_ip` and record outcome `missing_fallback`;
   - exactly one field: require UTF-8/ASCII text containing one bare `IpAddr`, with no comma or embedded ASCII whitespace; parse using `std::net::IpAddr` and choose it;
   - repeated fields or invalid/list/port/bracket/zone/empty input: fixed no-store `400`, close, no cookie/auth/upstream.
4. During sanitation, remove `Forwarded` and every inbound `X-Forwarded-*` field regardless of trust.
5. Emit exactly one `X-Forwarded-For: client_ip.to_string()` value. Regenerate `X-Forwarded-Proto` from `GATEWAY_PUBLIC_BASE_URL` and `X-Forwarded-Host` from the accepted canonical Host as today.
6. Never append, preserve, or log the raw input.

The missing-header fallback is secure because it can only reduce attribution to the authenticated direct peer; it cannot claim a browser address. A malformed **present** value—including opaque/non-ASCII bytes from a trusted peer—fails fixed `400`. The same opaque bytes from an untrusted peer are never parsed and are replaced by the direct peer. If Hyper removes protocol-legal leading/trailing OWS, the strict grammar begins at the typed `HeaderValue`; no raw parser is added.

### 13.3 Non-influence boundary

`ClientIp` may appear only in request-header sanitation. It is prohibited from:

- `AuthDecision`, session lookup/refresh/touch, policy or allowlist APIs;
- return-target validation or login URL/state content;
- upstream URI, scheme, authority, DNS, TCP connector, TLS SNI/certificate, or idle-pool key;
- route selection, error selection other than strict metadata syntax rejection, or cookie construction.

Tests vary XFF while asserting identical auth/allowlist, return target, fixed upstream target, TLS target, and pool reuse. The application remains free to treat the regenerated value as application data; the gateway makes no authorization claim about it.

### 13.4 Operational warning

Trusting `127.0.0.1/32` trusts every local process able to connect to gateway `7780` to assert informational client IP. Keep the listener restricted. CIDR matching preserves families: peer `::ffff:127.0.0.1` does **not** match `127.0.0.1/32`; only an explicitly configured mapped IPv6 CIDR can trust it. Never configure the Acorn public address when the direct peer is Axiom frpc.

## 14. Authoritative capacity, address, failure, and cookie mapping

| Phase/path | External/cookie outcome | Ownership proof |
|---|---|---|
| Invalid R/runtime plan or runtime build | sanitized nonzero startup exit; no traffic/cookies | before service; no silent shrink or raw source |
| Downstream/auth/validation/login/accept | all previously reviewed exact outcomes | unchanged |
| U saturated after Allow | exact service `503`; no body/pool/R/DNS/connect; renewal if due | no U acquired |
| Domain R saturated after U/pool miss | same exact service `503`; no waiter/spawn/body/connect; renewal if due | U released; no R/handle created |
| IPv4/IPv6 literal | continue | exact direct SocketAddr; no R/resolver |
| Domain success | continue | U+R+handle until observed join; release R; U enters connect |
| Domain failure/empty/join failure | `502`, close if unread, renewal if due | observe handle; release R/U; no TCP |
| DNS timeout queued/started | `502` may finish while cleanup runs | cleanup retains R+U through abort/join or started completion |
| Caller/cleanup cancellation | no response/new response | same R+U+handle relayed until observation |
| Multi-address TCP all fail | `502`, renewal if deliverable | DNS/R already complete; I/O dropped before U |
| TLS/HTTP handshake failure | `502`, renewal if deliverable | original authority identity retained; I/O dropped before U |
| Ready/send/nonreuse/early-final/body/pool/invalid `101` | existing reviewed behavior | complete owner atomic park or driver abort+join before U |
| Valid upgrade/tunnel | existing reviewed behavior | bridge spawned before `101`; joined driver; I/O before leases |

R saturation is service capacity, not auth unavailability. A timed-out DNS `502` does not imply immediate U or R return.

## 15. Exact production topology and configuration

### 15.1 Required chain

```text
Browser
  -> Acorn nginx public TLS :443
  -> Acorn loopback 127.0.0.1:18081 (frps TCP remotePort)
  -> authenticated/TLS FRP tunnel
  -> Axiom frpc local target 127.0.0.1:7780
  -> auth-mini-gateway 127.0.0.1:7780
  -> OpenCode 127.0.0.1:4096
```

Only nginx `:443` and the firewalled frps control port are externally reachable. Acorn `18081`, Axiom `7780`, and OpenCode `4096` are loopback-only. FRP never maps `3000` or `4096`.

### 15.2 Acorn nginx proxy-mode server

```nginx
# http context
map $http_upgrade $gateway_connection {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    server_name app.example.com;

    ssl_certificate     /etc/nginx/tls/app.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/app.example.com.key;

    # Hardened gateway must receive underscore names to reject them. Other
    # nginx-invalid names remain discarded regardless of inherited http config.
    underscores_in_headers on;
    ignore_invalid_headers on;

    client_max_body_size 0;
    client_body_timeout 24h;
    send_timeout 24h;

    location / {
        proxy_pass http://127.0.0.1:18081;
        proxy_http_version 1.1;

        proxy_set_header Cookie $http_cookie;
        proxy_pass_header Set-Cookie;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;

        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "";
        proxy_set_header X-Real-IP "";
        proxy_set_header X-Forwarded-Port "";

        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $gateway_connection;

        proxy_request_buffering off;
        proxy_buffering off;
        proxy_cache off;
        gzip off;

        proxy_connect_timeout 10s;
        proxy_send_timeout 24h;
        proxy_read_timeout 24h;
        proxy_socket_keepalive on;

        proxy_intercept_errors off;
        proxy_next_upstream off;
        proxy_redirect off;
    }
}
```

There is one all-path gateway location, no `auth_request`, no Cookie clear, and no `$proxy_add_x_forwarded_for`.

### 15.3 FRP v0.64.0+ TOML

`auth.tokenSource` requires **frp v0.64.0 or newer**. Pin/record matching frps/frpc versions.

Acorn `frps.toml`:

```toml
bindAddr = "0.0.0.0"
bindPort = 7000
proxyBindAddr = "127.0.0.1"
allowPorts = [{ single = 18081 }]

auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/token"

transport.tls.force = true
transport.tls.certFile = "/etc/frp/tls/server.crt"
transport.tls.keyFile = "/etc/frp/tls/server.key"
```

Axiom `frpc.toml`:

```toml
serverAddr = "frp.example.com"
serverPort = 7000

auth.method = "token"
auth.tokenSource.type = "file"
auth.tokenSource.file.path = "/etc/frp/token"

transport.tls.enable = true
transport.tls.trustedCaFile = "/etc/frp/tls/ca.crt"
transport.tls.serverName = "frp.example.com"

[[proxies]]
name = "auth-mini-gateway"
type = "tcp"
localIP = "127.0.0.1"
localPort = 7780
remotePort = 18081
```

No PROXY protocol. Restrict frps `7000` by firewall to Axiom.

### 15.4 Axiom gateway and systemd

```env
HOST=127.0.0.1
PORT=7780
UPSTREAM_URL=http://127.0.0.1:4096
GATEWAY_PUBLIC_BASE_URL=https://app.example.com
GATEWAY_MAX_DOWNSTREAM_CONNECTIONS=256
GATEWAY_MAX_ACTIVE_UPSTREAMS=128
GATEWAY_MAX_BLOCKING_RESOLVERS=8
TRUSTED_PROXY_CIDRS=127.0.0.1/32
```

Enable trust only after observing the exact frpc peer and canonical nginx overwrite.

```ini
[Service]
LimitNOFILE=4096
Restart=on-failure
RestartSec=5
```

Startup must calculate FD budget `905`, resolver limit `8`, and blocking maximum `88`; finite soft RLIMIT must meet the FD budget. Rollout records `systemctl show auth-mini-gateway -p LimitNOFILE -p TasksMax -p MemoryMax`, compares each to §7, and records host-wide FD plus stressed thread/memory evidence separately.

### 15.5 Native validation and old-binary alias probe

```bash
nginx -t
frps verify -c /etc/frp/frps.toml
frpc verify -c /etc/frp/frpc.toml
frps --version
frpc --version
```

For old-binary rollback, public traffic remains maintenance-denied while a local operator path exercises the same candidate server block:

1. explicitly set `underscores_in_headers off;` and retain/set `ignore_invalid_headers on;`;
2. run `nginx -t`; failure stops rollback;
3. reload nginx under maintenance and verify reload success;
4. while the hardened gateway still runs, send a raw non-owned anonymous request containing `X_Auth_Mini_User_Id: attacker` through the candidate nginx path;
5. require the normal anonymous `302` with zero app hit and **not** the hardened gateway's underscore `400`, proving nginx discarded the field;
6. only then stop the hardened gateway/start the old binary and consider removing maintenance deny.

The maintenance mechanism must leave a loopback/operator validation path through the candidate server configuration; a blanket local `return 503` that bypasses proxy parsing is not valid evidence. Artifact tests pin both directives in proxy and rollback examples.

## 16. Security and privacy analysis

| Threat | Control |
|---|---|
| Resolver starves auth blocking lane | R<=32 plus all-mode blocking max `64+R+16`; R jobs cannot consume 64 reserved auth capacity. |
| Hidden resolver waiter/submission | immediate R try before spawn; R+1 exact 503 and zero handle. |
| Started libc resolver leak | cleanup owns R+U+handle until join; stuck work fails closed within both caps. |
| Bracketed IPv6 treated as DNS | typed `url::Host::Ipv6` at Config parsing; no connect-time URI text parsing. |
| Dial/TLS identity split | private parser-built DialTarget; original authority remains hyper-rustls 0.27.9 ServerName input. |
| IP certificate weakening | IP URI remains IP ServerName and requires matching IP SAN; no DNS override. |
| Thread/FD budget confusion | exact blocking formula and separate TasksMax/memory evidence; FD RLIMIT unchanged. |
| Prior transport/auth/header/trust threats | all complete-owner, cancellation, no-replay, cookie, accept, nginx, and XFF controls unchanged. |

Dial host/domain/address values and runtime errors remain excluded from logs.

## 17. Observability and operations

Startup events add allowlisted numeric fields:

- `runtime_blocking_plan`: mode, auth workers `64`, resolver limit R, margin `16`, max blocking threads B;
- `capacity_start`: existing D/U plus R and effective domain resolver concurrency `min(R,U)`.

Resolver events add reason/outcome classes only:

- R admission `admitted|saturated`, submitted handles, request-owned jobs, cleanup jobs;
- resolver `queued|started|finished|joined`, timeout/cancel/failure classes;
- no hostname, authority, IP, answer, or raw error.

Exact equations:

```text
resolver_permits_held
  = synchronous_pre_submit + resolver_attempts + resolver_cleanup
  <= R and <= U

submitted_unobserved_resolver_handles
  = resolver_attempts + resolver_cleanup
  <= resolver_permits_held

active U phases
  = resolving + resolver_cleanup + connecting + active_http/driver_cleanup + bridge
```

For actual submitted jobs, resolver count is `<= min(R,U)`. Monitor auth-start latency while R jobs are blocked, blocking-thread count, R saturation `503`, cleanup duration, and existing owner/driver equations.

Alerts:

- any resolver handle without both permits, R+1 submitted handle, R waiter, or resolver count above `min(R,U)`;
- any of first 64 auth work items blocked solely because R resolvers occupy blocking threads;
- runtime plan mismatch, unexpected production `spawn_blocking` site, cleanup relay, or sustained R saturation;
- finite TasksMax/MemoryMax below operational guidance or stressed thread/RSS evidence.

## 18. Compatibility

### Preserved

- All owned route methods, statuses, bodies, cookies, ordering, refresh, logout, callback, and health behavior.
- Adapter fallback `404`, including requests carrying underscore headers.
- Shared auth decision, exact allowlists, Pending state, touch/renewal expiry, and auth-unavailable semantics.
- Fixed upstream URI/TLS, Host behavior, request/response sanitation, app-cookie filtering, streaming, SSE, early-final cancellation, no replay, and WebSocket handshake/half-close behavior.
- SQLite schema v2, gateway cookie format, browser session continuity, and existing deployment rollback mode.
- Default forwarding output remains the direct peer because trusted CIDRs default empty; inbound XFF remains ignored by default.

### Intentional changes

- New connections pause at the downstream cap.
- Allowed proxy requests can receive service-capacity `503` with Retry-After when active upstreams are full.
- Non-owned proxy fallback with any underscore field name becomes fixed `400` instead of stripping/forwarding it.
- A trusted direct peer with malformed present XFF becomes fixed `400`.
- Login overload can no longer become a cookie-clearing `500`; it is pre-decision cookie-neutral `503`.
- Listed recoverable accept errors no longer terminate the process. Fatal accept exits through one sanitized event, not raw `Result` formatting.
- Startup now refuses a finite soft RLIMIT below the exact mode budget instead of accepting an impossible capacity configuration.
- Upstream idle reuse is behaviorally unchanged, but complete owner teardown can delay capacity return until driver join is observed.
- Hostname DNS results and sequential TCP fallback remain fresh-connect-only; the implementation now owns resolver completion explicitly. A resolution timeout may return `502` while retaining active capacity until blocking DNS ends.
- Configured hostname/Host/SNI/certificate behavior is preserved; only the low-level TCP dial input changes from hostname tuple to resolved `SocketAddr`.
- Domain fresh-connect concurrency now has an independent default cap of 8 and may return immediate service `503`; IP literals and pooled owners do not consume that cap.
- Valid bracketed IPv6 upstream URLs now follow the intended direct-IP path rather than accidental DNS.

Applications that legitimately depend on underscore header names must migrate to hyphenated names before rollout; there is deliberately no bypass flag. Owned gateway routes and adapter mode are not affected.

## 19. Rollout, migration, and rollback

### 19.1 Data migration

None. No schema, row, token, cookie, or state backfill. New settings are process-only; the prior binary ignores them.

### 19.2 Safe rollout

1. Obtain `review-rfc` PASS; implement R admission/runtime sizing, typed URL dial targets, explicit resolver ownership, SocketAddr-only dialing, and all prior behavior; pass §§20 and 23.
2. Stage frp v0.64.0+, explicit TLS serverName, nginx, systemd, and environment without public reload. Verify FRP versions/config and loopback/firewall bindings.
3. Set default R=8, verify runtime blocking max 88, calculate FD budget 905, set `LimitNOFILE=4096`, and record LimitNOFILE/TasksMax/MemoryMax plus separate FD/thread-memory evidence.
4. Keep trust empty initially. Enable Acorn maintenance deny, stop current gateway, and start hardened gateway on `127.0.0.1:7780`. Startup must report successful FD-budget check.
5. Reload nginx with both `underscores_in_headers on;` and `ignore_invalid_headers on;`, canonical `$remote_addr` XFF, and all-path proxying. Establish `18081 -> 7780` under maintenance.
6. Verify R saturation/no-submit, `/healthz` plus 64-auth isolation under blocked R and margin fixtures, IPv4/bracketed-IPv6/domain classification and TLS identity, resolver/owner counters, raw U saturation, and all prior HTTP/security checks.
7. Confirm exact frpc direct peer, then set its explicit CIDR and restart under maintenance. Verify regenerated one-value XFF and non-influence.
8. Remove maintenance deny and monitor resolver cleanup, phase/owner/driver equations, saturation, accept suppression, and FD use. Retain prior binary/config.

Never enable nginx underscore pass-through while an old binary serves. Never enable trust before canonical overwrite/direct-peer evidence.

### 19.3 Rollback triggers

- Any R/U permit becomes available before resolver-handle observation, or U before complete-owner park/driver join/upgraded-I/O close.
- R/U/resolver accounting diverges, R+1 submits/waits, blocked R starves auth, bracketed IPv6 resolves as DNS, hidden hostname connect appears, or owner accounting diverges.
- Raw fatal source text reaches stderr or alternating accept errors exceed event schedule.
- RLIMIT arithmetic/comparison differs from §7.
- Cookie mapping differs across pre-decision, post-Unauth DB, or post-Unauth panic phases.
- Alias/XFF, no-replay, control route, streaming, or deployment boundaries regress.

### 19.4 Executable old-binary rollback

1. Enable maintenance deny while retaining an operator loopback path through the candidate nginx server.
2. Edit candidate nginx to explicit:

   ```nginx
   underscores_in_headers off;
   ignore_invalid_headers on;
   ```

3. Run `nginx -t`; on failure stop and remain denied.
4. Reload nginx under maintenance and verify successful reload.
5. While the hardened gateway still runs, raw-probe a non-owned anonymous request with `X_Auth_Mini_User_Id: attacker` through that exact server path. Require normal `302`, zero app hit, and no underscore-rejection `400`.
6. If the probe fails or is inconclusive, remain denied; do not start/expose the old binary.
7. Stop hardened gateway and wait for process/SQLite release. Start the prior verified proxy on `127.0.0.1:7780` with same DB/secret/upstream; new env is ignored/unset.
8. Keep `LimitNOFILE=4096`, canonical XFF overwrite, FRP `18081 -> 7780`, and loopback OpenCode. Verify auth/cookies/HTTP/SSE/WebSocket under maintenance, then remove deny.
9. If prior proxy fails, use approved adapter rollback; never map FRP to `4096`.

Active streams/tunnels close on switch. No DB restore is required.

## 20. Automated verification matrix

All prior rows remain mandatory. New blocker-closing rows:

| Area | Case | Required assertions |
|---|---|---|
| R config | default/bounds | default 8; 1/32 accepted; zero/33/non-numeric/overflow value-neutral failure |
| R/U relation | custom | U>R and R>U accepted; actual resolver jobs <=min(R,U) |
| Runtime plan | exact formula | both modes default 88/R32 112; same Config R feeds runtime and semaphore; configured after parse |
| R saturation | immediate/no-wait cancellation | R blocked; R+1 poll returns exact 503 without Pending/waiter/spawn/body/connect/hit; U released; cancellation leaves no waiter; `/healthz` succeeds |
| Auth isolation | 64 workers | with R resolver plus 16 test-margin closures blocked, all 64 auth closures—including an `/auth/check` control fixture—start/complete before resolver release |
| Blocking queue | accounting | submitted unobserved handles equal held R jobs; never >R; no hidden R+1 queue |
| Timeout/cancel | dual permits | started/queued cleanup retains both R/U until observed join; R+1 remains rejected |
| IP bypass | R full | pooled owner and IPv4/IPv6 direct connect proceed when U available; no R/spawn |
| Typed host | IPv4 | explicit/default port, exact IpAddr/SocketAddrV4, canonical authority retained |
| Typed host | bracketed IPv6 | explicit/default port, exact SocketAddrV6 scope/flow zero, zero resolver jobs |
| Typed host | domain | normalized domain, explicit/default port, exactly one R-governed resolver |
| TLS identity | domain/IP | domain SNI/DNS SAN; IPv4/IPv6 IP SAN; DNS-only cert rejected for IP; authority never rewritten |
| Operations | thread/memory | startup fields exact; TasksMax/MemoryMax commands and stressed Threads/RSS evidence documented |
| Static audit | blocking/dial APIs | only budgeted auth/resolver `spawn_blocking` and no production `block_in_place`; no connect-time Uri host classification, hostname TCP connect, Tokio lookup_host/ToSocketAddrs, Url::socket_addrs, or default HttpConnector |

Previously required resolver success/failure/queued/started barriers, multi-address fallback, complete-driver ownership, idle/bridge lifecycle, exact U saturation, accept logging/fatal stderr, auth cookies, nginx rollback, XFF, RLIMIT, FRP, and all regressions remain unchanged.

Use a dedicated test runtime built from `RuntimePlan`. IPv6 classification and IP-ServerName/certificate tests use injected or in-memory transport where needed, so CI does not depend on host IPv6 routing. The auth-isolation test holds R resolver and 16 test-only margin closures on barriers, submits 64 auth closures through the real 64-work admission, waits until all 64 started, lets them complete, and only then releases the other blockers. No scheduler sleeps, external DNS, or FD exhaustion.

## 21. Module boundaries and implementation milestones

| Module/artifact | Responsibility |
|---|---|
| `src/config.rs` | Parse R; make UpstreamBase parser-only/read-only; derive private `DialHost/DialTarget` from url::Host and known/default port. |
| `src/runtime_plan.rs` (new) | Constants 64/16, checked formula 80+R in both modes, runtime-builder input and startup fields. |
| `src/main.rs` | Parse Config first; validate FD/runtime plans; call explicit `max_blocking_threads`; sanitized build failure. |
| `src/server.rs` | Existing AuthExecutor 64 constant shared with RuntimePlan; prior auth/cookie/downstream behavior. |
| `src/proxy.rs` | Private R semaphore; immediate admission; U+R+resolver guard/cleanup; typed target; SocketAddr connector; complete owner/bridge. |
| Tests/artifacts | Auth isolation, R no-queue, address/TLS matrix, thread-memory guidance, and every prior gate. |

Implementation order:

1. Introduce shared auth-worker/runtime constants, R parsing/cap, RuntimePlan, and runtime construction.
2. Add typed parser-built DialTarget and migrate fixtures away from unconstrained UpstreamBase literals.
3. Insert immediate R admission before resolver spawn; carry R+U through cleanup.
4. Pass typed IP/domain/port into existing SocketAddr connector and verify hyper-rustls 0.27.9 identity.
5. Pass new deterministic tests, all prior matrix rows, and four Cargo gates.

## 22. Alternatives considered

### 22.1 Resolver execution isolation

- **U only with Tokio default 512:** rejected; custom U can occupy all auth blocking workers.
- **Scale `max_blocking_threads` to U:** rejected; U may approach `Semaphore::MAX_PERMITS`, creating unsafe thread/memory ceilings.
- **Dedicated custom resolver thread pool:** viable but rejected for this change; requires queue, shutdown, panic, and join machinery beyond the minimal fix.
- **Await an R semaphore:** rejected; retains authenticated request/body and creates resolver waiters.
- **Selected:** R `try_acquire_owned` plus exact shared blocking maximum `64+R+16`; R default8/max32 independent of U.

### 22.2 Runtime margin

- **No margin (`64+R`):** rejected; startup/runtime/library blocking work could consume a reserved lane.
- **Unbounded/default 512:** rejected; masks missing admission and weakens memory control.
- **Selected:** fixed 16, source-audited; new blocking call sites require explicit budget review.

### 22.3 Host classification

- **Parse `http::Uri::host()` at connect:** rejected; bracketed IPv6 is textually ambiguous for `IpAddr` parsing.
- **Strip brackets ad hoc:** implementable but rejected; duplicates URL parsing and risks authority mutation.
- **Public mutable dial fields:** rejected; callers could create authority/dial divergence.
- **Selected:** crate-private parser-built `DialHost/DialTarget` from typed url::Host plus known/default port.

### 22.4 Existing reviewed choices

Explicit resolver handle ownership, SocketAddr-only TCP, untouched URI ServerName, complete driver owner, cancellation relay, atomic pool, bridge order, D/U, RLIMIT, auth/header/XFF/accept/nginx/FRP choices remain unchanged.

## 23. Verification and release gate

Implementation remains blocked until another final `review-rfc` returns PASS. After implementation, preserve all existing tests and run exactly these mandatory commands:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release --bin auth-mini-gateway
```

The test report must record:

- commit/worktree;
- all four command results;
- mapping to every §20 row;
- existing suite counts without treating counts as fixed contracts;
- any native nginx/FRP/full-path deployment evidence attempted;
- explicit environment limitations without printing secrets or raw forwarding values.

A retained test failure is a product failure. Missing physical Acorn/Axiom access in a development run is an environment limitation, but public rollout remains blocked until §15.5 evidence is collected.

## 24. Open questions and accepted residuals

### Blocking open questions

None. Valid R cannot starve the 64 auth-worker lane, no resolver waiter/job exists beyond R, and IPv4/IPv6/domain targets are typed before runtime while URI/TLS identity remains unchanged. Status is **Ready for another final re-review**; implementation remains blocked until PASS.

### Accepted residuals

1. A started libc resolver may retain one bounded R/U pair indefinitely; R prevents multiplication and runtime sizing preserves auth workers.
2. R saturation is an intentional new service-capacity `503` for domain pool misses; IP literals and idle owners bypass R.
3. A DNS-timeout client may receive `502` before both permits return; retries may receive U- or R-capacity `503`.
4. Resolver answer order/cache/ancillary sockets remain OS behavior; FD reserve and R/U bounds remain applicable.
5. Blocking-thread stack/virtual-memory cost is platform-dependent; runtime ceiling is exact, while MemoryMax guidance uses measured stress evidence.
6. HTTPS IP authorities require matching IP SAN and do not gain a DNS-name override; this preserves certificate validation rather than weakening it.
7. All previously accepted driver, pool, backlog, TIME_WAIT, `mem::forget`, restart, trusted-XFF, and deployment-host residuals remain.

Any review finding that changes R/auth isolation, typed address compatibility, TLS identity, or prior terminal proofs returns status to Draft.

## 25. References

- Plan: `.legion/tasks/harden-proxy-production-boundaries/plan.md`
- Research: `.legion/tasks/harden-proxy-production-boundaries/docs/research.md`
- Blocking review addressed: `.legion/tasks/harden-proxy-production-boundaries/docs/review-rfc.md`
- Prior proxy RFC: `.legion/tasks/authenticated-reverse-proxy/docs/rfc.md`
- Prior proxy verification/review: `.legion/tasks/authenticated-reverse-proxy/docs/test-report.md`, `.legion/tasks/authenticated-reverse-proxy/docs/review-change.md`
- Runtime/config/tests: `src/server.rs`, `src/proxy.rs`, `src/config.rs`, `tests/proxy_integration.rs`
- Deployment baseline: `README.md`, `.env.example`, `docs/production-deployment.md`, `examples/nginx.conf`
- Hyper/hyper-rustls upgrade/body/client: <https://docs.rs/hyper/1.10.1/src/hyper/client/conn/http1.rs.html>, <https://docs.rs/hyper/latest/hyper/upgrade/>, <https://docs.rs/hyper-rustls/0.27.9/src/hyper_rustls/connector.rs.html>
- Tokio runtime/resolver/task/semaphore/listener: <https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html>, `tokio-1.52.3/src/net/addr.rs:192-221`, <https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html>, <https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html>, <https://docs.rs/tokio/latest/tokio/sync/struct.OwnedSemaphorePermit.html>, <https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html>
- URL typed host parsing: <https://docs.rs/url/2.5.8/url/enum.Host.html>, <https://docs.rs/url/2.5.8/url/struct.Url.html#method.port_or_known_default>
- Rustls TLS identity: <https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html>
- Linux accept/RLIMIT: <https://man7.org/linux/man-pages/man2/accept.2.html>, <https://man7.org/linux/man-pages/man2/getrlimit.2.html>
- nginx core/proxy/WebSocket: <https://nginx.org/en/docs/http/ngx_http_core_module.html>, <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>, <https://nginx.org/en/docs/http/websocket.html>
- FRP configuration/reference: <https://gofrp.org/en/docs/features/common/configure/>, <https://gofrp.org/en/docs/features/common/authentication/>, <https://gofrp.org/en/docs/reference/proxy/>, <https://gofrp.org/en/docs/reference/server-configures/>, <https://gofrp.org/en/docs/features/common/network/network-tls/>
