# Research: Proxy production-boundary hardening

> **Audience:** implementers and RFC reviewers deciding whether this high-risk availability and trust-boundary change is ready to build.
> **Scope:** repository revision `abe0aae24b055751787e24f9f9023dc837191cc8` on 2026-07-15, including the latest resolver-isolation and IPv6-classification blockers in `docs/review-rfc.md`. This file records evidence and design inputs; `rfc.md` owns revised decisions.
> **Contract:** `.legion/tasks/harden-proxy-production-boundaries/plan.md`.

## 1. Problem restatement

The authenticated proxy is functionally complete, but its production envelope is not. Accepted TCP connections and active upstream exchanges are unbounded, a recoverable `accept()` error exits the process, an HTTP header alias containing `_` can survive to applications that normalize it, unauthenticated fallback performs two separately admitted blocking operations, and the documented Acorn/FRP topology does not provide an executable all-path proxy configuration or a trustworthy client-IP handoff.

The RFC resolves the original six findings and the hidden resolver-handle escape. The latest review found two remaining integration gaps: valid resolver jobs still share Tokio's unbounded blocking queue with the fixed 64-worker auth lane, so arbitrary `U` can starve control work; and connect-time parsing of bracketed `http::Uri::host()` misclassifies valid IPv6 literals. The final design must cap resolver execution independently, reserve blocking threads for auth, and carry a typed `url::Host` result from configuration parsing without changing URI/TLS identity.

## 2. Current code and entry points

| Area | Current behavior and gap | Evidence |
|---|---|---|
| Startup config | `Config` has no downstream/upstream capacity, trusted-proxy, or RLIMIT fields. `validate()` checks only session lifetime ordering. | `src/config.rs:8-28`, `src/config.rs:44-105` |
| Process/runtime boundary | `Config` is parsed before a Tokio multi-thread runtime, but `max_blocking_threads` is not set, so Tokio defaults to 512. | `src/main.rs:7-20`; Tokio Builder docs |
| Listener | The loop calls `listener.accept().await?`; any surfaced error returns from the server. Every accepted connection immediately creates a Tokio task, with no admission bound. | `src/server.rs:109-178` |
| Downstream lifetime | The connection task owns the socket while Hyper serves HTTP/1 with keep-alive and upgrades, but it owns no capacity lease. | `src/server.rs:156-177` |
| Route boundary | Exact gateway-owned paths are classified first. Adapter fallback remains local. Proxy-only validation begins only for a non-owned path in proxy mode. | `src/server.rs:43-51`, `src/server.rs:181-194` |
| Blocking admission | `AuthExecutor` has exactly 64 work permits and 128 active-plus-queued permits. Its `spawn_blocking` calls share Tokio's runtime blocking pool with the proposed libc resolver jobs. | `src/server.rs:64-107`, `src/server.rs:1298-1427` |
| Login fallback | Proxy fallback runs `auth_decision` under one admission and, after `Unauthenticated`, calls `create_login_response` under a second admission. Every second-stage error, including overload or join panic, becomes `500` with the known session-clear cookie. | `src/server.rs:324-367` |
| Shared auth | `/auth/check` and proxy fallback already use one `AuthDecision` preserving lookup, refresh, policy, identity safety, touch, and renewal metadata. | `src/server.rs:670-826` |
| Upstream parsing/resolution | `UpstreamBase` retains only scheme/authority/path. `TcpConnector` reparses `http::Uri::host()` and calls a hostname tuple; bracketed IPv6 can be misclassified and hostname resolution shares Tokio blocking capacity. | `src/config.rs:30-35,108-138`; `src/proxy.rs:865-893`; Tokio 1.52.3 `src/net/addr.rs:192-221` |
| Upstream connection | `connect()` handshakes, spawns `connection.with_upgrades()`, discards the `JoinHandle`, and returns only `SendRequest`. The spawned future—not the sender—owns the transport I/O. | `src/proxy.rs:208-223`; Hyper 1.10.1 client source lines 22-67 |
| Upstream pool | The eight-entry idle pool stores only senders. It cannot abort/join the corresponding connection drivers or prove process FD release on non-reuse. | `src/proxy.rs:39-40`, `src/proxy.rs:62-73`, `src/proxy.rs:781-862` |
| Upstream response | A sender is returned after response EOS; cancellation/error drops it. Early final cancels upload and disables reuse, but the detached driver may still own I/O until separately polled/dropped. | `src/proxy.rs:145-205`, `src/proxy.rs:781-862` |
| WebSocket | On valid upstream `101`, both `OnUpgrade` handles are moved to a spawned bridge. No driver `JoinHandle` is retained to observe I/O transfer/completion. | `src/proxy.rs:151-165`, `src/proxy.rs:640-657` |
| Request headers | Browser credentials, forwarding fields, spoofed identity, hop-by-hop, and `Connection`-nominated fields are removed. There is no pre-auth rejection for header names containing `_`. | `src/proxy.rs:238-253`, `src/proxy.rs:326-373` |
| Client IP | Inbound forwarding fields are removed and upstream XFF is regenerated from the direct TCP peer. There is no opt-in trusted-peer path. | `src/proxy.rs:347-361` |

## 3. Established proxy contract that remains authoritative

The completed `authenticated-reverse-proxy` task is the compatibility baseline:

- `UPSTREAM_URL` remains optional and fixed; adapter mode is the configuration rollback path.
- Six exact gateway paths stay local for every method.
- One shared authentication decision owns refresh, Pending identity recovery, exact allowlists, touch, cleanup, and renewal metadata.
- Hyper is the framing authority; proxy bodies stream without collection; trailers and cross-proxy framing fields are discarded/regenerated.
- Every fallback request has one low-level upstream send attempt. A stale pooled connection fails `502`; no request is replayed.
- Early final responses stop upload polling and prohibit reuse.
- WebSocket handshakes are validated before downstream `101`, then bytes are bridged opaquely.
- App cookies precede gateway renewal; unauthenticated login emits session clear before login-state cookie.

Evidence:

- `.legion/tasks/authenticated-reverse-proxy/docs/rfc.md`
- `.legion/tasks/authenticated-reverse-proxy/docs/test-report.md` — four mandatory Cargo commands passed; 55 unit and 13 integration tests passed.
- `.legion/tasks/authenticated-reverse-proxy/docs/review-change.md` — security review PASS after early-final, identity-byte, WebSocket nomination, and TLS-root fixes.
- `.legion/wiki/tasks/authenticated-reverse-proxy.md`
- `.legion/wiki/patterns.md:70-84`

The current revision must strengthen ownership and evidence without changing these runtime/security choices.

## 4. Resolver isolation, typed host parsing, and connection lifecycle

### 4.1 Downstream and established post-handshake ownership

The reviewed downstream lease, complete sender+driver owner, atomic idle park, abort+join retirement, and bridge-before-`101` transfer remain sound. No new finding changes those decisions.

### 4.2 Explicit resolver ownership closes detachment, not starvation

Tokio 1.52.3 implements hostname `ToSocketAddrs` through `spawn_blocking`; started blocking work cannot be aborted and dropping its handle detaches it. The revised explicit `ResolutionAttemptGuard` correctly retains handle plus active permit through join or cleanup. This prevents resolver jobs multiplying beyond active admission.

However, `AuthExecutor` and resolver jobs still use the same Tokio blocking pool. Tokio's default `max_blocking_threads` is 512 and its blocking queue has no application backpressure. A valid custom `U=512` can start 512 stuck resolver closures, leaving no blocking thread for the fixed 64 auth workers. Bounding jobs by `U` therefore does not isolate control-plane execution.

### 4.3 Minimal implementable resolver execution domain

Use two controls together:

1. a private resolver semaphore with immediate `try_acquire_owned`, so no resolver waiter is created and no `spawn_blocking` job is submitted without capacity;
2. an explicitly sized shared Tokio blocking pool that reserves the complete auth lane plus resolver lane plus fixed runtime margin.

Constants/setting selected for the RFC:

```text
AUTH_BLOCKING_WORKERS       = 64   # existing AuthExecutor work permits
DEFAULT_BLOCKING_RESOLVERS  = 8
MAX_BLOCKING_RESOLVERS      = 32
BLOCKING_RUNTIME_MARGIN     = 16

proxy max_blocking_threads  = 64 + R + 16
adapter max_blocking_threads = 64 + R + 16
```

Thus either mode defaults to blocking maximum 88 and has hard maximum 112. Tokio documents that blocking-thread capacity is independent of async worker threads and threads are created on demand. `R` is positive, capped at 32, and has no required relationship to `U`; effective domain-resolution concurrency is `min(R,U)`. This prevents arbitrary `U` from scaling OS threads.

A pool miss for a domain performs immediate R admission after U admission. R saturation returns the same external service-capacity `503` as U saturation, with due renewal and no body poll/resolver submission/connect. IP literals and idle complete-owner hits do not consume R.

Once submitted, a resolver attempt/cleanup owns **R permit + U permit + JoinHandle** until handle observation. A queued closure is aborted/joined; a started closure is awaited. A stuck resolver consumes one bounded R/U pair but cannot submit a replacement or occupy any of the 64 reserved auth-worker capacity. The 16-thread runtime margin covers startup/runtime/library blocking activity and future audited direct Tokio blocking call sites; a source audit must fail if an unbudgeted production `spawn_blocking` site appears.

Sources retrieved through Context7 on 2026-07-15:

- Tokio `Builder::max_blocking_threads`, default 512, and independence from async workers: <https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html>
- Tokio `spawn_blocking` abort behavior: <https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html>

### 4.4 Thread budget is separate from FD/RLIMIT budget

Resolver jobs are still mutually exclusive U phases, so the checked FD formulas remain unchanged. Thread/task limits and memory are separate:

- runtime blocking ceiling is exact from the formula above;
- async worker threads retain current Tokio behavior and are not included in `max_blocking_threads`;
- systemd `TasksMax`, user/process thread limits, and memory must be checked separately from `LimitNOFILE`;
- blocking threads are lazy, but worst-case rollout must run R stuck-resolver fixtures plus 16 margin fixtures and 64 auth jobs and record `/proc/<pid>/status` `Threads`, `VmRSS`, and `VmSize`;
- if `MemoryMax` is used, retain at least 25% above measured worst-case RSS; do not estimate FD safety from thread limits or vice versa.

### 4.5 Typed host extraction at configuration time

`url` 2.5.8 already parses hosts into `Host::Ipv4`, `Host::Ipv6`, or normalized `Host::Domain`. Its `Url::host()` returns typed IPv6 without brackets, and `port_or_known_default()` returns explicit or scheme-default ports. The URL parser also IDNA-normalizes special-scheme domains.

Extend the parsed upstream concept with a crate-private dial target:

```text
DialHost::Ip(IpAddr)
DialHost::Domain(Box<str>)   # normalized URL domain
DialTarget { host: DialHost, port: u16 }
```

`UpstreamBase` retains its canonical parsed scheme, authority, and path prefix unchanged and additionally stores `DialTarget`. All four become parser-owned/private with read-only crate access, preventing later authority/dial mutation. Build the target exactly once in `parse_upstream_url`:

- `url::Host::Ipv4(v4)` -> `IpAddr::V4(v4)`;
- `url::Host::Ipv6(v6)` -> `IpAddr::V6(v6)`;
- `url::Host::Domain(name)` -> owned normalized domain;
- port -> `parsed.port_or_known_default()`, which is always present for accepted HTTP/HTTPS.

Never classify from bracketed `http::Uri::host()` during connect. IP variants directly form `SocketAddr::new(ip, port)` (IPv6 scope/flow zero) and spawn no resolver. Domain variants alone enter R admission and owned resolution. Do not reconstruct or mutate authority from `DialTarget`.

Sources:

- Context7 Rust URL docs: `Url::host`, typed `Host`, `port_or_known_default`.
- Pinned url 2.5.8 source: `src/lib.rs:1170-1207,1244-1303`; `src/host.rs:77-120`.

### 4.6 SocketAddr dialing and hyper-rustls 0.27.9 identity

The fresh inner connector continues to dial only resolved/direct `SocketAddr` candidates. The original configured connector URI remains scheme + canonical authority. Pinned hyper-rustls 0.27.9 derives `ServerName` from that URI before calling the inner connector, strips IPv6 brackets, then performs TLS with that server name (`connector.rs:103-120,148-168`).

Consequences:

- domain target: normalized domain is resolver input; original URI host remains DNS TLS identity/SNI;
- IPv4/IPv6 target: direct SocketAddr, zero resolver/R usage; original IP authority produces rustls IP identity, requiring matching IP SAN and never substituting a DNS name;
- explicit/default port changes only the dial SocketAddr; authority serialization remains the existing URL-derived source for Host/URI/TLS behavior.

### 4.7 Phase-linear cleanup remains unchanged

One U permit moves through pool checkout, optional R+resolver handle, resolved connect/TLS/handshake, complete owner, response cleanup/idle park, or bridge. R releases only after resolver handle observation; U continues into connect on success or remains with cleanup on timeout/cancellation. All previously reviewed driver and bridge cleanup remains unchanged.

## 5. Listener, logging, and fatal-exit findings

Tokio `TcpListener::accept()` surfaces `io::Result`; Linux distinguishes:

- process/system FD pressure: `EMFILE`, `ENFILE`;
- socket-buffer/memory pressure: `ENOBUFS`, `ENOMEM`;
- interrupted/per-connection failures: `EINTR`, `ECONNABORTED`;
- pending TCP/IP errors recommended for retry: `ENETDOWN`, `EPROTO`, `ENOPROTOOPT`, `EHOSTDOWN`, `ENONET`, `EHOSTUNREACH`, `EOPNOTSUPP`, `ENETUNREACH`;
- listener invariants such as `EBADF`, `EFAULT`, `EINVAL`, and `ENOTSOCK`.

Backoff streak and log suppression solve different problems. A class change may reset delay but must not make every alternating error log as “first.” Logging needs a global consecutive-failure sequence and monotonic rate limiter independent of class, with suppressed-count summaries and success reset.

Returning a raw fatal `io::Error` from the current `main() -> Result` allows Rust to format its Display/source chain to stderr after an intended structured event. The runtime must instead convert the error into a non-source-bearing sanitized exit classification. `main` emits exactly one allowlisted structured fatal event and exits nonzero explicitly; it never returns the original error.

Source: Linux `accept(2)`, <https://man7.org/linux/man-pages/man2/accept.2.html>.

## 6. Authentication phase boundary

Moving login-state creation into the first admitted closure removes the overload race, but phase-specific panic behavior matters:

- a panic before `AuthDecision` returns leaves no known cookie metadata and must remain cookie-neutral `500`;
- after `Unauthenticated { clear_session }` exists, login-state construction owns known cleanup metadata;
- recoverable DB failure **or panic** during that construction must be caught inside the closure and become `LoginInternal { clear_session }`;
- overload occurs before the closure and remains cookie-neutral auth `503`.

The injected post-decision panic seam must be inside the `catch_unwind` region. The outer `spawn_blocking` join error is reserved for pre-decision/uncontained internal failure.

## 7. nginx alias boundary and rollback

nginx has two independent directives:

- `underscores_in_headers on` makes underscore names available to the hardened gateway for fixed `400` rejection.
- When underscores are off, `ignore_invalid_headers on` is what discards fields nginx considers invalid.

Both are inheritable. A secure proxy-mode server must pin `underscores_in_headers on;` and `ignore_invalid_headers on;`. Rollback to a pre-gate binary must pin underscore handling off **while retaining invalid-header dropping on**, validate with `nginx -t`, reload under maintenance, and raw-probe through the same server configuration before old-binary exposure. Artifact tests must reject either missing directive.

Official nginx references: <https://nginx.org/en/docs/http/ngx_http_core_module.html>, <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>.

## 8. Executable FD and blocking-thread budgets

Checked FD budgets remain:

```text
proxy base budget   = D + U + 8 + 1 + 512
adapter base budget = D + 1 + 512
```

Default proxy is 905, adapter 769, and `LimitNOFILE=4096` remains sufficient. R adds no FD term because every resolver is already one mutually exclusive U phase; resolver ancillary descriptors remain in the 512 reserve.

Blocking-thread capacity is validated separately:

```text
proxy max_blocking_threads   = 64 + R + 16   # default 88; hard max 112
adapter max_blocking_threads = 64 + R + 16   # default 88; hard max 112
```

`Config::from_env` must parse/validate R before runtime construction. The explicit `main` boundary then applies `.max_blocking_threads(runtime_plan.blocking_max)` before `.build()`. Runtime construction failure remains sanitized. The cap is independent of arbitrary U.

Rollout records `LimitNOFILE` separately from `TasksMax`, `MemoryMax`, process thread limits, and observed thread/RSS peaks. `TasksMax` must leave room for main + async workers + configured blocking maximum + non-Tokio process margin; memory guidance is based on measured worst-case because platform stack reservation is not an FD quantity.

## 9. Trusted forwarding and FRP hardening inputs

The minimal forwarding algorithm remains sound: trust only the immediate peer CIDR, ignore all untrusted XFF syntax, accept one bare `IpAddr` from a trusted peer, delete all inbound forwarding fields, and emit one canonical value. Forwarded IP remains absent from auth, return-target, destination, TLS, and pool APIs.

Additional hardening evidence is required:

- an IPv4-mapped IPv6 peer does not match an IPv4 CIDR unless its exact IPv6-mapped CIDR is configured;
- opaque/non-ASCII XFF from an untrusted peer is ignored and regenerated from the peer;
- the same opaque value from a trusted peer fails fixed `400` without raw-value logging.

FRP `auth.tokenSource` requires frp **v0.64.0 or newer**. The Axiom client must set `transport.tls.serverName = "frp.example.com"` explicitly rather than relying on the `serverAddr` default.

References: <https://gofrp.org/en/docs/features/common/authentication/>, <https://gofrp.org/en/docs/features/common/network/network-tls/>.

## 10. Test surface and deterministic seams

`tests/proxy_integration.rs` already provides raw TCP clients, controllable HTTP/SSE/WebSocket upstreams, hit counters, stale-pool and early-final fixtures, TLS injection, and real-binary stderr capture. New seams/evidence must include:

- injectable capacities and a raw `Expect: 100-continue` saturation client that withholds marker body bytes and pins status, fixed headers, 31-byte body, EOF, body-poll count, cookies, hit count, and control health;
- an injected R semaphore/resolver handle with queued/started markers, abort/join barrier, live-resolver/cleanup counters, plus pre-owner I/O and complete-driver barriers;
- R default/max/invalid/runtime-formula tests; R blocked jobs reject R+1 before spawn while 64 auth work items start/complete; U>R and no-wait saturation; both permits survive timeout/cancel; no hidden submitted queue;
- a login-state builder that can return DB error or panic after `Unauthenticated`;
- separate accept backoff and global logging clocks/state, with captured stderr at the explicit process boundary;
- injected finite/infinite RLIMIT values and checked-budget arithmetic;
- trusted-peer tests for mapped IPv6 and opaque header bytes;
- static nginx/FRP artifacts pinning both header directives, minimum FRP version, and TLS server name.

Resolver barriers must prove unique jobs in request-owned resolution plus resolver-cleanup phases never exceed both `R` and `U`; live blocking closures are an overlapping subset, not a second additive count. Replacement resolution/connect cannot begin until the prior handle is observed. Typed-host tests cover IPv4, bracketed IPv6, normalized domains, explicit/default ports, and zero resolver submissions for both IP families. TLS tests cover hostname SNI plus IPv4/IPv6 IP-SAN identity while retaining original authority. No test should lower RLIMIT, exhaust host FDs, use external DNS, or depend on scheduler timing.

## 11. Risks and design inputs

1. **Shared blocking-pool starvation:** U alone can exceed Tokio's default pool; independent R plus exact blocking maximum is required.
2. **Hidden resolver queue:** acquiring R must be immediate and precede `spawn_blocking`; R+1 cannot submit.
3. **Started resolver retention:** libc work can be unabortable; it must retain both R/U until join.
4. **IPv6 misclassification:** bracketed `http::Uri` text is not a valid `IpAddr`; classification belongs at typed URL parsing.
5. **TLS identity drift:** dial IP must never replace original URI authority/ServerName.
6. **Detached driver/cleanup/upgrade risks:** all previously reviewed complete-owner and relay controls remain mandatory.
7. **Thread memory versus FDs:** RLIMIT cannot validate thread count, stack reservation, TasksMax, or MemoryMax.
8. **Permit leakage:** wrappers cannot prevent deliberate `mem::forget`; privacy/review/tests remain controls.
9. **Existing cookie/log/alias/trust/deployment risks:** prior controls remain unchanged.

## 12. Residual deployment evidence, not design unknowns

No design question remains after R-isolated resolver ownership and typed host classification. Rollout must still collect environment-specific evidence:

- confirm Acorn frps binds remote port `18081` only on loopback and both frp processes are v0.64.0+;
- confirm Axiom gateway observes frpc as the intended peer before enabling its CIDR;
- confirm gateway `7780` and OpenCode `4096` are loopback-only;
- record calculated FD budget/effective `LimitNOFILE` separately from runtime blocking maximum, `TasksMax`, `MemoryMax`, process thread limits, and stressed Threads/RSS/virtual-memory evidence;
- validate staged nginx/FRP configuration with native verify commands;
- execute the maintenance-gated raw underscore rollback probe before any old-binary exposure.

Failure of any check blocks trusted-proxy enablement, rollback exposure, or public cutover; it does not require a different software design.

## 13. Evidence index

- Contract: `.legion/tasks/harden-proxy-production-boundaries/plan.md`
- Adversarial review: `.legion/tasks/harden-proxy-production-boundaries/docs/review-rfc.md`
- Completed proxy evidence: `.legion/tasks/authenticated-reverse-proxy/docs/{research,rfc,review-rfc,test-report,review-change,report-walkthrough}.md`
- Runtime: `src/server.rs`, `src/proxy.rs`, `src/config.rs`, `src/main.rs`
- Tests: `tests/proxy_integration.rs`, inline tests under `src/*.rs`
- Deployment: `README.md`, `.env.example`, `docs/production-deployment.md`, `docs/README.md`, `examples/nginx.conf`
- Hyper/hyper-rustls client and upgrade: <https://docs.rs/hyper/1.10.1/src/hyper/client/conn/http1.rs.html>, <https://docs.rs/hyper/latest/hyper/upgrade/>, <https://docs.rs/hyper-rustls/0.27.9/src/hyper_rustls/connector.rs.html>
- Tokio runtime/resolution/task/semaphore/listener: <https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html>, `tokio-1.52.3/src/net/addr.rs`, <https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html>, <https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html>, <https://docs.rs/tokio/latest/tokio/sync/struct.OwnedSemaphorePermit.html>, <https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html>
- URL typed host parsing: <https://docs.rs/url/2.5.8/url/enum.Host.html>, <https://docs.rs/url/2.5.8/url/struct.Url.html#method.port_or_known_default>
- Rustls TLS identity: <https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html>
- Linux accept/RLIMIT: <https://man7.org/linux/man-pages/man2/accept.2.html>, <https://man7.org/linux/man-pages/man2/getrlimit.2.html>
- nginx core/proxy/WebSocket: <https://nginx.org/en/docs/http/ngx_http_core_module.html>, <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>, <https://nginx.org/en/docs/http/websocket.html>
- FRP configuration/auth/TLS: <https://gofrp.org/en/docs/features/common/configure/>, <https://gofrp.org/en/docs/features/common/authentication/>, <https://gofrp.org/en/docs/features/common/network/network-tls/>
