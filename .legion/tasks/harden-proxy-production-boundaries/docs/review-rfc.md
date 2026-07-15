# Final adversarial RFC re-review: harden proxy production boundaries

> **Reviewed:** 2026-07-15
> **Inputs:** stable `plan.md`, final `docs/research.md` and `docs/rfc.md`, all prior RFC reviews, current runtime/tests, pinned Tokio 1.52.3, url 2.5.8, Hyper 1.10.1, hyper-rustls 0.27.9, and rustls behavior
> **Review type:** final pre-implementation availability/authentication/trust-boundary gate
> **Verdict:** **PASS**

## Gate decision

No blocking finding remains. The final RFC closes resolver starvation and IPv6 classification without weakening explicit resolver/driver ownership, TLS identity, no-replay behavior, overload/cookie mappings, rollback, or verification.

Implementation may proceed under `legion-workflow`. This is a design PASS only; release still requires every RFC §20 row, retained test, deployment gate, and mandatory Cargo command.

## Final resolution verification

### Resolver execution isolation — PASS

- `GATEWAY_MAX_BLOCKING_RESOLVERS` defaults to `8`, accepts exactly `1..=32`, and is independent of arbitrary `U`; effective submitted domain resolvers are `<= min(R,U)`.
- A domain pool miss acquires U and then uses immediate `R.try_acquire_owned()`. R saturation creates no waiter or blocking submission, releases U, and returns the exact service-capacity `503` with due renewal and no body poll/DNS/connect/hit.
- Every submitted resolver owns U + R + its `JoinHandle`. Timeout/cancellation relays all three; queued work is aborted/joined and started libc work is awaited. Neither permit returns before handle observation.
- Tokio is built only after validated Config with exact `max_blocking_threads = 64 + R + 16`: default `88`, maximum `112`, in proxy and adapter modes.
- At most R resolver closures can consume the shared pool, leaving capacity for all 64 `AuthExecutor` work permits plus 16 audited runtime/library slots. R does not scale with U and R+1 cannot enter Tokio's unbounded blocking queue.
- Deterministic tests block R resolvers and all 16 margin fixtures while proving all 64 auth jobs, including `/auth/check`, start and complete before resolver release. Custom `U > R`, waiter cancellation, submitted-handle accounting, and runtime-plan drift are pinned.

There is no U/R acquisition deadlock: code always owns U first and performs a non-waiting R try; no path owns R while waiting for U.

### Typed dial target and TLS identity — PASS

- `parse_upstream_url` derives private `DialHost::Ip`/`DialHost::Domain` and port once from typed `url::Host` plus `port_or_known_default()`.
- `Host::Ipv4` and unbracketed typed `Host::Ipv6` form exact `SocketAddr` values with zero R/resolver work. Bracketed authority text is never reparsed at connect time.
- Domains use URL-normalized/IDNA ASCII only for explicit resolution. The canonical parsed scheme/authority/path remain separate, private, read-only, and are never reconstructed from DNS answers or `DialTarget`.
- The fresh inner connector dials only direct/resolved `SocketAddr` candidates. The untouched connector URI reaches hyper-rustls 0.27.9, which derives `ServerName` before invoking the inner connector; DNS authorities retain hostname SNI/DNS SAN verification and IP authorities retain exact IP SAN verification.
- Explicit/default ports, IPv4, bracketed IPv6, normalized domains, hostname certificates, and IPv4/IPv6 IP-SAN controls all have deterministic tests.

### DNS through WebSocket lifecycle — PASS

The ownership chain is phase-linear:

```text
U admission
  -> optional immediate R admission + resolver handle
  -> resolved SocketAddr TCP/TLS/HTTP handshake
  -> complete sender + Hyper driver owner
  -> response body / driver cleanup / atomic idle pool
  -> or guarded upgraded bridge
```

- Resolver join is observed before R release or TCP start; U moves into the connect attempt without a gap.
- Resolved connector/TLS/handshake futures own current I/O and drop it before U on failure/cancellation.
- Multi-address fallback occurs only after TCP-connect failure and before TLS/HTTP. First TCP success stops fallback; TLS, HTTP handshake, ready, send, or response failure never chooses another address or replays a request.
- Every post-handshake non-idle path drops sender, aborts the driver, observes join, and only then releases U.
- Reusable EOS parks the complete owner before U return with no await while holding the pool lock; full/poisoned paths unlock before retirement.
- The bridge task receives both upgrades, driver handle, U, and downstream lease before the handler returns `101`; after transfer, both I/Os drop before leases on EOF/error/panic/cancellation.
- Resolver and driver cleanup relays keep unchanged permit/handle jobs across cancel-safe awaits and fail-stop rather than release early if replacement scheduling is impossible.

No new deadlock, detached task, FD escape, request replay, or capacity-release gap is present in the design.

## Earlier blocker reconfirmation

| Boundary | Result |
|---|---|
| Pre-accept downstream bound and Arc-backed upgrade lease | **PASS** |
| Complete upstream sender+driver ownership and abort/join teardown | **PASS** |
| Immediate U/R `503`, renewal cookie, no `100`/body poll/replay | **PASS** |
| Exact FD budgets and effective soft `RLIMIT_NOFILE` validation | **PASS** |
| Recoverable accept classification/backoff, global log suppression, sanitized fatal exit | **PASS** |
| Proxy-only underscore rejection and nginx on/on, rollback off/on raw-probe order | **PASS** |
| One-admission auth/login and post-Unauth panic clear-cookie mapping | **PASS** |
| Trusted CIDR/single-IP XFF parsing and auth/routing non-influence | **PASS** |
| Exact nginx/FRP topology, Cookie/Host/proto/WS/SSE/upload/retry behavior | **PASS** |
| Deterministic verification and secret-free observability | **PASS** |

## Accepted residual risks

1. A started libc resolver cannot be aborted and may retain one bounded R/U pair indefinitely. R caps multiplication and runtime sizing preserves all 64 auth workers.
2. R saturation intentionally returns service-capacity `503` for domain fresh-connect pool misses; IP literals and idle-owner hits bypass R.
3. A DNS-timeout client may receive `502` before U/R return; retries may receive U- or R-capacity `503`.
4. Resolver answer order/cache and ancillary DNS sockets remain libc/OS behavior. Answers are not logged; jobs and FDs remain covered by R/U plus reserve assumptions.
5. Blocking-thread stack and virtual-memory cost is platform-dependent. `TasksMax`, process thread limits, `MemoryMax`, and stressed Threads/RSS/virtual-memory evidence remain rollout gates separate from RLIMIT.
6. Sequential fallback may contact multiple resolved IPs at TCP level, but only one TLS/HTTP/send attempt occurs.
7. An aborted Hyper driver that stops yielding can retain one active slot indefinitely; it cannot release capacity or create replacement FDs.
8. Pool poisoning may strand at most eight budgeted idle owners until process exit.
9. Downstream headroom is not a reservation; malicious idle downstream connections can consume it.
10. Kernel TIME_WAIT, deliberate `mem::forget`, trusted-XFF informational risk, non-graceful restart, and physical nginx/FRP/firewall/rollback evidence remain previously accepted residuals.

## Final decision

**PASS.** The RFC is implementable, verifiable, and rollbackable. Hand back to `legion-workflow` for implementation; no production rollout is approved by this design review alone.
