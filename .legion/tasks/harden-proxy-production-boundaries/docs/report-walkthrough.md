# Delivery walkthrough: harden proxy production boundaries

> Mode: `implementation`
> Labels: `high-risk`, `security`, `availability`
> Merge readiness: implementation verification **PASS**, security review **PASS**
> Production readiness: **BLOCKED** until native Acorn/Axiom rollout gates pass
> Compatibility: no SQLite schema, cookie/session format, allowlist, or auth-mini change

## Reviewer decision

All five production-review groups are closed:

| Finding | Resolution |
|---|---|
| Unbounded connections and fatal recoverable accept errors | Pre-accept downstream capacity, full-lifetime upstream/resolver ownership, RLIMIT/runtime budgets, bounded retry |
| Underscore header aliases | Proxy fallback rejects the request with fixed `400` before auth/upstream |
| Second login admission overload | Auth decision and login-state creation share one admission; overload is cookie-neutral `503` |
| Untrusted or lost browser IP | Explicit direct-peer CIDRs and one strict canonical XFF value with no auth/routing influence |
| Incomplete Acorn/FRP deployment | Exact `18081 -> 7780 -> 4096` nginx/FRP/systemd artifacts and rollback |

No code finding remains. Native deployment evidence is intentionally separate from implementation readiness.

## Capacity and lifecycle

| Budget | Default | Behavior |
|---|---:|---|
| D: downstream connections | 256 | Acquired before `accept()` and retained through keep-alive, uploads, SSE, and full WebSocket bridge. Saturation pauses accept without creating an FD/task/rejection queue. |
| U: active upstreams | 128 | Acquired after `Allow` and retained through DNS/TCP/TLS/HTTP, complete sender+driver ownership, body/SSE cleanup, or WebSocket completion. |
| R: blocking resolvers | 8, range 1..=32 | Immediate domain resolver admission; effective concurrency `min(R,U)`. IP literals and warm pooled owners bypass R. |

Proxy mode requires `D >= U + 16`. Tokio blocking capacity is exactly `64 auth + R + 16 margin`, or 88 by default.

U/R saturation returns fixed `503` plus `Retry-After: 5`, with no `100 Continue`, request-body poll, DNS/connect/application hit, or replay. Only a due gateway renewal cookie may be appended.

## Connection and DNS ownership

- A complete upstream owner contains Hyper `SendRequest` plus its connection-driver `JoinHandle`.
- Non-idle retirement drops sender, aborts driver, observes join, then returns U.
- Reusable owners park atomically in the eight-entry idle pool before U returns.
- Resolver cleanup owns U + R + resolver handle until completion is observed.
- A stuck resolver consumes one bounded U/R pair but cannot submit replacement work or consume the 64-worker auth lane.
- IPv4 and bracketed IPv6 become direct `SocketAddr` values and consume no R; domains alone resolve.
- The configured authority remains the HTTP/TLS identity.
- TCP candidate fallback ends at first TCP success; TLS/HTTP/send/pool failures never replay.
- WebSocket bridge owns both upgrades, U, driver owner, and a cloned D lease before downstream `101` returns.

## Listener and process safety

- Recoverable accept errors retry inline with deterministic transient/resource backoff.
- Logging uses a global suppression schedule across changing error classes.
- Fatal listener errors become one sanitized non-source event and nonzero exit.
- `runtime.shutdown_background()` prevents an unfinishable resolver from blocking systemd restart.
- Panic-time output is one direct static `libc::write`, with no stdio lock, allocation, formatting, tracing, payload, location, or path.

## Request trust boundary

- Any underscore header name on non-owned proxy fallback returns no-store `400` before auth, DB, login state, DNS, or upstream work.
- Owned routes and adapter fallback remain compatible.
- Anonymous auth and login-state creation share one admission.
- Admission overload is cookie-neutral `503`; post-Unauth DB error/panic is clear-only `500`; pre-decision panic is cookie-neutral `500`.
- `TRUSTED_PROXY_CIDRS` defaults empty and trusts only the immediate peer.
- Trusted XFF accepts one bare IPv4/IPv6 value; repeated/list/port/bracket/zone/whitespace/opaque values fail `400`.
- All forwarding fields are removed and regenerated. Client IP cannot enter auth, policy, return targets, route selection, DNS, TCP, TLS, or pooling.

## Production topology

```text
Browser
  -> Acorn nginx TLS :443
  -> Acorn 127.0.0.1:18081 (frps remotePort)
  -> FRP tunnel
  -> Axiom gateway 127.0.0.1:7780
  -> OpenCode 127.0.0.1:4096
```

Artifacts:

- `examples/nginx-proxy.conf`: all paths, browser Cookie, Host/proto, WebSocket, SSE/uploads, buffering/retry off, underscore on + invalid headers on.
- `examples/frps.toml` and `examples/frpc.toml`: loopback remote/local ports, token-file auth, TLS CA/serverName, frp v0.64.0+.
- `examples/auth-mini-gateway.service`: `LimitNOFILE=4096`, restart policy, hardening.
- `examples/nginx-proxy-rollback.conf`: old-binary gate with underscores off and invalid-header dropping on.

## Verification

```text
cargo fmt --check                                        PASS
cargo clippy --all-targets --all-features -- -D warnings PASS
cargo test                                               PASS (90 unit, 27 integration)
cargo build --release --bin auth-mini-gateway            PASS
cargo check --all-targets                                PASS
git diff --check                                         PASS
```

Repository proxy, mode-switch, old-binary compatibility, and WAL drills passed. The final focused set passed 20 combined cycles. Final security review is PASS with no code finding.

## Safe rollback

1. Enable maintenance deny.
2. Apply rollback nginx with underscores off and invalid-header dropping on.
3. Run `nginx -t`, reload, and raw-probe an underscore header while the hardened gateway still runs.
4. Require normal anonymous `302`, zero OpenCode hit, and not the hardened underscore `400`.
5. Only then start the previous binary on `127.0.0.1:7780`.
6. Verify auth, cookies, HTTP, SSE, and WebSocket before removing maintenance.

No DB restore is required. Never expose the old binary while underscore pass-through is on and never map FRP to `4096`.

## Rollout checklist

- [ ] Native Acorn `nginx -t`, reload, hardened probe, and old-binary rollback probe.
- [ ] Native frps/frpc verification with deployed token/certificate files.
- [ ] Firewall proof for `:443 -> 18081 -> 7780 -> 4096`, with no unintended public/FRP listener.
- [ ] Effective systemd `LimitNOFILE`, `TasksMax`, and `MemoryMax`.
- [ ] Production Threads/VmRSS/VmSize under R + 16 + 64-auth stress.
- [ ] Staged HTTP/upload/SSE/WebSocket, U/R saturation, health, no-replay, and owner accounting.
- [ ] Observe exact frpc peer and canonical nginx XFF before enabling only that CIDR.
- [ ] Restore pinned auth-mini checkout and pass the real-auth script.

## Evidence

- [Stable plan](../plan.md)
- [Final RFC](rfc.md)
- [Final RFC review](review-rfc.md)
- [Final test report](test-report.md)
- [Final security review](review-change.md)
