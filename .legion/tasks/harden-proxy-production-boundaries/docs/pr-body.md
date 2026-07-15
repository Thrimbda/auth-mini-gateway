## Summary

> **Labels:** `high-risk`, `security`, `availability`
> **Implementation:** **PASS, merge candidate**
> **Production rollout:** **BLOCKED** on native Acorn/Axiom gates

Closes all production-review findings from authenticated proxy launch:

- bounds downstream, active-upstream, resolver, driver, and DNS lifetimes;
- retries recoverable accept failures without process exit or spin;
- rejects underscore header aliases before authentication/upstream access;
- removes the second independently overloaded login admission;
- adds explicit trusted-peer client-IP forwarding without auth/routing influence;
- provides the exact Acorn `18081 -> Axiom 7780 -> OpenCode 4096` deployment and rollback.

No SQLite schema, gateway cookie/session format, allowlist/auth behavior, or auth-mini code changes.

## Key behavior

- D/U/R defaults: `256/128/8`; R range `1..=32`; proxy headroom at least 16.
- Runtime blocking capacity: `64 auth + R + 16`, default 88.
- Default proxy FD startup budget: 905; production unit uses `LimitNOFILE=4096`.
- D is held across HTTP/SSE/upload/WebSocket lifetime.
- U owns DNS/TCP/TLS/HTTP, complete sender+driver, response cleanup, or tunnel lifetime.
- R owns explicit domain resolution; IP literals and warm pools bypass R.
- U/R saturation is exact `503` + `Retry-After`, no `100`, body poll, DNS/connect/hit, or replay.
- Fatal accept uses non-waiting runtime shutdown and one sanitized exit.
- Panic hook is a direct static syscall write with no payload/location/lock.
- Trusted XFF defaults off and accepts one strict IP only from an explicitly trusted direct peer.

## Verification

- [x] `cargo fmt --check`
- [x] `cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test` - 90 unit + 27 integration
- [x] `cargo build --release --bin auth-mini-gateway`
- [x] `cargo check --all-targets`
- [x] `git diff --check`
- [x] proxy, mode-switch, old-binary, and WAL repository drills
- [ ] real-auth-mini wrapper: pinned external checkout absent

Final security review: **PASS**, no code finding.

## Reviewer focus

1. `src/config.rs`, `src/runtime_plan.rs`, `src/main.rs`: limits, RLIMIT, runtime and exit.
2. `src/capacity.rs`, `src/server.rs`, `src/exit.rs`: D lease, accept retry, panic/auth/header/XFF boundaries.
3. `src/proxy.rs`: U/R, DNS, complete owner, TLS, pooling, retirement, WebSocket.
4. `tests/proxy_integration.rs`: raw saturation, process, lifecycle, TLS, XFF, deployment artifacts.
5. `docs/production-deployment.md` and `examples/`: native rollout and rollback.

## Rollout remains blocked

- Native Acorn nginx validation/reload/raw probes.
- FRP verification with deployed credentials and certificates.
- Physical/firewall proof of `:443 -> 18081 -> 7780 -> 4096`.
- Effective systemd `LimitNOFILE`, `TasksMax`, `MemoryMax` and production memory/thread stress.
- Exact frpc peer observation before enabling trusted CIDRs.
- Pinned real-auth-mini compatibility run.

Do not remove maintenance deny until all deployment gates pass. Rollback must set underscores off while retaining invalid-header dropping before exposing an older binary. Never map FRP directly to `4096`.

## Evidence

- [Plan](.legion/tasks/harden-proxy-production-boundaries/plan.md)
- [RFC](.legion/tasks/harden-proxy-production-boundaries/docs/rfc.md)
- [RFC review](.legion/tasks/harden-proxy-production-boundaries/docs/review-rfc.md)
- [Test report](.legion/tasks/harden-proxy-production-boundaries/docs/test-report.md)
- [Security review](.legion/tasks/harden-proxy-production-boundaries/docs/review-change.md)
- [Walkthrough](.legion/tasks/harden-proxy-production-boundaries/docs/report-walkthrough.md)
