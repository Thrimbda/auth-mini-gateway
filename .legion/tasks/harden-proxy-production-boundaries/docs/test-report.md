# Final independent verification: harden proxy production boundaries

> Date: 2026-07-16
> Worktree: `/home/c1/Work/auth-mini-gateway/.worktrees/harden-proxy-production-boundaries`
> Branch: `legion/harden-proxy-production-boundaries`
> Design gate: `docs/review-rfc.md` **PASS**
> Implementation verdict: **PASS**
> Production rollout: **BLOCKED pending native deployment evidence**

## Required commands

| Command | Result |
|---|---|
| `cargo fmt --check` | **PASS** |
| `cargo clippy --all-targets --all-features -- -D warnings` | **PASS** |
| `cargo test` | **PASS** - 90 unit + 27 integration; 0 failed/ignored |
| `cargo build --release --bin auth-mini-gateway` | **PASS** |
| `cargo check --all-targets` | **PASS** |
| `git diff --check` | **PASS** |

## Final review fixes

### Fatal exit with a blocked resolver

**PASS.** The real debug binary starts an unfinishable resolver, receives a fatal accept error through the production path, consumes the Tokio runtime with non-waiting `shutdown_background()`, emits exactly one sanitized `process_exit`, and exits nonzero within five seconds without resolver release or raw markers.

### Panic hook lock and reentrancy safety

**PASS.** Panic-time output is one direct `libc::write` of a static line. It uses no Rust stdio lock, allocation, formatting, tracing, payload, location, or path. Child tests cover panic while stderr is locked and panic originating in an stderr-writing path; both finish within three seconds and leak no marker.

### Full auth-worker isolation

**PASS.** Under the exact default blocking maximum:

```text
8 resolver-budget blockers
+ 16 runtime-margin blockers
+ 64 concurrent auth jobs
= 88
```

All 64 auth closures enter while R+16 remain blocked. Releasing only the auth gate lets all auth work complete; resolver/margin blockers remain held until released afterward.

### Warm domain pool reuse under full R

**PASS.** A first domain request resolves and parks a reusable complete owner. With R then fully occupied, a second request reuses the same owner, submits no resolver, opens no replacement connection, leaves accounting unchanged, and reaches the application.

### Real bracketed IPv6 TLS path

**PASS.** The actual gateway/hyper-rustls path to `[::1]` succeeds with a matching IPv6 IP SAN and returns sanitized `502` with a DNS-only certificate. IPv6 literal dialing creates no resolver work.

## Boundary results

| Boundary | Result |
|---|---|
| D/U/R defaults, validation, headroom, runtime formula, RLIMIT budgets | **PASS** |
| Pre-accept downstream capacity through keep-alive/upload/SSE/WebSocket | **PASS** |
| Raw U/R saturation: exact 503, no 100/body poll/hit/replay, renewal, health | **PASS** |
| Complete sender/driver owner and abort+join before U release | **PASS** |
| Resolver success/failure/empty/panic/timeout/cancellation and accounting | **PASS** |
| Recoverable accept retry/backoff/suppression/reset and fatal exit | **PASS** |
| Underscore rejection before auth/upstream with owned/adapter compatibility | **PASS** |
| One-admission auth/login and overload/pre/post-panic cookie mapping | **PASS** |
| Trusted XFF parsing, non-influence, regeneration, and log secrecy | **PASS** |
| IPv4/IPv6/domain dialing and TLS identity | **PASS** |
| nginx/FRP/systemd/topology static artifacts and rollback | **PASS** |
| Inherited auth/session/proxy/streaming/no-replay behavior | **PASS** |

Resolver accounting proves:

```text
submitted_unobserved = request_owned + cleanup_owned
submitted_unobserved <= held_r <= R
live_blocking <= submitted_unobserved <= R
```

## Repeated evidence

- 20 combined cycles of fatal resolver exit, panic lock/reentrancy, 64-worker auth isolation, warm pool reuse, and real IPv6 TLS.
- 90 unit tests and 27 integration tests in the retained suite.
- No focused repetition failed or timed out.

## Repository wrappers

| Wrapper | Result |
|---|---|
| `scripts/e2e-proxy-mode.sh` | **PASS** - 27 integration tests |
| `scripts/e2e-mode-switch.sh` | **PASS** |
| `scripts/e2e-old-binary-compat.sh` | **PASS** |
| `scripts/e2e-wal-backup-restore.sh` | **PASS** |
| `scripts/e2e-real-auth-mini.sh` | **BLOCKED** - pinned external checkout absent |

## RLIMIT evidence

- Proxy nofile `904` refuses and exact `905` starts: **PASS**.
- Adapter nofile `768` refuses and exact `769` starts: **PASS**.
- Defaults report D/U/R `256/128/8` and blocking maximum `88`: **PASS**.

## Native rollout limitations

1. Native nginx validation/reload/raw rollback requires Acorn; nginx is not installed here.
2. FRP binaries are v0.65.0, but full verify requires deployment token/certificate files.
3. The service is not installed, so effective deployed `LimitNOFILE`, `TasksMax`, and `MemoryMax` remain unverified.
4. Physical Acorn `:443 -> 127.0.0.1:18081`, FRP, Axiom `127.0.0.1:7780`, OpenCode `127.0.0.1:4096`, firewall, direct-peer, and maintenance rollback evidence remains outstanding.
5. Production Threads/VmRSS/VmSize stress and MemoryMax headroom remain rollout gates.
6. The pinned external auth-mini checkout is unavailable.

## Verdict

**PASS for the implementation change. Do not roll out until the native Acorn/Axiom deployment and resource gates pass.**
