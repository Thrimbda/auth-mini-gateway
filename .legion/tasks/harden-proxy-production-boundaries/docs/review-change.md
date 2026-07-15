# Final security-focused readiness re-review

> Date: 2026-07-16
> Implementation verdict: **PASS**
> Production rollout: **BLOCKED pending native deployment evidence**

## Findings

No blocking or non-blocking code findings remain.

## Resolved review findings

### Terminal exit with an unfinishable resolver

**PASS.** The terminal result is preserved before `runtime.shutdown_background()` consumes the runtime. A child process starts an unfinishable resolver through the real proxy path, injects fatal accept through the production accept driver, and exits nonzero within five seconds with exactly one sanitized event and no raw marker.

### Panic-hook lock and reentrancy safety

**PASS.** Panic-time behavior is one direct `libc::write` of static bytes. It performs no Rust stdio locking, allocation, formatting, tracing, payload inspection, or location inspection. Child tests cover stderr lock contention and panic from an stderr-writing path without deadlock or leakage.

### Full 64-worker auth isolation

**PASS.** Eight resolver-budget blockers and 16 margin blockers remain held while all 64 auth closures concurrently enter. Releasing only the auth barrier completes all 64 auth operations; resolver/margin work releases last.

### Warm domain owner reuse under full R

**PASS.** A parked complete domain owner is reused while R is occupied, with no resolver submission, replacement connection, or accounting change.

### Real bracketed IPv6 TLS identity

**PASS.** The actual gateway/hyper-rustls path accepts a matching IPv6 IP SAN and rejects a DNS-only certificate with sanitized `502`, while IPv6 literal dialing uses no resolver capacity.

## Security/readiness matrix

| Boundary | Result |
|---|---|
| Pre-accept D ownership through HTTP, upload, SSE, upgrade, and WebSocket | **PASS** |
| Immediate U/R admission, exact saturation, renewal, no body poll/replay | **PASS** |
| Resolver accounting, cancellation, timeout, address typing, auth isolation | **PASS** |
| Complete sender/driver ownership and abort+join before U release | **PASS** |
| Accept classification, backoff, global suppression, and fatal exit | **PASS** |
| Panic secrecy and caught/uncaught behavior | **PASS** |
| Underscore aliases and owned/adapter compatibility | **PASS** |
| One-admission auth/login and exact cookie phases | **PASS** |
| Trusted CIDR/XFF parsing, non-influence, and log secrecy | **PASS** |
| Config secrecy, RLIMIT arithmetic, runtime plan, startup refusal | **PASS** |
| nginx/FRP/systemd topology and rollback ordering | **PASS** |
| Scope and inherited adapter/proxy compatibility | **PASS** |

No new race, premature permit release, detached live-service FD/task escape, request replay, trust-boundary influence, or raw metadata logging was found.

## Test-only seam assessment

Process fault seams are guarded by `#[cfg(debug_assertions)]`; proxy inspection helpers are guarded by `#[cfg(test)]`. Release cfg inspection confirms `debug_assertions` is absent, so resolver substitution, fatal-accept injection, and panic controls are not present in the production release binary and expose no HTTP-triggered control.

## Independent evidence

```text
git diff --check                                         PASS
cargo fmt --check                                        PASS
cargo clippy --all-targets --all-features -- -D warnings PASS
cargo test                                               PASS (90 unit, 27 integration)
cargo build --release --bin auth-mini-gateway            PASS
cargo check --all-targets                                PASS
```

The final focused tests also passed repeated cycles without failure.

## Accepted residuals

- A started libc resolver may retain one bounded U/R pair indefinitely.
- An unyielding aborted Hyper driver may retain one U slot.
- Idle downstream clients can consume D.
- Restart remains non-graceful.
- A poisoned idle pool can strand at most eight budgeted owners until exit.

The fatal-path fix ensures these residuals cannot prevent process termination and systemd restart.

## Production rollout blockers

1. Native Acorn `nginx -t`, reload, and underscore rollback probe.
2. FRP verification with deployed token/certificate files and matching versions.
3. Physical `:443 -> 127.0.0.1:18081 -> 127.0.0.1:7780 -> 127.0.0.1:4096` and firewall evidence.
4. Confirmation of the exact frpc direct peer before enabling trusted CIDRs.
5. Effective systemd `LimitNOFILE`, `TasksMax`, and `MemoryMax`.
6. Production thread, RSS, and virtual-memory stress evidence and headroom.
7. The pinned external auth-mini compatibility run.

## Verdict

**PASS for the implementation change. Do not deploy until the native rollout blockers above are cleared.**
