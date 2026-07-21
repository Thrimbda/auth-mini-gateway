# Research: HTTP/2 performance-regression boundary

> **Scope:** read-only inspection on 2026-07-18 of the task contract, current worktree, Git objects `28a4a27` and `1f9821a`, current Axiom state, and existing Legion proxy/security decisions.
> **Purpose:** give `review-rfc` the minimum evidence needed to judge the benchmark design. No benchmark or production code was changed.

## 1. Problem restatement

The HTTP/2 change is functionally and security reviewed, but it adds work to both the old H1 path and the new H2 paths. The task must distinguish a material regression from host noise using the full five-workload, three-concurrency, four-topology matrix. A valid result must come from exact release binaries and black-box protocol/byte evidence; microbenchmarks, averages, reduced matrices, and noisy inconclusive runs cannot support `PASS`.

The cost is material. There are 15 H1 baseline/candidate cells and 30 hard candidate-H2/bridge cells. Running every comparison as an independent A/B experiment duplicates candidate H1 controls and can take days at 30–100 pairs.

## 2. Version and build facts

| Item | Evidence |
|---|---|
| Immutable H1 baseline | `28a4a273ea9b2725191dce35233f55972beaac6f`, tree `d411fb4c2f560d08d790c73bd3ab324464222d40` |
| Initial candidate | `1f9821ab36f546ca0ffd9f6b83cb9a1f0af512ad`, tree `e464d2a0a15226a6fc94d342c5c4eeb4422e0a70`; `HEAD` equals this object |
| Ancestry | Baseline is an ancestor of candidate; the range contains feature commit `5638fb0` and closeout commit `1f9821a` |
| Toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)`, LLVM 22.1.2; `cargo 1.96.0 (30a34c682 2026-05-25)` |
| Baseline lock | Git blob `217752325d1535cc05e91aeadaddac55872d0ac0`; SHA-256 `8f05c93c0711c6e620de0c2cdffb67fc0555ab69ff80a317cb60200f98e50530` |
| Candidate lock | Git blob `966f74c396672b5c389a234f564e87ed5574091c`; SHA-256 `ca61e7ea2dc259fd3ed907eb95d9ab460179f41778cbc671b14f8d015566df87` |

The baseline enables Hyper HTTP/1 only. The candidate enables the existing Hyper, hyper-rustls, and hyper-util H2/server-auto features and adds pinned `h2 0.4.14`; there is no new direct production dependency (`Cargo.toml`, `Cargo.lock`, `git diff 28a4a27..1f9821a`). The baseline has no `UPSTREAM_PROTOCOL` read, so setting common H1 launch environment `UPSTREAM_PROTOCOL=http1` is harmless and ignored there (`28a4a27:src/config.rs`; current `src/config.rs:209-244,293-318`).

Existing `scripts/e2e-old-binary-compat.sh:60-88` already demonstrates the repository convention of extracting a Git object with `git archive` and building it separately. The performance harness must use that principle without injecting helper code into either gateway archive.

## 3. Relevant current paths and likely costs

| Surface | Evidence and performance implication |
|---|---|
| Release logging | Both binaries install synchronous stderr formatting (`src/main.rs:18-23`). The candidate additionally emits one `upstream_dispatch_selected` INFO event on every dispatch (`src/proxy.rs:1520-1565`); the baseline has no equivalent event. Suppressing it would hide shipped H1 cost. |
| Downstream H1/H2 | Candidate replaces the H1-only server with auto detection, a per-connection `watch` first-head latch, H2 stream admission, and a boxed downstream lease body (`src/server.rs:866-966,1450-1479`; baseline boundary indexed in `.legion/tasks/enable-http2-proxy/docs/research.md:13-21`). |
| H1 ownership | Candidate routes H1 through the combined owner vector, `ExchangeLatch`, tracked request/response wrappers, and the same per-dispatch INFO call (`src/proxy.rs:1135-1257,1427-1609,1946-2072`). These are the leading H1 regression hypotheses. |
| H2 generation gate | `GenerationControl` uses an atomic plus a synchronous mutex; every H2 enqueue takes that mutex (`src/proxy.rs:220-338,1531-1548`). |
| Continuous proof | Every H2 read/write checks generation state; inbound bytes also traverse the fixed-cursor scanner under the proof mutex (`src/proxy.rs:340-621,688-836`). This is bounded for safety but not free. |
| H2 reservation/pool | Selection clones a vector of H2 generations, takes pool/master locks, clones a sender, and acquires a stream permit per exchange (`src/proxy.rs:1148-1197,2081-2122`). |
| Body/lifetime work | Request and response halves use `ExchangeLatch`, upload state, body wrappers, and downstream body boxing (`src/proxy.rs:1946-2072,4200-4379`; `src/server.rs:202-230,1470-1479`). Flow-control can retain request ownership until wrapper drop. |
| Auth hot path | A schema-v2 `Ready` session avoids refresh but still performs signed-cookie verification, SQLite lookup, policy, sanitation, and upstream admission (`src/db.rs:11,248-265,600-668`; `src/server.rs:1120-1204`). |

These are hypotheses, not grounds for selective gates or sample removal. Diagnostics may target them only after a sealed authoritative failure.

## 4. Existing fixtures and security decisions

- The integration suite already has loopback H1/H2 fixtures, actual-version observations, hit/connection counters, streamed bodies, finite SSE, raw H2 SETTINGS, and all WebSocket bridges (`tests/proxy_integration.rs:46-179,4660-5109,5640-6151`). It is useful design evidence but is debug/test code and cannot become a release callback.
- Tests seed a fresh schema-v2 session and sign its cookie without contacting auth-mini (`tests/proxy_integration.rs:4702-4774`). A benchmark package can reproduce the on-disk contract externally and place a zero-hit auth-mini listener at the configured issuer.
- The current framed fixture uses text frames for its local assertion (`tests/proxy_integration.rs:5701-5707,6423-6438`). The performance workload must instead use real RFC 6455 Ping (`0x9`) and Pong (`0xA`) control frames.
- Existing decisions require per-stream authentication, fixed startup routing/TLS identity, credential and hop-header stripping, no replay/fallback, lifecycle-correct D/U ownership, an eight-owner combined pool, same-connection SETTINGS proof, exact-generation retirement, and tunnel leases through EOF (`.legion/wiki/decisions.md:7-20`; `.legion/wiki/patterns.md:70-110`).
- The HTTP/2 implementation/security review passed those properties and confirms that release builds contain no dynamic integration hooks (`.legion/tasks/enable-http2-proxy/docs/review-change.md:55-80`). Performance remediation must preserve that reviewed state.
- The accepted H2 residuals—pre-service nonzero CONNECT close, generation-wide retirement after illegal capability revocation, and initial-false monotonicity—remain unchanged (`.legion/wiki/tasks/enable-http2-proxy.md:33-39`).

## 5. Current Axiom snapshot

Snapshot time: `2026-07-18T15:00:12+08:00`.

| Item | Observed state |
|---|---|
| Host / kernel | `axiom`; NixOS 25.11 build `25.11.20260630.b6018f8`; Linux `6.12.93`, `PREEMPT_DYNAMIC` |
| CPU | AMD Ryzen 9 9950X, 16 cores / 32 threads, one NUMA node; SMT active |
| Cache topology | CCD/L3 groups `0-7,16-23` and `8-15,24-31` |
| Frequency policy | `amd-pstate-epp` active; all sampled/validated policies and EPP values `performance`; boost `1`; advertised max 5752 MHz |
| Clock/accounting | TSC clocksource; `CLK_TCK=100`; ASLR remains `2` |
| Memory | 48,345,320 KiB total; 29,928,600 KiB available at snapshot; swap configured but idle |
| Thermal/load | Tctl 57.375°C; load average `1.25 1.33 1.41`; CPU/memory/I/O PSI 10/60/300-second averages all zero at the instant sampled |
| File descriptors | soft/hard nofile both 524,288 |
| Storage | 62,371,192,832 bytes free; root filesystem 94% used |

The machine is an active desktop/server, not an isolated lab host: GUI/browser/Steam, Docker/Postgres, monitoring/tunnel processes, developer tools, and an installed gateway were present. The contract forbids stopping or retuning them. CPU affinity, prospective randomization, direct-load headroom checks, and strict noise stops are therefore mandatory; the current snapshot is not proof that a multi-hour campaign will remain acceptable. Storage is also a prospective gate because raw per-operation latencies and sealed failed runs may not be deleted to make a result pass.

## 6. Design implications resolved in the RFC

1. Use a nested benchmark-only Rust package and black-box release binaries extracted from exact Git objects; no production hook or release API is added.
2. Use one fresh gateway process per arm-run, with separate fixture, load, sampler, and orchestrator processes. Never run baseline and candidate gateways together.
3. Use one five-arm randomized complete block per workload/concurrency cell. This shares one candidate H1 control prospectively across three H2 comparisons and avoids 28.6% of the naive arm-runs.
4. Use ten non-authoritative balanced calibration rounds to freeze one global `N` in `{30,50,70,100}` and equal per-cell steady/warmup durations. Calibration never contributes to authoritative estimates.
5. Treat startup, SETTINGS/connection proof, and WebSocket handshakes as descriptive cold-path evidence. Steady CPU and latency start after warmup; final per-process `VmHWM` deliberately retains startup/warmup memory.
6. Redirect both binaries' stderr to the same nonblocking `/dev/null` sink with default shipped INFO filtering. This retains candidate formatting/write cost without creating an unbounded log file or pipe backpressure.
7. Seal every calibration, failed, blocked, and authoritative run under the repository. A changed candidate is a new Git object and requires a completely new campaign.

## 7. Remaining uncertainty

There is no unresolved design-contract question. The implementation-stage blockers are empirical and fail closed:

- calibration may project confidence width, runtime, or disk beyond the declared bounds;
- the direct fixture/load ceiling may be too close to gateway throughput;
- active-host noise, frequency drift, PSI, or thermal limits may invalidate an arm;
- a final `N=100` campaign may not fit the 48-hour wall budget.

Any of these yields `BLOCKED`; none permits a reduced matrix, reused sample, weaker threshold, host tuning, or a no-regression claim.

## 8. References

- Contract: `.legion/tasks/prove-http2-performance-regression/plan.md`
- Task history: `.legion/tasks/prove-http2-performance-regression/log.md`, `tasks.md`
- HTTP/2 design/evidence: `.legion/tasks/enable-http2-proxy/docs/{research,rfc,review-rfc,review-change,test-report}.md`
- Effective decisions: `.legion/wiki/decisions.md`, `.legion/wiki/patterns.md`, `.legion/wiki/tasks/{enable-http2-proxy,harden-proxy-production-boundaries,authenticated-reverse-proxy}.md`
- Current implementation: `Cargo.toml`, `Cargo.lock`, `src/{main,config,db,cookies,server,proxy,capacity,runtime_plan}.rs`
- Existing fixtures/scripts: `tests/proxy_integration.rs`, `scripts/e2e-*.sh`
