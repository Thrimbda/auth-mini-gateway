# Prove HTTP/2 performance regression boundaries

## Goal

Provide reproducible, statistically defensible evidence that the HTTP/2 proxy change does not materially degrade existing HTTP/1 proxy performance, and that new HTTP/2 and bridge paths meet explicit latency, throughput, CPU, and memory efficiency gates on the current machine. Fix confirmed regressions within the task without weakening gateway safety invariants.

## Problem

The HTTP/2 delivery passed functional, security, ownership, and protocol tests, but those checks do not prove performance equivalence. The change adds downstream protocol detection, per-stream admission, SETTINGS observation, multiplexed generation ownership, header translation, and cross-protocol tunnels. Any of these can preserve correctness while regressing latency, throughput, CPU per request, or memory. A one-off load test or comparison of averages would be too noisy to support a no-regression claim.

## Acceptance

- The pre-HTTP/2 commit `28a4a27` is the immutable H1 baseline. The candidate begins at `1f9821a` and the final tested candidate commit is recorded exactly.
- Baseline and candidate use the same Rust toolchain, release profile, machine, CPU affinity, fixture, gateway configuration, authenticated ready-session state, request corpus, warmup, run duration, and measurement code.
- One repository command builds isolated release binaries, runs the benchmark, validates response/protocol/byte correctness, writes machine-readable raw results plus a reviewer report, and exits nonzero for `FAIL` or `BLOCKED`.
- The H1-to-H1 differential covers a small authenticated GET, 1 MiB streaming upload, 1 MiB streaming download, finite SSE stream, and framed WebSocket ping/pong at concurrency 1, 16, and 64.
- Every H1 scenario passes a paired one-sided 95% confidence gate: throughput lower bound is at least 97% of baseline, p99 latency upper bound is at most 105%, gateway CPU per completed operation is at most 105%, and peak gateway RSS is at most 110%.
- The candidate additionally covers H2-to-H1, H1-to-H2, and H2-to-H2 with the same workload and concurrency matrix. Concurrency 1 reports protocol fixed cost without a hard H2 comparison gate.
- At concurrency 16 and 64, H2-to-H2 throughput has a paired geometric-mean point estimate of at least 100% of candidate H1-to-H1 and a confidence lower bound of at least 97%; p99 is at most 105%. Bridge throughput is at least 95% and bridge p99 is at most 110%. H2 and bridge CPU per operation are at most 110% and peak RSS at most 115% of candidate H1-to-H1.
- Every authoritative comparison uses at least 30 balanced randomized A/B pairs and may expand to at most 100 pairs under a predeclared stopping rule. Confidence intervals, deterministic seeds, warmups, and all raw samples are retained; samples are not manually removed.
- The current machine is the sole authoritative environment. CPU placement and machine/runtime state are recorded. If predeclared noise or confidence-width requirements remain unsatisfied after 100 pairs, the result is `BLOCKED`, never `PASS`.
- Statistical code has deterministic synthetic-data tests that prove PASS, threshold FAIL, noise BLOCKED, pairing, percentile, confidence-interval, and stopping behavior.
- If a gate fails, the failing evidence is retained, the implementation is optimized only within the demonstrated path, and the complete authoritative matrix is rerun. Authentication, fixed routing, TLS verification, no replay, capacity ownership, header sanitation, and tunnel safety may not be weakened for speed.
- Formatting, strict Clippy, functional tests, release build, benchmark self-tests, independent result verification, readiness/security review, and relevant repository E2Es pass before delivery.

## Assumptions

- Both commits build with the current pinned Rust toolchain and can run concurrently isolated on loopback without external services.
- Linux process accounting and CPU affinity are available on the current machine without sudo or host reconfiguration.
- A deterministic local fixture and pre-seeded ready session can exercise the authenticated proxy hot path without refresh/network-auth variance.
- The current machine may be too noisy for a conclusion; `BLOCKED` is an acceptable honest terminal benchmark result but not proof of no regression.

## Constraints

- Use a separate load generator/fixture process from each measured gateway process and measure gateway CPU/RSS only.
- Keep persistent benchmark inputs, outputs, caches, and temporary work inside this repository/worktree; clean unneeded generated binaries and runtime state before delivery.
- Do not use sudo, change CPU governor/turbo/background services, run Nix, deploy, or modify production/Nginx/FRP/NixOS/external repositories.
- Do not add an opaque external load generator or statistics service whose behavior cannot be versioned and unit-tested in the repository.
- Do not label a scenario PASS from a single run, averages alone, statistical non-significance, overlapping error bars, or a reduced workload.
- Keep benchmark instrumentation out of the production request path and release gateway API.

## Risks

- Scheduler, thermal, frequency, and background-load drift can create false regressions or false passes on one machine.
- A load generator bottleneck can make gateway throughput look equal while hiding gateway cost.
- CPU/RSS sampling can be biased by startup, connection warmup, allocator retention, or fixture work.
- A benchmark can accidentally compare different protocol, response size, auth state, pool reuse, or correctness behavior.
- The full matrix can be expensive; premature stopping or selective reruns would invalidate paired evidence.
- Performance fixes can accidentally weaken the security and ownership properties established by the HTTP/2 task.

## Scope

- A versioned end-to-end benchmark runner, local H1/H2 upstream fixture, authenticated gateway setup, load drivers, process resource sampler, statistical analyzer, and deterministic analyzer tests.
- Differential H1 baseline/candidate evidence and candidate-only H1/H2 protocol matrix evidence for GET, upload, download, SSE, and WebSocket workloads.
- Machine fingerprint, run manifest, raw samples, confidence intervals, gate decisions, and a concise reviewer-facing performance report.
- Focused gateway performance fixes only when a statistically confirmed failing scenario identifies them, followed by complete reruns.
- Operator/developer documentation for reproducing the benchmark and interpreting PASS/FAIL/BLOCKED.

## Non-goals

- Production rollout, capacity tuning for a production host, WAN benchmarks, distributed load, HTTP/3, or replacing the functional/security test suite.
- Treating shared CI, another host, a microbenchmark, flamegraph, or profiler trace as the authoritative no-regression gate.
- Changing authentication policy, routing behavior, protocol semantics, capacity defaults, TLS trust, or accepted residuals from the HTTP/2 task.
- General optimization unrelated to a measured failing path.

## Design Summary

- Run baseline and candidate as separate release gateway processes against the same deterministic local fixture; keep fixture and client work outside gateway CPU accounting.
- Execute balanced randomized A/B pairs on pinned CPU sets, with correctness assertions embedded in every workload before recording a sample.
- Record per-operation latency distributions, completed operations/bytes, gateway process CPU time, sampled peak RSS, machine state, and protocol/connection observations.
- Use a deterministic paired bootstrap and one-sided equivalence gates, plus explicit noise/stopping rules, to produce scenario-level and aggregate PASS/FAIL/BLOCKED decisions.
- Keep raw data immutable; optimization iterations produce new run IDs rather than overwriting failed evidence.

## Design Index

> **Design source of truth**: `docs/rfc.md` after adversarial review.

## Phases

1. Contract and design: specify the process topology, workloads, statistics, noise controls, result schema, safety checks, and stopping rules; obtain RFC PASS.
2. Harness implementation: build the fixture, load drivers, sampler, analyzer, synthetic tests, and reproducible command without changing production behavior.
3. Measurement and remediation: run the authoritative matrix, retain failures, optimize confirmed regressions if needed, and rerun to a defensible verdict.
4. Verification and delivery: independently verify raw/result consistency and functional safety, review readiness/security, produce walkthrough/wiki evidence, and complete the PR lifecycle.

---

*Created: 2026-07-18 | Last updated: 2026-07-18*
