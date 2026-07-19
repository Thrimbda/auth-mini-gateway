# Prove HTTP/2 performance regression boundaries - Log

## 2026-07-18 - Task initialized

- User selected the strict H1 gate: throughput -3%, p99 +5%, CPU/operation +5%, and peak RSS +10%, all from paired 95% confidence bounds.
- User selected the complete protocol/workload matrix and concurrency-aware H2 gates: H2-to-H2 throughput/p99 0%/+5%, bridges -5%/+10%, and H2 resource +10% CPU/+15% RSS at concurrency 16/64.
- User selected the current machine as the sole authoritative environment and required noise to produce `BLOCKED` rather than a weaker claim; no sudo host tuning is allowed.
- User required confirmed regressions to be fixed and the complete gate rerun in the same task without weakening security or ownership invariants.
- Base ref: `origin/master` at `1f9821ab36f546ca0ffd9f6b83cb9a1f0af512ad`.
- Immutable H1 comparison baseline: `28a4a273ea9b2725191dce35233f55972beaac6f`.
- Branch: `legion/prove-http2-performance-regression-benchmark-gate`.
- Worktree: `/home/c1/Work/auth-mini-gateway/.worktrees/prove-http2-performance-regression`.
- Risk: high. A weak harness can create a false safety claim; default implementation mode requires `spec-rfc -> review-rfc` before benchmark or production edits.
- No production, Nix, external-host, or system-tuning action is in scope.

## 2026-07-18 - H2 throughput estimand clarified

- Statistical review showed that requiring a 95% lower bound of 100% would be a superiority test that usually blocks when H1 and H2 are truly equal.
- The user selected a two-part H2-to-H2 throughput gate: paired geometric-mean point estimate at least 100%, with the corrected confidence lower bound at least 97%.
- This preserves the observed no-slowdown requirement while making equality statistically decidable under the same 3% material-regression margin.

## 2026-07-18 - Benchmark RFC passed

- `docs/research.md` records the exact commits/toolchain, process seams, likely H1/H2 costs, and current Axiom machine constraints.
- `docs/rfc.md` defines a black-box five-arm Williams-block campaign with 45 hard comparisons, 190 scalar gates, paired log-ratio bootstrap analysis, exact protocol/work validation, immutable evidence, and fail-closed noise/runtime controls.
- Repeated RFC review corrected all-role transient CPU attribution, non-circular scout/calibration state machines, exact 42/48-hour projection, lazy Tokio auth-worker lifecycle, mandatory quiet-window accounting, and read-only wall-clock provenance.
- Final `review-rfc` records PASS with no blocking design finding.
- Feasibility remains empirical: thread signatures, active-host noise, endpoint headroom, disk reserve, and N=30/50 runtime may block; N=70/100 is prospectively runtime-inadmissible under the complete matrix.
- Next: implement only the benchmark package/harness and its deterministic tests; no production request-path instrumentation is authorized.

## 2026-07-18 - H1 upload topology corrected

- Milestone 2 smoke proved that both exact baseline and candidate intentionally return `Connection: close` for every body-bearing downstream H1 request, including a fully consumed successful 1 MiB upload.
- The RFC had incorrectly required persistent downstream H1 upload connections; implementation stopped rather than normalizing away shipped safety behavior.
- The reviewed correction defines one fresh H1 connection per upload operation for B11/C11/C12, includes connect-through-close/EOF in latency, forbids retry/reuse, and requires exact cumulative connection accounting. H2 upload remains multiplexed on one persistent connection.
- Focused `review-rfc` records PASS; no production behavior change is authorized or required.

## 2026-07-18 - Benchmark harness implemented

- Added an independent nested Rust benchmark package with deterministic schedule/statistics, strict schemas, raw seals, canonical Zstandard bundles, independent recomputation, exact Git archive builds, fixture/load/sampler/orchestrator roles, and scout/calibration/campaign state machines.
- Benchmark foundation and process tests pass: 80 unit plus 6 integration tests, strict Clippy, locked/offline checks, and self-test.
- Exact offline/frozen release builds succeeded for baseline `28a4a27` and candidate `1f9821a`, with no source injection, RUSTFLAGS change, production hook, or root production-source modification.
- Final bounded smoke `smoke-1784428958226473328-1f9821ab36f5` passed all 25 C1 gateway arm/workload combinations and two direct upload controls, including actual H1/H2, 1 MiB streaming, finite SSE, H1 Upgrade, RFC 8441, and real Ping/Pong.
- H1 upload smoke confirms B11/C11/C12 use one fresh connection per operation with required close/EOF and zero retry/reuse; C21/C22 use one persistent H2 connection and unique streams.
- N30/N50 dry-run inventories are structurally admissible at 98,757s and 147,117s before empirical calibration; no authoritative sample has run.
- Remaining empirical gates: required C64 smoke, quiet/noise/headroom, thread signatures, scout, 750-arm Williams calibration, calibration direct panel, selected N/W/T projection, complete authoritative campaign, bundle cap, and independent verdict.
