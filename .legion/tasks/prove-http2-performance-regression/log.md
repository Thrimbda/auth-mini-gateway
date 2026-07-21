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

## 2026-07-19 - Sealed second-smoke B11 upload failure remediated

- Preserved both blocked smoke calibrations and bundles. A new bounded, non-authoritative B11/C1 upload diagnostic reproduced load-role detail hash `ce137486...` as stage `proof`, code `response-head-invalid`.
- Root cause: the fresh-H1 raw response reader required `Content-Length`, while the exact gateway validly emitted a chunked response before its required connection close. Added bounded chunked decoding without changing one-connect/one-POST/close/peer-EOF/no-retry semantics or ledgers.
- Authenticated terminal frames and new retained role-failure schema v2 now carry fixed allowlisted stage/code fields; raw detail remains absent and v1 sealed evidence remains verifiable.
- Final diagnostic `diag-b11-c1-upload-1784472591816797084-f229f563b759` passed with 2 distinct downstream connections, 2 close tokens, 2 EOFs, and zero retry/reconnect/reuse. Seal root `502ece5890eb0d41205f5d8733ebccfc06efcac11acc139e51847a65efc42d5e`; bundle index SHA-256 `b5513c4241077f777e242327c633f93735dd462fa73481925654219cc4e1121a`.
- Benchmark tests (117 unit + 13 integration), repository tests (110 unit + 50 integration), formatting, strict Clippy, locked/offline release builds, self-test, bundle reconstruction/recompression, and production-root diff passed. No full topology smoke or campaign was rerun.
- Next: run one new additive C1+C64 topology smoke with the corrected harness; prior evidence remains retained.

## 2026-07-20 - Full topology smoke hardened and passed

- Fail-closed smoke iterations exposed and fixed benchmark-only defects in full-concurrency auth-worker materialization, checkpoint comparison, upstream-H1 cumulative connection accounting, H2 observer capacity, repeated executable hashing, and WebSocket cold-start sequencing. Every failed calibration and bundle remains additive and sealed.
- The release harness completed the exact C1/C64 matrix in 152.724 seconds: 50 gateway cases plus four direct controls, all 54 with semantic class `ok` and no terminal integrity failure.
- Provisional smoke `cal-smoke-50028c5f6764-84f0174d30b7` has seal root `8e14bd90bc85ac0eca1b2218a4f90e21cf22f49ce45e340c36190e302ce26c01`; bundle index SHA-256 `51767bce233c5adcc38f14cfda1774c45f83c2c221f56b63b0af59140f87fbb7` independently reconstructs and recompresses byte-for-byte.
- This smoke proves topology only and used the pre-commit harness candidate. No performance sample or non-regression claim exists yet. Commit the final harness, rerun smoke against that exact Git object, then enter scout/calibration only if all gates remain clean.

## 2026-07-21 - Implementation passed; empirical proof blocked

- Implementation checkpoints are `743fa30`, `0017c9d`, and final candidate `91bb210cbf6703e1f3258b517cee1acfd337da79`.
- Final implementation review passed with no open finding. Verification passed 151 benchmark tests plus `process-arms`, 160 root tests, strict Clippy, and the release self-test.
- The first exact-`743fa30` smoke exposed missing quiet-failure retention. Its partial unsealed root `cal-smoke-743fa30d7371-a03fd3cf021e` remains preserved and was not used for any claim.
- Exact-candidate smoke `cal-smoke-91bb210cbf67-b2297c713de2` reached terminal `BLOCKED` before running a case: 12 consecutive 10-second `Q_obs` candidates produced zero accepted observations and `q_extra=110002598526ns`.
- The persistent orchestrator inventory remained stable. External logical-CPU activity was approximately 38%-81%, and I/O PSI `full` was nonzero. The contract permits neither a retry nor a threshold change.
- The terminal source seal root is `a78786cedf214fcff3fe779fa985bfdcc3eb203d007945dcac6e29f02d3e3e0e`; bundle index SHA-256 is `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`. Independent verification returned `success=true`, `byte_equal=true`, and terminal `BLOCKED`.
- No scout, calibration, authoritative, or performance-verdict sample was produced. No production change or regression remediation was attempted.
- Main conclusion: implementation readiness is `PASS`, but empirical proof is `BLOCKED` by Axiom host noise; therefore this task makes no no-regression claim. Only the delivery lifecycle remains.

## 2026-07-21 - Main PR merged; tracked closeout evidence prepared

- Main implementation PR [#13](https://github.com/Thrimbda/auth-mini-gateway/pull/13) merged at `9f9fb3f0959cefac0608cdece5f661b3b7973cef`.
- Materialized the ordinary-Git terminal evidence copy at `.legion/tasks/prove-http2-performance-regression/artifacts/cal-smoke-91bb210cbf67-b2297c713de2/` for the closeout PR.
- The tracked-path copy has bundle index SHA-256 `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`, chunk SHA-256 `1e5f375b64f9009c16689484e6f37120e9a18ebec179d86e686adf97551dcd5a`, verification receipt SHA-256 `cb14b85dd1ad3413c40d53d87893483924085da2c1122b78b0eb8458a0d61f82`, and seal root `a78786cedf214fcff3fe779fa985bfdcc3eb203d007945dcac6e29f02d3e3e0e`.
- The receipt records `success=true`, `byte_equal=true`, and terminal `BLOCKED`.
- Current branch is `legion/prove-http2-performance-regression-closeout`. A second closeout PR must merge before the fetched-base retention check can authorize `.perf` cleanup, worktree/branch removal, and main-workspace refresh.
- Conclusion unchanged: implementation `PASS`, empirical proof `BLOCKED`, and no performance or no-regression claim.
