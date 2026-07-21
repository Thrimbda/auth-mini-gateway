# Review change: HTTP/2 performance-regression proof

> **Reviewed:** 2026-07-21
> **Scope:** focused read-only review of commits `0017c9de1dbbe6f93c1168806cfa842da0fc6ae6` and `91bb210cbf6703e1f3258b517cee1acfd337da79`, plus exact-candidate smoke `cal-smoke-91bb210cbf67-b2297c713de2`
> **Implementation decision:** **PASS**
> **Empirical terminal:** **BLOCKED** by the predeclared quiet-observation gate; no performance sample or no-regression claim exists
> **Security lens:** Applied because source provenance, process affinity, protocol evidence, and retained-evidence trust boundaries are in scope.

## Blocking findings

None. The focused changes do not create a false-PASS or evidence-retention path. The preceding implementation-readiness **PASS** remains valid.

## Closeout review: PASS

**Scope:** commits `2ab0fc2` through `d19ce2e`, the tracked artifact ledger added after merged PR #13, and exact-commit `delivery-ready` verification at `d19ce2e8083111ec5989d11225809ed09597c6ac`. The security lens was applied to receipt identity, committed-evidence integrity, dependency provenance, and clean-build reproducibility.

No blocking or non-blocking finding remains.

- Verifier portability does not normalize evidence-derived content. `verify_artifact_tree` freshly verifies the index, chunks, canonical reconstruction, exact recompression, seal, intent, terminal state, and receipt fields, then substitutes only the stored `verifier_executable_sha256` before exact receipt comparison (`benchmarks/http2-regression/src/delivery.rs:693-759`). The stored executable hash remains a validated non-placeholder SHA-256 bound by the canonical stored receipt and ledger (`benchmarks/http2-regression/src/bundle.rs:213-265`, `1486-1551`). Exact artifact-commit verifier source is separately required before `delivery-ready` succeeds (`benchmarks/http2-regression/src/delivery.rs:577-623`, `909-958`).
- The clean Cargo config is accepted only after the generated scratch vendor path occurs exactly once, is replaced with the sealed vendor path, and the complete resulting config hash equals the sealed manifest (`benchmarks/http2-regression/src/build.rs:635-644`, `739-758`). This preserves the existing frozen/offline, exact toolchain, vendor-tree, and registry-cache checks rather than accepting an alternate config.
- Each rebuild uses a fresh repository-local scratch directory and a one-component rebuild root whose byte length exactly matches the sealed object root (`benchmarks/http2-regression/src/build.rs:554-585`, `685-708`). The scratch compilation remaps that root to the sealed root; any remaining equal-length path bytes are normalized, after which the complete binary length, SHA-256, and parsed ELF Build-ID value must equal the sealed manifest (`benchmarks/http2-regression/src/build.rs:647-681`, `710-737`, `1519-1573`). Allowing zero post-build replacements at `d19ce2e` is correct when compile-time remapping already removed every scratch-root occurrence; it does not weaken the full-file comparison.
- Fresh `delivery-ready --commit d19ce2e8083111ec5989d11225809ed09597c6ac` returned `success=true`, artifact tree `266a1341af0b2309b50503266ea8be5865fc15ae0623bb51c5c7b15c4dfd0be8`, ledger `9e9fe765a485785365aa26ae7bb218a89b2bf29893bfa6d95b920169af83142e`, and verifier source tree `9c7fa8c0ca437a7f3bf54cae7a4290b4520dbc9c`. Clean rebuilds reproduced candidate binary `6f1dc2713d99cd65ac478c718b4ebaeef7b4a45241913d69434af69e5704cf4d` and baseline binary `9a32bab7281ed672b1d27327a23000b6968cf7630452b68813a987c8fb372d73`; both sealed Build-ID values are `null`, and equality was preserved.
- Scope is clean. Since PR #13, tracked changes are limited to closeout docs/wiki, the new ordinary-Git evidence copy and ledger, and benchmark-only `build.rs`/`delivery.rs`. Production code, Cargo manifests/locks, statistical code, retry behavior, and thresholds are unchanged. The tracked bundle index, chunk, and verification receipt are byte-for-byte identical to their retained `.perf` staging sources.

**Closeout decision: PASS.** Commit `d19ce2e` is delivery-ready. The empirical outcome remains terminal `BLOCKED`, and no performance or no-regression claim is authorized.

## Focused review

### 1. Dirty quiet-search retention: PASS

`observe_quiet_exact` now returns a validated v2 `QuietEvidence` containing the complete candidate inventory when the 120-second search cap expires, rather than discarding the observations in an error (`benchmarks/http2-regression/src/linux.rs:766-961`). `QuietEvidence::validate` independently recomputes every candidate's decision, requires only the final candidate to be eligible for acceptance, and binds all top-level fields to that final retained candidate (`benchmarks/http2-regression/src/raw.rs:153-225`).

This relaxes only structural validation so a dirty terminal search can be sealed. It does not make that evidence clean: v2 `QuietEvidence::clean` still requires the final candidate's independently recomputed `accepted=true` decision and all existing PSI, swap, steal, and external-time checks (`benchmarks/http2-regression/src/raw.rs:228-257`). The topology smoke checks `quiet.clean()` before creating any case and seals/bundles a terminal failure when no candidate was accepted (`benchmarks/http2-regression/src/orchestrator.rs:4583-4609`, `5098-5177`). Calibration/campaign raw quality also continues to require `quiet.clean()` (`benchmarks/http2-regression/src/raw.rs:1678-1685`; `benchmarks/http2-regression/src/calibration_coordinator.rs:1004-1025`; `benchmarks/http2-regression/src/evidence.rs:2740-2800`).

### 2. Persistent orchestrator TID pinning and external noise: PASS

Before taking the frozen inventory or starting `Q_obs`, the harness enumerates every persistent orchestrator TID and singleton-pins it round-robin to control CPUs 15 and 31. It then freezes PID/TID/start-time/comm/CPU identities and rejects an empty or non-control inventory (`benchmarks/http2-regression/src/linux.rs:766-800`). During every candidate it requires the same frozen inventory and CPU assignment, subtracts only those exact TIDs' measured ticks on control CPUs, and retains all per-CPU scheduled, capacity, subtracted, and external ticks (`benchmarks/http2-regression/src/linux.rs:800-930`).

The logical-CPU, sibling-pair, and role-bucket external-time rules are unchanged. Subtraction remains forbidden outside the control set, and a candidate still requires the exact 1%, 0.5%, and 0.25% external-time limits plus the existing PSI, memory/I/O, swap, and steal gates (`benchmarks/http2-regression/src/raw.rs:245-320`). The exact smoke confirms three persistent TIDs pinned as 15/31/15, stable inventory in all 12 candidates, and only exact retained orchestrator tick subtraction on control CPU 15. All 12 candidates nevertheless remain rejected by external-time and I/O-noise evidence, proving the pinning did not turn host noise into acceptance.

### 3. Retry and threshold scope: PASS

The two commits modify only `linux.rs`, `orchestrator.rs`, and the quiet-evidence validation/clean split in `raw.rs`. There is no change to operation retry/reconnect behavior, schedules, sample counts, comparison thresholds, bootstrap logic, or verdict precedence. The hard thresholds remain H1 `0.97/1.05/1.05/1.10`, H2-to-H2 `0.97 + 1.00 point/1.05/1.10/1.15`, and bridge `0.95/1.10/1.10/1.15` (`benchmarks/http2-regression/src/schema.rs:297-343`). Existing zero-retry/reconnect ledgers and checks are untouched.

### 4. Exact-candidate terminal smoke: BLOCKED and retained correctly

The sealed intent binds candidate and harness provenance to exact commit `91bb210cbf6703e1f3258b517cee1acfd337da79`, harness tree `b2500a770e739b7b5e234049f1c28e482ed6290c`, source archive SHA-256 `4c3f8cab582f53e4c2dbb9cd9e780ab8ad4d4d0da7c2e765b4b8048aae3adf17`, lock SHA-256 `16a8c2faa197aecf2a581fc2ea7c6546feb7f49edc64d13102f06149ca564e47`, and producer executable SHA-256 `b2297c713de2752caeeef497f2832af2876ee1c915cacaf04141de48215f433a`. The current release executable and Git object/tree reproduce those identities, and `benchmarks/http2-regression` has no tracked or untracked drift.

`quiet.json` retains 12 distinct ten-second candidates, zero accepted candidates, and `q_extra_ns=110002598526`. Every candidate has a stable orchestrator inventory but fails the unchanged external-time gate; every candidate also records nonzero I/O-full PSI, with one additionally recording memory-full PSI. The smoke therefore stops before the first case: `topology-smoke.json` has zero cases and terminal integrity failure `Q_obs did not find a clean interval within 120 seconds of Q_extra`; `execution-state.json` is incomplete with zero completed arms. This is the required empirical **BLOCKED** result, not implementation FAIL and not performance FAIL/PASS.

The terminal source is sealed with 9 entries and root SHA-256 `a78786cedf214fcff3fe779fa985bfdcc3eb203d007945dcac6e29f02d3e3e0e`. Bundle index SHA-256 is `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`; its canonical archive is 304128 bytes with SHA-256 `e1dbfee54bbd27b42b08ab95f512a17951e6133f259ca36143667839fa6afcc5`. The single 33700-byte compressed chunk and stream both hash to `1e5f375b64f9009c16689484e6f37120e9a18ebec179d86e686adf97551dcd5a`.

Fresh source and bundle verification independently reproduced terminal `BLOCKED`, the same seal/archive/stream hashes, exact reconstruction and recompression, `byte_equal=true`, `success=true`, zero raw arms, and ignored derived analysis. Both CLI commands exited nonzero only because non-PASS terminal evidence is intentionally nonzero; verification itself succeeded.

## Verification evidence

Run Git and evidence commands from the repository root; run Cargo and `./target/release/...` commands from `benchmarks/http2-regression`:

```bash
git diff --check 743fa30..91bb210
git diff --exit-code 743fa30..91bb210 -- benchmarks/http2-regression/src/statistics.rs benchmarks/http2-regression/src/schema.rs benchmarks/http2-regression/src/load.rs benchmarks/http2-regression/src/calibration_coordinator.rs benchmarks/http2-regression/src/campaign_coordinator.rs
cargo test --locked --offline
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
./target/release/auth-mini-http2-regression self-test
./benchmarks/http2-regression/target/release/auth-mini-http2-regression verify --source .perf/prove-http2-performance-regression/calibrations/cal-smoke-91bb210cbf67-b2297c713de2
./benchmarks/http2-regression/target/release/auth-mini-http2-regression verify-bundle --index .perf/prove-http2-performance-regression/delivery-staging/cal-smoke-91bb210cbf67-b2297c713de2/bundle-index.json --scratch .perf/prove-http2-performance-regression/bundle-verify/review-cal-smoke-91bb210
```

Results: 151 standard tests passed, the custom process-arm executable reported PASS, strict Clippy and release self-test passed, both diffs were clean, source verification derived the sealed quiet-search blocker, and bundle verification reconstructed/recompressed byte-for-byte. The transient verification scratch was removed by the verifier.

## Final decision

**PASS for implementation readiness.** Commits `0017c9d` and `91bb210` correctly retain dirty bounded quiet-search evidence, keep accepted candidates mandatory for clean evidence, pin persistent orchestrator TIDs before observation without weakening external-noise gates, and leave retry/statistical thresholds unchanged.

**BLOCKED empirically.** Exact-candidate smoke `cal-smoke-91bb210cbf67-b2297c713de2` is a complete, sealed, bundled, independently byte-equal terminal blocker. The current host did not provide an accepted `Q_obs`, so calibration and the authoritative performance matrix must not begin and no no-regression conclusion may be claimed.
