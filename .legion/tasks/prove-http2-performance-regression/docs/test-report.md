# Verification report: implementation, terminal smoke, and retained delivery

> **Date:** 2026-07-21
> **Role:** `verify-change`
> **Implementation readiness:** **PASS**
> **Empirical proof:** **BLOCKED** before cases by the predeclared Axiom quiet gate
> **Performance claim:** None; no no-regression conclusion is supported
> **Repository delivery:** **COMPLETE** (`8/8`); local cleanup follows the finalization docs merge

## Reviewed state

- Implementation checkpoints: `743fa30`, `0017c9d`, and final candidate `91bb210cbf6703e1f3258b517cee1acfd337da79`.
- The final implementation review has no open finding. Findings previously numbered 1-3 are closed, not deferred.
- Benchmark-only implementation changed; no production code or performance threshold changed.

## Implementation verification

- Benchmark package: 151 tests passed, plus `process-arms: PASS`.
- Root package: 160 tests passed.
- Strict Clippy passed.
- Release self-test passed.
- The implementation review found the quiet-failure retention, persistent-orchestrator pinning, external-noise accounting, retry policy, and statistical thresholds fail closed as designed.

Implementation readiness is **PASS**.

## Closeout verification at `d19ce2e`: PASS

Fresh verification on the closeout worktree produced:

- `cargo test --locked --offline` at the repository root: 110 unit and 50 integration tests passed.
- `cargo test --locked --offline` in `benchmarks/http2-regression`: 126 unit and 25 integration tests passed, plus `process-arms: PASS`. A first run made concurrently with the root suite had one transient `spawned role cycle changed after freeze` failure; the exact test then passed, followed by two complete isolated benchmark-suite passes.
- `cargo clippy --locked --offline --all-targets --all-features -- -D warnings`: passed at both the repository root and benchmark package.
- `cargo build --release --locked --offline` for the benchmark verifier: passed.
- `delivery-ready --commit d19ce2e8083111ec5989d11225809ed09597c6ac`: `success=true` with committed artifact tree `266a1341af0b2309b50503266ea8be5865fc15ae0623bb51c5c7b15c4dfd0be8`, ledger `9e9fe765a485785365aa26ae7bb218a89b2bf29893bfa6d95b920169af83142e`, and exact verifier source tree `9c7fa8c0ca437a7f3bf54cae7a4290b4520dbc9c`.
- Clean candidate rebuild: 11,213,072 bytes, SHA-256 `6f1dc2713d99cd65ac478c718b4ebaeef7b4a45241913d69434af69e5704cf4d`, Build-ID `null`.
- Clean baseline rebuild: 9,192,512 bytes, SHA-256 `9a32bab7281ed672b1d27327a23000b6968cf7630452b68813a987c8fb372d73`, Build-ID `null`.

Diff and byte checks confirmed no production source, Cargo manifest/lock, statistical threshold, retry, or evidence-analysis code changed after PR #13. The tracked bundle index, compressed chunk, and verification receipt exactly match the retained `.perf` staging bytes. Closeout verification is **PASS**; the retained empirical result remains **BLOCKED** without a no-regression claim.

## Post-closeout retention verification: PASS

- Main implementation PR #13 merged at `9f9fb3f0959cefac0608cdece5f661b3b7973cef`.
- Closeout PR #14 merged at `9c4122d2cd2eabe73f4d3785daf22197242de54d`.
- `delivery-retained --base 9c4122d2cd2eabe73f4d3785daf22197242de54d --merge 9c4122d2cd2eabe73f4d3785daf22197242de54d` returned `success=true`.
- The merged artifact tree is `266a1341af0b2309b50503266ea8be5865fc15ae0623bb51c5c7b15c4dfd0be8`; the merged ledger SHA-256 is `9e9fe765a485785365aa26ae7bb218a89b2bf29893bfa6d95b920169af83142e`.
- The ready receipt SHA-256 is `8f8da4ba20a6aef97f4512da8f67589eda589e1b903ad199a4474f21d9cfb96b`; the retained receipt file SHA-256 is `953d10fd2cb26b70ec25b1799932394bbdd43f19b9ce0a6e132da64dce69c283`.
- Cleanup authorization is content-bound and permits deletion only of matching `.perf` evidence. It does not authorize deletion of non-matching historical local evidence.

Retention verification is **PASS**. It proves durable delivery and bounded cleanup authority; it does not supply a performance sample or change the empirical `BLOCKED` result.

## Retained smoke evidence

### First exact implementation checkpoint

The exact-`743fa30` smoke exposed that a failed bounded quiet search was not retained. Partial unsealed root `cal-smoke-743fa30d7371-a03fd3cf021e` remains preserved for provenance. It was not sealed, was not used for a claim, and prompted the benchmark-only correction in `0017c9d`.

### Final exact candidate

Smoke `cal-smoke-91bb210cbf67-b2297c713de2` binds candidate `91bb210cbf6703e1f3258b517cee1acfd337da79` and stopped before its first case:

- 12 consecutive 10-second `Q_obs` candidates
- zero accepted candidates
- `q_extra=110002598526ns`
- stable persistent orchestrator inventory throughout
- approximately 38%-81% external logical-CPU activity
- nonzero I/O PSI `full`

The unchanged contract requires immediate `BLOCKED`; it permits no retry and no threshold change.

## Seal verification

- Seal root: `a78786cedf214fcff3fe779fa985bfdcc3eb203d007945dcac6e29f02d3e3e0e`
- Bundle index SHA-256: `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`
- Independent verification: `success=true`, `byte_equal=true`, terminal `BLOCKED`

The verifier independently reconstructed and re-encoded the bundle byte-for-byte. Its nonzero command status reflects the retained non-PASS terminal, not verification failure.

## Tracked terminal artifact

The ordinary-Git copy prepared for the closeout PR is [`.legion/tasks/prove-http2-performance-regression/artifacts/cal-smoke-91bb210cbf67-b2297c713de2/`](../artifacts/cal-smoke-91bb210cbf67-b2297c713de2/):

- `bundle-index.json`: SHA-256 `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`
- `chunks/000000.tar.zst.part`: SHA-256 `1e5f375b64f9009c16689484e6f37120e9a18ebec179d86e686adf97551dcd5a`
- `verification.json`: SHA-256 `cb14b85dd1ad3413c40d53d87893483924085da2c1122b78b0eb8458a0d61f82`

Reviewers can inspect and verify this copy without relying on ignored `.perf` delivery staging. Post-merge durable-retention verification now authorizes deletion of matching ignored evidence only; non-authorized historical local evidence remains outside that deletion boundary.

## Measurement boundary

No smoke case, scout, Williams calibration, calibration-direct, authoritative, latency, throughput, CPU/op, RSS, confidence-interval, or performance-verdict sample was produced by the final candidate run. With no confirmed performance regression, remediation was not needed and no production change was attempted.

## Conclusion

**Implementation PASS; empirical proof BLOCKED by Axiom noise.** The harness is ready and its terminal evidence verifies independently, but the host never supplied an accepted quiet observation. The task therefore makes no HTTP/2 no-regression claim. PRs #13 and #14 are merged, retained delivery verification passed, and the repository checklist is complete at `8/8`. After this finalization docs PR merges, the agent will reverify fetched `master`, preserve non-authorized historical local evidence outside the worktree, remove the worktree and merged local branches, and refresh main as mechanical cleanup.
