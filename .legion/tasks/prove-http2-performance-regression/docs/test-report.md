# Verification report: final implementation and terminal smoke

> **Date:** 2026-07-21
> **Role:** `verify-change`
> **Implementation readiness:** **PASS**
> **Empirical proof:** **BLOCKED** before cases by the predeclared Axiom quiet gate
> **Performance claim:** None; no no-regression conclusion is supported

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

Reviewers can inspect and verify this copy without relying only on ignored `.perf` delivery staging. Ignored source/staging evidence remains retained until the closeout PR merges and post-merge durable-retention verification authorizes cleanup.

## Measurement boundary

No smoke case, scout, Williams calibration, calibration-direct, authoritative, latency, throughput, CPU/op, RSS, confidence-interval, or performance-verdict sample was produced by the final candidate run. With no confirmed performance regression, remediation was not needed and no production change was attempted.

## Conclusion

**Implementation PASS; empirical proof BLOCKED by Axiom noise.** The harness is ready and its terminal evidence verifies independently, but the host never supplied an accepted quiet observation. The task therefore makes no HTTP/2 no-regression claim. Main PR #13 has merged; the closeout PR, post-merge retention check, cleanup, and main refresh remain pending.
