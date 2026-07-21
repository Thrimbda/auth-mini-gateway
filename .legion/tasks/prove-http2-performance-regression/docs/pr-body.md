## Summary

- deliver the repository-owned HTTP/1 and HTTP/2 performance campaign runner at checkpoints `743fa30`, `0017c9d`, and `91bb210cbf6703e1f3258b517cee1acfd337da79`
- retain bounded quiet-search failures, pin persistent orchestrator threads, and preserve unchanged external-noise and statistical gates
- record final implementation **PASS** and exact-candidate empirical **BLOCKED** without making a no-regression claim

## Review scope

Final implementation review passed with no open finding. The change is benchmark-only: production code, retry behavior, and performance thresholds are unchanged.

## Verification

- benchmark package: 151 tests passed plus `process-arms: PASS`
- root package: 160 tests passed
- strict Clippy passed
- release self-test passed
- terminal bundle verification returned `success=true` and `byte_equal=true`

## Empirical result

Exact-candidate smoke `cal-smoke-91bb210cbf67-b2297c713de2` stopped before cases after 12 consecutive 10-second `Q_obs` candidates produced zero accepted observations and `q_extra=110002598526ns`. Persistent orchestrator inventory was stable, but external logical-CPU activity was approximately 38%-81% and I/O PSI `full` was nonzero.

Seal root is `a78786cedf214fcff3fe779fa985bfdcc3eb203d007945dcac6e29f02d3e3e0e`; bundle index SHA-256 is `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`. The result is terminal `BLOCKED`; retry and threshold changes are not permitted.

No scout, calibration, authoritative sample, or performance verdict was produced. No production change or regression remediation was attempted. **Implementation passed, empirical proof was blocked by Axiom noise, and this PR makes no no-regression claim.**

## Evidence

- `.legion/tasks/prove-http2-performance-regression/docs/test-report.md`
- `.legion/tasks/prove-http2-performance-regression/docs/review-change.md`
- `.legion/tasks/prove-http2-performance-regression/docs/report-walkthrough.md`
