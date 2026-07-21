# prove-http2-performance-regression

## Metadata

- `task-id`: `prove-http2-performance-regression`
- `status`: `complete`
- `risk`: `high`
- `schema-version`: `gateway-session-v2` (unchanged)
- `historical`: `false`
- `supersedes`: `(none)`
- `superseded-by`: `(none)`
- `empirical-proof`: `BLOCKED-before-sampling`
- `performance-verdict`: `none`
- `implementation-pr`: [#13](https://github.com/Thrimbda/auth-mini-gateway/pull/13), merged at `9f9fb3f0959cefac0608cdece5f661b3b7973cef`
- `closeout-pr`: [#14](https://github.com/Thrimbda/auth-mini-gateway/pull/14), merged at `9c4122d2cd2eabe73f4d3785daf22197242de54d`
- `repository-checklist`: `8/8`
- `closeout-state`: retained delivery verified; finalization docs are the last repository mutation

## Outcome Summary

- The repository-local HTTP/1 and HTTP/2 benchmark harness passed final implementation review at candidate `91bb210cbf6703e1f3258b517cee1acfd337da79`; no implementation finding remains open.
- Verification passed 151 benchmark tests plus `process-arms`, 160 root tests, strict Clippy, the release self-test, and independent byte-equal terminal-bundle reconstruction.
- Exact-candidate smoke `cal-smoke-91bb210cbf67-b2297c713de2` stopped before cases after 12 consecutive 10-second quiet candidates produced zero accepted observations. Stable orchestrator inventory did not hide approximately 38%-81% external logical-CPU activity or nonzero I/O PSI `full`.
- The terminal evidence is sealed and independently verified as `BLOCKED`. Its ordinary-Git closeout copy is under `.legion/tasks/prove-http2-performance-regression/artifacts/cal-smoke-91bb210cbf67-b2297c713de2/`, so reviewers need not rely only on ignored `.perf` staging.
- Exact-commit `delivery-ready` passed for artifact commit `d19ce2e8083111ec5989d11225809ed09597c6ac`. The 40,405-byte tracked set is bound to artifact tree `266a1341af0b2309b50503266ea8be5865fc15ae0623bb51c5c7b15c4dfd0be8`, ledger `9e9fe765a485785365aa26ae7bb218a89b2bf29893bfa6d95b920169af83142e`, and verifier source tree `9c7fa8c0ca437a7f3bf54cae7a4290b4520dbc9c`; clean scratch builds exactly matched both sealed gateway binary hashes.
- Closeout verification passed 160 root tests, 151 nested benchmark tests plus `process-arms`, and strict Clippy. Focused closeout review records **PASS** with no remaining finding.
- Closeout PR #14 merged at `9c4122d2cd2eabe73f4d3785daf22197242de54d`. `delivery-retained` returned `success=true` against that fetched base/merge and revalidated the artifact tree and ledger above.
- Cleanup authorization is bound to the fetched base, merge, artifact tree, ledger, ready receipt `8f8da4ba20a6aef97f4512da8f67589eda589e1b903ad199a4474f21d9cfb96b`, and retained entries. It permits deletion only of matching evidence; non-authorized historical local evidence remains outside its scope.
- No scout, calibration, authoritative sample, performance verdict, production change, or regression remediation exists.
- Main conclusion: implementation **PASS**, empirical proof **BLOCKED** by Axiom noise, therefore no no-regression claim. Repository delivery is complete at `8/8`.

## Reusable Decisions

- A bounded quiet-search failure must retain every candidate and remain independently verifiable; retention does not make dirty evidence clean.
- A predeclared environmental entry-gate failure stops before measurement. It cannot be retried, weakened, or converted into a performance conclusion.
- Partial unsealed evidence may be preserved for provenance but cannot support a claim. Conclusion-bearing evidence requires a complete seal, deterministic bundle, and independent byte-equal verification.
- Sealing evidence and publishing its terminal outcome are separate states. Post-seal products use a write-once transaction, and terminal publication follows complete hash, ledger, cap, and current-closure validation.
- Postmerge cleanup requires content-bound authorization after fetched-base reachability and retained-identity checks. Verification may authorize cleanup but does not perform deletion.

## Finalization Handoff

- This finalization docs PR is the last repository mutation.
- Immediately after it merges, re-fetch `master`, rerun retained verification against the fetched commit, preserve non-authorized historical local evidence outside the worktree, remove the worktree and merged local branches, and refresh main.
- These are mechanical local cleanup actions, not an empirical rerun or performance claim.

## Related Raw Sources

- [Plan](../../tasks/prove-http2-performance-regression/plan.md)
- [Log](../../tasks/prove-http2-performance-regression/log.md)
- [Task checklist](../../tasks/prove-http2-performance-regression/tasks.md)
- [RFC](../../tasks/prove-http2-performance-regression/docs/rfc.md)
- [RFC review](../../tasks/prove-http2-performance-regression/docs/review-rfc.md)
- [Implementation review](../../tasks/prove-http2-performance-regression/docs/review-change.md)
- [Test report](../../tasks/prove-http2-performance-regression/docs/test-report.md)
- [Reviewer walkthrough](../../tasks/prove-http2-performance-regression/docs/report-walkthrough.md)
- [Tracked terminal artifact](../../tasks/prove-http2-performance-regression/artifacts/cal-smoke-91bb210cbf67-b2297c713de2/)

## Verification

- Final implementation review passed on 2026-07-21 with no open finding.
- The final terminal source seal root is `a78786cedf214fcff3fe779fa985bfdcc3eb203d007945dcac6e29f02d3e3e0e`; bundle index SHA-256 is `681d6fa1c8c28dfe0a666dae13dcffca970cf7d09d923441d2c9b4c2f1ad35e0`.
- The tracked chunk SHA-256 is `1e5f375b64f9009c16689484e6f37120e9a18ebec179d86e686adf97551dcd5a`; verification receipt SHA-256 is `cb14b85dd1ad3413c40d53d87893483924085da2c1122b78b0eb8458a0d61f82`.
- Independent verification returned `success=true`, `byte_equal=true`, and terminal `BLOCKED`.
- Exact-commit `delivery-ready` returned `success=true` at `d19ce2e8083111ec5989d11225809ed09597c6ac`; the tracked total is 40,405 bytes, and both clean scratch gateway rebuilds exactly matched their sealed binary hashes.
- `delivery-retained` returned `success=true` for base/merge `9c4122d2cd2eabe73f4d3785daf22197242de54d`, artifact tree `266a1341af0b2309b50503266ea8be5865fc15ae0623bb51c5c7b15c4dfd0be8`, and ledger `9e9fe765a485785365aa26ae7bb218a89b2bf29893bfa6d95b920169af83142e`.
- Ready receipt SHA-256 is `8f8da4ba20a6aef97f4512da8f67589eda589e1b903ad199a4474f21d9cfb96b`; retained receipt file SHA-256 is `953d10fd2cb26b70ec25b1799932394bbdd43f19b9ce0a6e132da64dce69c283`.
