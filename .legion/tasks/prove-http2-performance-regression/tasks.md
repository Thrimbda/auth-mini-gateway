# Prove HTTP/2 performance regression boundaries - Task checklist

## Quick Resume

**Current phase**: Finalization handoff; repository delivery complete
**Current item**: Merge the finalization docs PR, then perform the recorded local cleanup sequence
**Progress**: 8/8 tasks complete
---

## Phase 1: Contract and design

- [x] Materialize the confirmed performance-regression contract. | Acceptance: baseline, matrix, statistical/resource gates, noise policy, remediation rule, scope, and non-goals are explicit.
- [x] Write and adversarially review the benchmark methodology RFC. | Acceptance: process topology, correctness controls, statistics, noise/stopping rules, schemas, reproducibility, and anti-gaming checks record PASS.
---

## Phase 2: Harness implementation

- [x] Implement the isolated baseline/candidate build and benchmark topology. | Acceptance: one command builds and runs deterministic gateway, fixture, client, affinity, and process sampling paths.
- [x] Implement workloads, raw-result schema, statistical gate, and synthetic tests. | Acceptance: every workload validates work performed and analyzer tests pin PASS/FAIL/BLOCKED boundaries.
---

## Phase 3: Measurement and remediation

- [x] Attempt the authoritative H1 and H2 matrix under its predeclared entry gates. | Result: exact candidate `91bb210` stopped honestly `BLOCKED` before cases when 12 quiet candidates yielded zero accepted observations; no sample was omitted.
- [x] Fix confirmed regressions without weakening safety, then rerun when required. | Result: not needed; no performance sample, verdict, or confirmed regression existed, and retry or threshold changes were forbidden.
---

## Phase 4: Verification and delivery

- [x] Independently verify harness correctness, terminal evidence, functional gates, and repository checks; run readiness/security review. | Result: implementation `PASS`; 151 benchmark tests plus `process-arms`, 160 root tests, strict Clippy, release self-test, and byte-equal terminal-bundle verification passed.
- [x] Produce walkthrough/wiki evidence and complete the repository commit, PR, review, merge, and retained-delivery lifecycle. | Result: main PR #13 merged at `9f9fb3f`; closeout PR #14 merged at `9c4122d`; `delivery-retained` returned `success=true` against that fetched base/merge, with content-bound authorization to delete only matching evidence. This finalization docs PR is the last repository mutation. Its immediate post-merge local cleanup sequence is to reverify fetched `master`, preserve non-authorized historical evidence outside the worktree, remove the worktree and merged local branches, and refresh main; those mechanical actions do not reopen the completed repository checklist.
---

## Discovered Tasks

(None)
---

*Last updated: 2026-07-21*
