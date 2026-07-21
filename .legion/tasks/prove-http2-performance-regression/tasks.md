# Prove HTTP/2 performance regression boundaries - Task checklist

## Quick Resume

**Current phase**: Verification and delivery
**Current item**: Open and merge the closeout PR, verify retained evidence from the fetched merged base, clean retained state, and refresh main
**Progress**: 7/8 tasks complete
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
- [ ] Produce walkthrough/wiki evidence and complete commit, rebase, PR, checks/review, merge, cleanup, and main refresh. | Current state: main PR #13 merged at `9f9fb3f`; artifact commit `d19ce2e` passed exact-commit `delivery-ready`, full tests, strict Clippy, and focused closeout review. The closeout PR remains pending on `legion/prove-http2-performance-regression-closeout`. Acceptance: the second PR merges, post-merge `delivery-retained` passes against the fetched durable base, retained state/worktree/branches are cleaned, and main is refreshed.
---

## Discovered Tasks

(None)
---

*Last updated: 2026-07-21*
