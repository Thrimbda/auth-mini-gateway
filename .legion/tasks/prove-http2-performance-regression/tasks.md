# Prove HTTP/2 performance regression boundaries - Task checklist

## Quick Resume

**Current phase**: Measurement and remediation
**Current item**: Run C64 smoke, scout, calibration, and the authoritative matrix
**Progress**: 4/8 tasks complete
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

- [ ] Run the authoritative 30-100-pair H1 and H2 matrix on the current machine. | Acceptance: immutable raw results and a complete scenario report produce PASS, FAIL, or honest BLOCKED without selective omission.
- [ ] Fix confirmed regressions without weakening safety, then rerun when required. | Acceptance: failing evidence is retained and the final candidate is measured by the complete matrix; mark not-needed if the first run passes.
---

## Phase 4: Verification and delivery

- [ ] Independently verify harness correctness, raw statistics, functional gates, and repository checks; run readiness/security review. | Acceptance: test and review artifacts record PASS or a precise blocker.
- [ ] Produce walkthrough/wiki evidence and complete commit, rebase, PR, checks/review, merge, cleanup, and main refresh. | Acceptance: reviewer artifacts exist and the delivery lifecycle reaches terminal state.
---

## Discovered Tasks

(None)
---

*Last updated: 2026-07-18*
