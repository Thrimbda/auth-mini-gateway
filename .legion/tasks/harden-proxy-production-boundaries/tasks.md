# Harden proxy production boundaries - 任务清单

## 快速恢复

**当前阶段**: (none)
**当前检查项**: (none)
**进度**: 8/8 任务完成
---

## 阶段 1: Contract and design ✅ COMPLETE

- [x] Materialize the production-hardening contract and research the current lifecycle/trust boundaries. | 验收: plan.md and research.md define the availability, header, overload, forwarding, and deployment gaps with stable scope.
- [x] Write and adversarially review the high-risk hardening RFC. | 验收: rfc.md resolves permit ownership, backoff, overload mapping, trusted proxy semantics, tests, rollout, and rollback; review-rfc.md records PASS.
---

## 阶段 2: Implementation ✅ COMPLETE

- [x] Implement connection/admission hardening and recoverable accept behavior. | 验收: Downstream/upstream capacities are bounded through full stream/upgrade lifetimes and recoverable accept errors retry safely.
- [x] Implement header alias, login overload, and trusted proxy fixes with regression tests. | 验收: Ambiguous headers fail closed, login overload is cookie-neutral 503, and client IP is accepted only from configured trusted peers.
- [x] Correct deployment and configuration documentation. | 验收: Docs provide exact Acorn 18081 to Axiom 7780 to OpenCode 4096 topology and usable nginx/FRP configuration.
---

## 阶段 3: Verification ✅ COMPLETE

- [x] Run required commands and focused availability/security tests and record evidence. | 验收: test-report.md records PASS for mandatory commands and every contract outcome or an explicit blocker.
---

## 阶段 4: Review and delivery ✅ COMPLETE

- [x] Run readiness/security review, resolve blockers, and produce walkthrough/wiki evidence. | 验收: review-change PASS, walkthrough, PR body, and Legion wiki writeback are complete.
- [x] Complete PR lifecycle and workspace cleanup. | 验收: PR reaches merged or explicit non-success terminal state, review/checks are handled, worktree is removed, and main workspace is refreshed.
---

## 发现的新任务

(暂无)
---

*最后更新: 2026-07-15 18:01*
