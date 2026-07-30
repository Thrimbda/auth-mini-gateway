# Fix Audience-Bound Login Callback - 任务清单

## 快速恢复

**当前阶段**: (none)
**当前检查项**: (none)
**进度**: 4/4 任务完成
---

## 阶段 1: Contract and design ✅ COMPLETE

- [x] Record upstream and runtime evidence, then specify audience, identity, migration, rollback, and verification behavior. | 验收: RFC is reviewed and resolves legacy-session and cross-audience replay risks.
---

## 阶段 2: Implementation ✅ COMPLETE

- [x] Implement audience-bound verification and user-ID session authorization with focused regression coverage. | 验收: Callback and refresh paths accept only the intended audience and no longer require downstream /me.
- [x] Update active configuration, deployment guidance, examples, and real-auth contract drill. | 验收: Operators have an explicit ALLOW_USER_IDS migration path and the drill targets current official auth-mini.
---

## 阶段 3: Verification and delivery ✅ COMPLETE

- [x] Run formatting, tests, current-auth-mini E2E, security review, walkthrough, and wiki writeback. | 验收: All applicable gates pass with recorded evidence and no secret disclosure.
---

## 发现的新任务

(暂无)
---

*最后更新: 2026-07-30 10:39*
